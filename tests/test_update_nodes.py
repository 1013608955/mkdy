import os
import sys
import socket
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import update_nodes as u


class TestIsCnIp(unittest.TestCase):
    def test_cn(self):
        self.assertTrue(u.is_cn_ip("1.0.1.1"))
        self.assertTrue(u.is_cn_ip("114.114.114.114"))
        self.assertTrue(u.is_cn_ip("223.5.5.5"))

    def test_non_cn(self):
        self.assertFalse(u.is_cn_ip("8.8.8.8"))
        self.assertFalse(u.is_cn_ip("1.1.1.1"))

    def test_private(self):
        self.assertFalse(u.is_cn_ip("10.0.0.1"))
        self.assertFalse(u.is_cn_ip("192.168.1.1"))

    def test_invalid(self):
        self.assertFalse(u.is_cn_ip("not-an-ip"))
        self.assertFalse(u.is_cn_ip(""))


class TestResolveConnect(unittest.TestCase):
    def test_ipv4_literal(self):
        fam, host = u._resolve_connect("5.6.7.8")
        self.assertEqual(fam, socket.AF_INET)
        self.assertEqual(host, "5.6.7.8")

    def test_ipv6_literal(self):
        fam, host = u._resolve_connect("::1")
        self.assertEqual(fam, socket.AF_INET6)
        self.assertEqual(host, "::1")

    def test_domain_cached(self):
        with mock.patch.object(u, "dns_resolve", return_value=(True, ["9.9.9.9"])):
            fam, host = u._resolve_connect("example.com")
            self.assertEqual(host, "9.9.9.9")

    def test_domain_fail(self):
        with mock.patch.object(u, "dns_resolve", return_value=(False, [])):
            self.assertIsNone(u._resolve_connect("nope.invalid"))


class TestConfigOverlay(unittest.TestCase):
    def test_config_loaded(self):
        # 模块导入时已加载 config.yaml（overlay 语义），顶层键应存在
        self.assertIn("sources", u.CONFIG)
        self.assertIn("detection", u.CONFIG)
        # private_ip 正则必须在代码内编译（YAML 无法表达），且可用
        self.assertTrue(u.is_private_ip("10.0.0.1"))

    def test_deep_merge_nested_preserves_other_keys(self):
        # 嵌套合并：config.yaml 写 filter.request_timeout 不应整体替换内联 filter
        # （否则 score_rules / private_ip 等会丢失，导致评分规则全丢、is_private_ip 崩溃）
        base = {"filter": {"score_rules": ["a"], "private_ip": "RX"},
                "request": {"timeout": 15}}
        override = {"filter": {"request_timeout": 20}}
        merged = u._deep_merge(dict(base), override)
        self.assertEqual(merged["filter"]["score_rules"], ["a"])
        self.assertEqual(merged["filter"]["private_ip"], "RX")
        self.assertEqual(merged["filter"]["request_timeout"], 20)
        # 顶层非 dict 值以 override 为准
        self.assertEqual(merged["request"]["timeout"], 15)

    def test_deep_merge_overrides_leaf(self):
        base = {"detection": {"tcp_timeout": {"vmess": 5}, "thread_pool": 16}}
        override = {"detection": {"tcp_timeout": {"vless": 6}}}
        merged = u._deep_merge(dict(base), override)
        self.assertEqual(merged["detection"]["tcp_timeout"]["vmess"], 5)
        self.assertEqual(merged["detection"]["tcp_timeout"]["vless"], 6)
        self.assertEqual(merged["detection"]["thread_pool"], 16)


if __name__ == "__main__":
    unittest.main()
