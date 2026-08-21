import os
import sys
import ssl
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


class TestWeightSortDefensive(unittest.TestCase):
    """P1-2：节点缺 weight 键时排序不应 KeyError（应为 0 兜底）。"""

    def test_sort_without_weight_key(self):
        nodes = [{"line": "x", "weight": 5}, {"line": "y"}]  # 第二个缺 weight
        # 复刻 main 里的排序表达式，确认 .get 兜底不抛异常
        nodes.sort(key=lambda x: x.get("weight", 0), reverse=True)
        self.assertEqual(nodes[0]["line"], "x")  # weight=5 排前
        self.assertEqual(nodes[1]["line"], "y")  # 缺键兜底 0，排后

    def test_sort_all_missing_weight(self):
        nodes = [{"line": "a"}, {"line": "b"}, {"line": "c"}]
        nodes.sort(key=lambda x: x.get("weight", 0), reverse=True)
        self.assertEqual([n["line"] for n in nodes], ["a", "b", "c"])


class TestTlsHandshakeProbe(unittest.TestCase):
    """P0#2：probe_proxy_handshake 默认严格校验证书，防 MITM 伪造可达节点骗加分。"""

    def _patch_connect(self, addr="1.2.3.4"):
        return mock.patch.multiple(
            u,
            _resolve_connect=mock.Mock(return_value=(socket.AF_INET, addr)),
            is_cn_ip=mock.Mock(return_value=False),
            is_private_ip=mock.Mock(return_value=False),
        )

    def test_default_strict_verification(self):
        # 默认 CONFIG.request.allow_insecure=false → 用校验上下文
        captured = {}
        tls_sock = mock.MagicMock()
        tls_sock.do_handshake.return_value = None

        def fake_create():
            ctx = mock.MagicMock()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.wrap_socket.return_value = tls_sock
            captured["ctx"] = ctx
            return ctx

        with self._patch_connect(), \
             mock.patch.object(u.ssl, "create_default_context", side_effect=fake_create), \
             mock.patch("socket.create_connection") as m_conn:
            m_conn.return_value.__enter__ = lambda s: s
            m_conn.return_value.__exit__ = lambda s, *a: None
            ok, tag, _ = u.probe_proxy_handshake("1.2.3.4", 443, "trojan",
                                                  use_tls=True, sni="x.com")
        self.assertTrue(ok)
        self.assertEqual(tag, "tls_ok")
        self.assertIn("ctx", captured)
        self.assertTrue(captured["ctx"].check_hostname)
        self.assertEqual(captured["ctx"].verify_mode, ssl.CERT_REQUIRED)

    def test_allow_insecure_downgrade(self):
        # 临时开启 allow_insecure → 降级为不校验
        orig = u.CONFIG.get("request", {}).get("allow_insecure", False)
        u.CONFIG.setdefault("request", {})["allow_insecure"] = True
        try:
            captured = {}
            tls_sock = mock.MagicMock()
            tls_sock.do_handshake.return_value = None

            def fake_create():
                ctx = mock.MagicMock()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.wrap_socket.return_value = tls_sock
                captured["ctx"] = ctx
                return ctx

            with self._patch_connect(), \
                 mock.patch.object(u.ssl, "create_default_context", side_effect=fake_create), \
                 mock.patch("socket.create_connection") as m_conn:
                m_conn.return_value.__enter__ = lambda s: s
                m_conn.return_value.__exit__ = lambda s, *a: None
                ok, tag, _ = u.probe_proxy_handshake("1.2.3.4", 443, "trojan",
                                                      use_tls=True, sni="x.com")
            self.assertTrue(ok)
            self.assertEqual(captured["ctx"].check_hostname, False)
            self.assertEqual(captured["ctx"].verify_mode, ssl.CERT_NONE)
        finally:
            u.CONFIG["request"]["allow_insecure"] = orig


class TestResetState(unittest.TestCase):
    """P1#6：reset_state 清空跨运行全局态，避免 CI/测试多次调用泄漏。"""

    def test_reset_clears_counters_and_cache(self):
        u._PROBE_COUNT["n"] = 999
        u._IPINFO_QUOTA["used"] = 999
        u.dns_resolve.cache_clear()
        u.dns_resolve("cached.example.com")  # 填充缓存
        self.assertGreater(len(u.dns_resolve.cache_info()._fields), 0)
        u.reset_state()
        self.assertEqual(u._PROBE_COUNT["n"], 0)
        self.assertEqual(u._IPINFO_QUOTA["used"], 0)
        self.assertEqual(u.dns_resolve.cache_info().hits, 0)
        self.assertEqual(u.dns_resolve.cache_info().misses, 0)


if __name__ == "__main__":
    unittest.main()
