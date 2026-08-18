import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml
import merge_subs as m


class TestMergeFallback(unittest.TestCase):
    def test_missing_template_returns(self):
        """回归 #77：clash_template.yaml 缺失时应返回（写降级 proxies），
        而非继续 open(template_path) 触发 FileNotFoundError。"""
        d = tempfile.mkdtemp()
        out = os.path.join(d, "s-clash.yaml")
        with mock.patch.object(sys, "argv", ["merge_subs", "--base", d, "--out", "s-clash.yaml"]):
            m.main()  # 不应抛异常
        self.assertTrue(os.path.exists(out))
        with open(out, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self.assertIn("proxies", data)


class TestMergeDedup(unittest.TestCase):
    def test_dedup_two_identical(self):
        d = tempfile.mkdtemp()
        clash = {"proxies": [
            {"name": "a", "type": "ss", "server": "h1", "port": 1,
             "cipher": "aes-256-gcm", "password": "p"},
            {"name": "a", "type": "ss", "server": "h1", "port": 1,
             "cipher": "aes-256-gcm", "password": "p"},
        ]}
        with open(os.path.join(d, "s2-clash-1.yaml"), "w", encoding="utf-8") as f:
            yaml.safe_dump(clash, f)
        out = os.path.join(d, "s-clash.yaml")
        with mock.patch.object(sys, "argv", ["merge_subs", "--base", d, "--out", "s-clash.yaml"]):
            m.main()
        with open(out, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self.assertEqual(len(data.get("proxies", [])), 1)


if __name__ == "__main__":
    unittest.main()
