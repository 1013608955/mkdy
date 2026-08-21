import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import verify_cn.run_local as rl


class TestBuildMihomoConfig(unittest.TestCase):
    """P0#3 关联：build_mihomo_config 是纯函数，验证结构与端口注入正确。"""

    def test_structure(self):
        proxies = [{"name": "n1", "type": "ss"}]
        cfg = rl.build_mihomo_config(proxies, 9090, 7890)
        self.assertEqual(cfg["external-controller"], "127.0.0.1:9090")
        self.assertEqual(cfg["mixed-port"], 7890)
        self.assertEqual(cfg["mode"], "direct")
        self.assertEqual(cfg["proxies"], proxies)
        self.assertEqual(cfg["rules"], ["MATCH,DIRECT"])
        # 不应引用需要联网下载的 geo 数据
        self.assertFalse(cfg.get("geo-auto-update", True))


class TestNormErr(unittest.TestCase):
    """P0#3 关联：_norm_err 错误归一，便于统计诊断。"""

    def test_timeout(self):
        self.assertEqual(rl._norm_err("context deadline exceeded i/o timeout"), "timeout")

    def test_conn_refused(self):
        self.assertEqual(rl._norm_err("dial tcp: connection refused"), "conn_refused")

    def test_tls(self):
        self.assertEqual(rl._norm_err("x509: certificate signed by unknown authority"),
                         "tls_fail")

    def test_unknown_truncated(self):
        # 未命中已知类别时原样返回，且截断到 60 字符内
        self.assertEqual(rl._norm_err("some weird error abcdefghij"),
                         "some weird error abcdefghij")
        long_detail = "x" * 200
        self.assertLessEqual(len(rl._norm_err(long_detail)), 60)


if __name__ == "__main__":
    unittest.main()
