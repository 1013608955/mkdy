import os
import sys
import json
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


class TestVerifiedMerge(unittest.TestCase):
    def test_verified_priority_and_dedup(self):
        """方案 A：从 verify_cn/verified.json 并入验证通过节点（含完整 proxy），且去重：
        - 与订阅源重复的节点优先保留 verified 的完整配置（而非精简版）
        - 最终无重复节点
        - verified 的全部节点都同步进产物
        """
        d = tempfile.mkdtemp()

        # verify_cn/verified.json（新格式：nodes[i] 含 proxy 完整配置）
        verified = {"nodes": [
            {"name": "N1", "ok": True, "proxy":
                {"name": "N1-verified", "type": "ss", "server": "h1", "port": 1,
                 "cipher": "aes-256-gcm", "password": "p", "extra": "verified-full"}},
            {"name": "N2", "ok": True, "proxy":
                {"name": "N2", "type": "ss", "server": "h2", "port": 2,
                 "cipher": "aes-256-gcm", "password": "q"}},
        ]}
        os.makedirs(os.path.join(d, "verify_cn"), exist_ok=True)
        with open(os.path.join(d, "verify_cn", "verified.json"), "w", encoding="utf-8") as f:
            json.dump(verified, f)

        # s2-clash-1.yaml：N1(精简版，无 extra，与 verified 重复) + N3(源独有)
        src = {"proxies": [
            {"name": "N1-txt", "type": "ss", "server": "h1", "port": 1,
             "cipher": "aes-256-gcm", "password": "p"},
            {"name": "N3", "type": "ss", "server": "h3", "port": 3,
             "cipher": "aes-256-gcm", "password": "r"},
        ]}
        with open(os.path.join(d, "s2-clash-1.yaml"), "w", encoding="utf-8") as f:
            yaml.safe_dump(src, f)

        out = os.path.join(d, "s-clash.yaml")
        with mock.patch.object(sys, "argv", ["merge_subs", "--base", d, "--out", "s-clash.yaml"]):
            m.main()

        with open(out, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        proxies = data.get("proxies", [])

        # 1) 无重复：N1(重复) + N2 + N3 = 3
        self.assertEqual(len(proxies), 3, f"期望去重后 3 节点，实际 {len(proxies)}")

        by_name = {p["name"]: p for p in proxies}

        # 2) verified 优先：重复的 N1 保留的是 verified 完整版（带 extra 标记）
        self.assertIn("✅ N1-verified", by_name, "重复节点应保留 verified 完整版(带✅)")
        self.assertNotIn("N1-txt", by_name, "重复的精简版应被去重跳过")
        self.assertEqual(by_name["✅ N1-verified"].get("extra"), "verified-full",
                         "应优先保留 verified 的完整配置")

        # 3) verified 全部同步进产物
        self.assertIn("✅ N2", by_name, "verified 独有节点 N2 应同步进产物")
        # 4) 订阅源独有节点正常并入
        self.assertIn("N3", by_name, "源独有节点 N3 应正常并入")

    def test_verified_legacy_name_fallback(self):
        """方案 A 过渡兼容：旧版 verified.json 无 proxy 字段时，
        用 name 去全量节点（含 s-clash.yaml）匹配补全，不丢节点。"""
        d = tempfile.mkdtemp()
        # 旧格式：只有 name/proto/ok，无 proxy
        legacy = {"nodes": [
            {"name": "N1", "ok": True, "proto": "ss", "latency": 0.1},
            {"name": "N2", "ok": True, "proto": "ss", "latency": 0.2},
        ]}
        os.makedirs(os.path.join(d, "verify_cn"), exist_ok=True)
        with open(os.path.join(d, "verify_cn", "verified.json"), "w", encoding="utf-8") as f:
            json.dump(legacy, f)
        # s-clash.yaml 提供完整配置供 name 匹配
        full = {"proxies": [
            {"name": "N1", "type": "ss", "server": "h1", "port": 1,
             "cipher": "aes-256-gcm", "password": "p"},
            {"name": "N2", "type": "ss", "server": "h2", "port": 2,
             "cipher": "aes-256-gcm", "password": "q"},
        ]}
        with open(os.path.join(d, "s-clash.yaml"), "w", encoding="utf-8") as f:
            yaml.safe_dump(full, f)

        verified_nodes = m.load_verified_proxies(
            os.path.join(d, "verify_cn", "verified.json"),
            {n["name"]: n for n in full["proxies"]})
        self.assertEqual(len(verified_nodes), 2)
        self.assertEqual(verified_nodes[0]["server"], "h1")
        self.assertTrue(verified_nodes[0]["name"].startswith("✅ "))

    def test_missing_verified_is_noop(self):
        """verified.json 缺失时不应报错，按原流程继续。"""
        d = tempfile.mkdtemp()
        src = {"proxies": [
            {"name": "X", "type": "ss", "server": "hx", "port": 9,
             "cipher": "aes-256-gcm", "password": "z"},
        ]}
        with open(os.path.join(d, "s2-clash-1.yaml"), "w", encoding="utf-8") as f:
            yaml.safe_dump(src, f)
        out = os.path.join(d, "s-clash.yaml")
        with mock.patch.object(sys, "argv", ["merge_subs", "--base", d, "--out", "s-clash.yaml"]):
            m.main()  # 不应抛异常
        with open(out, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self.assertEqual(len(data.get("proxies", [])), 1)


class TestFetchProtocolCoverage(unittest.TestCase):
    """fetch.download_nodes 的协议识别应以 node_parse._PARSERS 为单一事实来源，
    覆盖 tuic/ssr/hysteria2 等此前被硬编码漏掉的协议（避免静默丢节点）。"""

    def _encode(self, lines):
        import base64
        return base64.b64encode("\n".join(lines).encode("utf-8")).decode("ascii")

    def test_all_parser_protocols_extracted(self):
        from node_parse import _PARSERS
        import fetch
        sample = []
        for scheme in _PARSERS:
            sample.append(scheme + "example.com:443?demo=1#node-" + scheme.split("://")[0])
        src = self._encode(sample)
        nodes = fetch.download_nodes(src)
        # 每种协议都应被识别提取，无遗漏
        self.assertEqual(len(nodes), len(_PARSERS),
                         f"提取 {len(nodes)} 条，应 {len(_PARSERS)} 条（{list(_PARSERS)}）")
        for scheme in _PARSERS:
            self.assertTrue(any(n.startswith(scheme) for n in nodes),
                            f"缺少协议 {scheme} 的提取")

    def test_plaintext_prefixes_used(self):
        # 与硬编码旧值对比，确认补充了此前缺失的协议
        from node_parse import _PARSERS
        self.assertIn("ssr://", _PARSERS)
        self.assertIn("tuic://", _PARSERS)
        self.assertIn("hysteria2://", _PARSERS)


class TestP1Fixes(unittest.TestCase):
    """P1 修复回归：txt 路径对齐 --out / weight 缺键不崩。"""

    def _write_minimal_sources(self, d):
        # 仅放一个最小 s2-clash-1.yaml（无需 clash_template 即可触发无模版分支）
        src = {"proxies": [
            {"name": "A", "type": "ss", "server": "a.example", "port": 1,
             "cipher": "aes-256-gcm", "password": "x"},
        ]}
        with open(os.path.join(d, "s2-clash-1.yaml"), "w", encoding="utf-8") as f:
            yaml.safe_dump(src, f)

    def test_txt_path_follows_out(self):
        # --out 带子目录时，txt 应同目录同名前缀，而非固定落在 --base 根
        d = tempfile.mkdtemp()
        self._write_minimal_sources(d)
        out_rel = os.path.join("sub", "s-clash.yaml")
        out_abs = os.path.join(d, out_rel)
        with mock.patch.object(sys, "argv", ["merge_subs", "--base", d, "--out", out_rel]):
            m.main()
        expected_txt = os.path.join(d, "sub", "s-clash.txt")
        self.assertTrue(os.path.exists(expected_txt),
                        "s-clash.txt 应随 --out 落在 sub/ 下")
        self.assertFalse(os.path.exists(os.path.join(d, "s-clash.txt")),
                         "不应再固定落在 base 根的 s-clash.txt")
        # yaml 与 txt 都存在
        self.assertTrue(os.path.exists(out_abs))

    def test_txt_path_default_flat(self):
        # 默认 --out s-clash.yaml 时，txt 仍在 base 根（向后兼容）
        d = tempfile.mkdtemp()
        self._write_minimal_sources(d)
        out = os.path.join(d, "s-clash.yaml")
        with mock.patch.object(sys, "argv", ["merge_subs", "--base", d, "--out", "s-clash.yaml"]):
            m.main()
        self.assertTrue(os.path.exists(os.path.join(d, "s-clash.txt")))
        self.assertTrue(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
