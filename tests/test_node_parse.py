import os
import sys
import base64
import json
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from node_parse import parse_uri_to_struct, struct_to_uri


def _vmess_uri():
    j = {"v": "2", "ps": "t", "add": "example.com", "port": "443",
         "id": "12345678-1234-1234-1234-123456789012", "aid": "0", "scy": "auto",
         "net": "tcp", "type": "none", "host": "", "path": "", "tls": "", "sni": ""}
    return "vmess://" + base64.b64encode(json.dumps(j, ensure_ascii=False).encode()).decode()


CASES = {
    "ss": "ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388#t",
    "vmess": _vmess_uri(),
    "vless": "vless://uuid-1234@example.com:443?type=tcp&security=tls&sni=ex.com#t",
    "trojan": "trojan://pass@example.com:443?sni=ex.com#t",
    "ssr": "ssr://" + base64.b64encode(
        b"example.com:8388:origin:aes-256-cfb:plain:" + base64.b64encode(b"pass")
        + b"/?remarks=" + base64.b64encode(b"myname")).decode(),
    "tuic": "tuic://pass@example.com:443?uuid=uuid-1&congestion_control=bbr&udp_relay_mode=native&alpn=h3#t",
    "hysteria2": "hysteria2://pass@example.com:443?sni=ex.com&insecure=1#t",
}

# 反向转换 struct_to_uri 已知、需在往返中保真的字段
KEYS = {
    "ss": ["type", "server", "port", "cipher", "password"],
    "vmess": ["type", "server", "port", "uuid", "cipher", "tls", "network"],
    "vless": ["type", "server", "port", "uuid", "tls", "network", "security_scheme"],
    "trojan": ["type", "server", "port", "password", "tls"],
    "ssr": ["type", "server", "port", "protocol", "cipher", "obfs", "password"],
    "tuic": ["type", "server", "port", "password", "uuid"],
    "hysteria2": ["type", "server", "port", "password", "tls"],
}


class TestRoundtrip(unittest.TestCase):
    def test_all_roundtrip(self):
        for t, uri in CASES.items():
            with self.subTest(t):
                s = parse_uri_to_struct(uri)
                self.assertIsNotNone(s, f"{t} parse failed")
                back = struct_to_uri(s)
                self.assertIsNotNone(back, f"{t} struct_to_uri failed")
                s2 = parse_uri_to_struct(back)
                self.assertIsNotNone(s2, f"{t} re-parse failed")
                for k in KEYS[t]:
                    self.assertEqual(
                        s.get(k), s2.get(k),
                        f"{t}: 字段 {k} 往返丢失 (原={s.get(k)} 回={s2.get(k)})")

    def test_ssr_obfs_protoparam_preserved(self):
        uri = "ssr://" + base64.b64encode(
            b"h:8388:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:" + base64.b64encode(b"pw")
            + b"/?obfsparam=" + base64.b64encode(b"x")
            + b"&protoparam=" + base64.b64encode(b"y")
            + b"&remarks=" + base64.b64encode(b"n")).decode()
        s = parse_uri_to_struct(uri)
        back = struct_to_uri(s)
        s2 = parse_uri_to_struct(back)
        self.assertEqual(s["protocol"], s2["protocol"])
        self.assertEqual(s["obfs"], s2["obfs"])
        self.assertEqual(s["password"], s2["password"])
        self.assertEqual(s.get("obfsparam"), s2.get("obfsparam"))
        self.assertEqual(s.get("protoparam"), s2.get("protoparam"))

    def test_tuic_fields(self):
        uri = "tuic://p@h:443?uuid=u-1&congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=s.com#n"
        s = parse_uri_to_struct(uri)
        back = struct_to_uri(s)
        s2 = parse_uri_to_struct(back)
        self.assertEqual(s.get("uuid"), s2.get("uuid"))
        self.assertEqual(s.get("congestion_control"), s2.get("congestion_control"))
        self.assertEqual(s.get("udp_relay_mode"), s2.get("udp_relay_mode"))

    def test_hy2_fields(self):
        uri = ("hysteria2://p@h:443?sni=s.com&insecure=1&obfs=quic&obfs-password=op"
               "&pinSHA256=abc&alpn=h3&mport=2000#n")
        s = parse_uri_to_struct(uri)
        back = struct_to_uri(s)
        s2 = parse_uri_to_struct(back)
        for k in ("sni", "obfs", "obfs-password", "pinSHA256", "alpn", "mport"):
            self.assertEqual(s.get(k), s2.get(k), f"hy2 字段 {k} 丢失")


if __name__ == "__main__":
    unittest.main()
