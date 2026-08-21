import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fetch_tuijian as ft


class TestExtractLink(unittest.TestCase):
    """P1#5：extract_link 纯函数可测，不触网络/IO。"""

    def test_pre_code_long_hex(self):
        html = '<pre>https://tosslk.xyz/abcdef0123456789abcdef0123456789ab</pre>'
        self.assertEqual(
            ft.extract_link(html),
            "https://tosslk.xyz/abcdef0123456789abcdef0123456789ab",
        )

    def test_short_hex_rejected(self):
        # 末段 <32 位不应匹配
        html = '<pre>https://tosslk.xyz/short</pre>'
        self.assertIsNone(ft.extract_link(html))

    def test_a_href_fallback(self):
        html = ('<a href="https://tosslk.xyz/'
                'abcdef0123456789abcdef0123456789abcdef0123456789abcdef01">x</a>')
        self.assertIn("tosslk.xyz", ft.extract_link(html))

    def test_no_link(self):
        self.assertIsNone(ft.extract_link("<html><body>no link here</body></html>"))

    def test_irrelevant_domain_ignored(self):
        html = '<pre>https://example.com/abcdef0123456789abcdef0123456789ab</pre>'
        self.assertIsNone(ft.extract_link(html))


if __name__ == "__main__":
    unittest.main()
