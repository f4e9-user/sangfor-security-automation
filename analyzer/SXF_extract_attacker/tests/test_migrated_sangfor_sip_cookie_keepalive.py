import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT / "situation-awareness"))

from sangfor_sip_cookie_keepalive import should_exit_after_response


class SangforSipCookieKeepaliveTests(unittest.TestCase):
    def test_redirect_response_exits_without_retry(self):
        self.assertTrue(should_exit_after_response(302, None, stop_on_need_login=False))


if __name__ == "__main__":
    unittest.main()
