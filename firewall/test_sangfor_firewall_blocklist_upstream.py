import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from sangfor_firewall_blocklist import (
    BlacklistClient,
    build_entries,
    csrf_token_from_cookie,
    default_description,
    extract_export_file,
    load_cookie_from_session_file,
    parse_args,
    resolve_cookie,
)


class FakeTransport:
    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or [(200, {"content-type": "application/json"}, b'{"ok":true}')]

    def request(self, method, url, *, headers=None, data=None):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers or {},
                "data": data,
            }
        )
        return self.responses.pop(0)


class AutoBlocklistTests(unittest.TestCase):
    def test_extract_export_file_from_common_response_shapes(self):
        cases = [
            (b'{"file":"/export/blacklist_1783136728541.csv"}', "/export/blacklist_1783136728541.csv"),
            (b'{"data":{"path":"/export/blacklist_1783136728541.csv"}}', "/export/blacklist_1783136728541.csv"),
            (b'{"data":{"fileName":"blacklist_1783145496646.csv"}}', "/export/blacklist_1783145496646.csv"),
            (b'{"msg":"created /export/blacklist_1783136728541.csv"}', "/export/blacklist_1783136728541.csv"),
        ]

        for body, expected in cases:
            with self.subTest(body=body):
                self.assertEqual(extract_export_file(body), expected)

    def test_build_entries_trims_deduplicates_and_uses_black_type(self):
        entries = build_entries([" 117.72.195.41 ", "", "evil.example", "117.72.195.41"], "7月封禁")

        self.assertEqual(
            entries,
            [
                {"url": "117.72.195.41", "description": "7月封禁", "type": "BLACK"},
                {"url": "evil.example", "description": "7月封禁", "type": "BLACK"},
            ],
        )

    def test_default_description_uses_current_month(self):
        self.assertEqual(default_description(date(2026, 7, 4)), "7月封禁")
        self.assertEqual(default_description(date(2026, 12, 1)), "12月封禁")

    def test_desc_argument_overrides_default_description(self):
        args = parse_args(["--desc", "应急处置", "117.72.195.41"])

        self.assertEqual(args.description, "应急处置")

    def test_csrf_token_is_triple_md5_of_sessid_cookie(self):
        cookie = "SESSID=D1842119E76B83CACC4B7C46B88F9DAB41A11F5624F1E408A802E71B02E6968; language=zh_CN"

        self.assertEqual(csrf_token_from_cookie(cookie), "cc3a1440b59db85ae6441a927b46aedf")

    def test_client_derives_csrf_token_when_not_provided(self):
        client = BlacklistClient(
            cookie="SESSID=27A9E94454106C72C4E8BE698B51F2D01055D9B1EBD461D0C37BB3396A92903",
            csrf_token=None,
            transport=FakeTransport(),
        )

        self.assertEqual(client.csrf_token, "ec71c063bc2dd610d1bb2cbb539b2112")

    def test_load_cookie_from_nonempty_session_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session_path = f"{tmpdir}/session.json"
            with open(session_path, "w", encoding="utf-8") as file:
                json.dump({"base_url": "https://fw.local", "cookie": "SESSID=from-file; language=zh_CN"}, file)

            self.assertEqual(load_cookie_from_session_file(session_path), "SESSID=from-file; language=zh_CN")

    def test_resolve_cookie_prefers_cli_cookie_over_session_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session_path = f"{tmpdir}/session.json"
            with open(session_path, "w", encoding="utf-8") as file:
                json.dump({"cookie": "SESSID=from-file"}, file)

            self.assertEqual(resolve_cookie("SESSID=from-cli", session_path), "SESSID=from-cli")

    def test_block_posts_expected_headers_and_payload(self):
        transport = FakeTransport()
        client = BlacklistClient(
            base_url="https://firewall.local",
            cookie="SESSID=abc; x-anti-csrf-gcs=csrf-cookie",
            csrf_token="csrf-header",
            transport=transport,
        )

        client.block(["117.72.195.41"], description="7月封禁")

        self.assertEqual(len(transport.calls), 1)
        call = transport.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(
            call["url"],
            "https://firewall.local/api/batch/v1/namespaces/public/whiteblacklist?override=SKIPBACK",
        )
        self.assertEqual(call["headers"]["Cookie"], "SESSID=abc; x-anti-csrf-gcs=csrf-cookie")
        self.assertEqual(call["headers"]["_cftoken"], "csrf-header")
        self.assertEqual(call["headers"]["Content-Type"], "application/json")
        self.assertEqual(
            json.loads(call["data"].decode("utf-8")),
            [{"url": "117.72.195.41", "description": "7月封禁", "type": "BLACK"}],
        )

    def test_export_posts_expected_payload_and_returns_file(self):
        transport = FakeTransport(
            [(200, {"content-type": "application/json"}, b'{"data":{"file":"/export/blacklist_1783145132411.csv"}}')]
        )
        client = BlacklistClient(
            base_url="https://firewall.local",
            cookie="SESSID=abc",
            csrf_token="csrf-header",
            transport=transport,
        )

        export_file = client.export_blacklist()

        self.assertEqual(export_file, "/export/blacklist_1783145132411.csv")
        call = transport.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["url"], "https://firewall.local/api/v1/namespaces/public/export")
        self.assertEqual(call["headers"]["_cftoken"], "csrf-header")
        self.assertEqual(call["headers"]["Content-Type"], "application/json")
        self.assertEqual(
            json.loads(call["data"].decode("utf-8")),
            {"moduleName": "blacklist", "filter": [], "isAll": True, "exportType": "CSV"},
        )

    def test_download_export_uses_empty_post_body(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            old_file = f"{tmpdir}/blacklist_1783145132411.csv"
            keep_file = f"{tmpdir}/unrelated.csv"
            with open(old_file, "wb") as file:
                file.write(b"old\n")
            with open(keep_file, "wb") as file:
                file.write(b"keep\n")
            transport = FakeTransport([(200, {"content-type": "text/csv"}, b"url,description\n")])
            client = BlacklistClient(
                base_url="https://firewall.local",
                cookie="SESSID=abc",
                csrf_token="csrf-header",
                transport=transport,
            )

            output_path = client.download_export("/export/blacklist_1783145132411.csv", output_dir=tmpdir)

            call = transport.calls[0]
            self.assertEqual(call["method"], "POST")
            self.assertEqual(
                call["url"],
                "https://firewall.local/php/loadfile.php?file=/export/blacklist_1783145132411.csv",
            )
            self.assertEqual(call["data"], b"")
            self.assertEqual(call["headers"]["Content-Type"], "application/x-www-form-urlencoded")
            self.assertEqual(str(output_path), f"{tmpdir}/sangfor_firewall_blacklists.csv")
            self.assertFalse(Path(old_file).exists())
            self.assertTrue(Path(keep_file).exists())
            self.assertEqual(Path(output_path).read_bytes(), b"url,description\n")


if __name__ == "__main__":
    unittest.main()
