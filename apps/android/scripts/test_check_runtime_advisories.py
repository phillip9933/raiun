import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError


SCRIPT = Path(__file__).with_name("check_runtime_advisories.py")
SPEC = importlib.util.spec_from_file_location("check_runtime_advisories", SCRIPT)
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class FakeResponse:
    status = 200

    def __init__(self, payload):
        self.raw = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, limit):
        return self.raw[:limit]


class RuntimeAdvisoryChecks(unittest.TestCase):
    def write_pins(self, root, lines):
        path = root / "runtime-artifact-pins.sha256"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_pin_inventory_validates_and_deduplicates_identical_coordinates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = "a" * 64 + "  g:artifact:1.2.3"
            path = self.write_pins(root, [pin, pin])
            self.assertEqual(
                [{"coordinate": "g:artifact:1.2.3", "sha256": "a" * 64}],
                TOOL.read_pins(path),
            )
            conflict = "b" * 64 + "  g:artifact:1.2.3"
            path = self.write_pins(root, [pin, conflict])
            with self.assertRaisesRegex(TOOL.CheckUnavailable, "conflicting hashes"):
                TOOL.read_pins(path)

    def test_no_advisories_is_a_complete_clean_result(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_pins(Path(directory), ["a" * 64 + "  g:artifact:1.2.3"])
            with patch.object(TOOL.OSV_OPENER, "open", return_value=FakeResponse({"results": [{}]})):
                result = TOOL.run(path)
        self.assertEqual("no_advisories", result["status"])
        self.assertEqual(1, result["package_count"])
        self.assertEqual([], result["packages"][0]["advisories"])

    def test_reports_advisories_and_paginates_each_result_token(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_pins(
                Path(directory),
                ["a" * 64 + "  g:first:1.0", "b" * 64 + "  g:second:2.0"],
            )
            responses = [
                FakeResponse(
                    {
                        "results": [
                            {"vulns": [{"id": "GHSA-first", "summary": "example"}], "next_page_token": "opaque"},
                            {},
                        ]
                    }
                ),
                FakeResponse({"results": [{"vulns": [{"id": "GHSA-second"}]}]}),
            ]
            with patch.object(TOOL.OSV_OPENER, "open", side_effect=responses) as urlopen:
                result = TOOL.run(path)
        self.assertEqual("advisories_found", result["status"])
        self.assertEqual(2, result["advisory_count"])
        self.assertEqual(2, urlopen.call_count)
        second_request = urlopen.call_args_list[1].args[0]
        second_payload = json.loads(second_request.data)
        self.assertEqual(1, len(second_payload["queries"]))
        self.assertEqual("opaque", second_payload["queries"][0]["page_token"])

    def test_malformed_response_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_pins(Path(directory), ["a" * 64 + "  g:artifact:1.2.3"])
            with patch.object(TOOL.OSV_OPENER, "open", return_value=FakeResponse({"unexpected": []})):
                result = TOOL.run(path)
        self.assertEqual("unavailable", result["status"])
        self.assertIn("no results list", result["error"])

    def test_transport_failure_is_unavailable_not_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_pins(Path(directory), ["a" * 64 + "  g:artifact:1.2.3"])
            with patch.object(TOOL.OSV_OPENER, "open", side_effect=URLError("offline")):
                result = TOOL.run(path)
        self.assertEqual("unavailable", result["status"])
        self.assertNotIn("packages", result)

    def test_error_and_unknown_response_fields_cannot_become_clean_results(self):
        payloads = [
            {"results": [{}], "error": {"code": 503}},
            {"results": [{}], "unexpected": True},
            {"results": [{"error": {"code": 503}}]},
            {"results": [{"unexpected": True}]},
            {"results": []},
            {"results": [None]},
            {"results": [{"vulns": None}]},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_pins(Path(directory), ["a" * 64 + "  g:artifact:1.2.3"])
            for payload in payloads:
                with self.subTest(payload=payload):
                    with patch.object(TOOL.OSV_OPENER, "open", return_value=FakeResponse(payload)):
                        result = TOOL.run(path)
                    self.assertEqual("unavailable", result["status"])
                    self.assertNotIn("packages", result)

    def test_advisory_identifiers_and_page_tokens_are_bounded_and_have_no_controls(self):
        entries = [
            {"vulns": [{"id": value}]}
            for value in ("", " ", "bad\nid", "id\u202e", "x" * (TOOL.MAX_ADVISORY_ID_CHARS + 1))
        ] + [
            {"next_page_token": value}
            for value in ("", "bad\ntoken", "x" * (TOOL.MAX_PAGE_TOKEN_CHARS + 1), 7)
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_pins(Path(directory), ["a" * 64 + "  g:artifact:1.2.3"])
            for entry in entries:
                with self.subTest(entry=entry):
                    response = FakeResponse({"results": [entry]})
                    with patch.object(TOOL.OSV_OPENER, "open", return_value=response):
                        result = TOOL.run(path)
                    self.assertEqual("unavailable", result["status"])

    def test_repeated_pagination_is_unavailable_at_the_page_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_pins(Path(directory), ["a" * 64 + "  g:artifact:1.2.3"])
            response = FakeResponse({"results": [{"next_page_token": "repeated"}]})
            with patch.object(TOOL.OSV_OPENER, "open", return_value=response) as request:
                result = TOOL.run(path)
        self.assertEqual("unavailable", result["status"])
        self.assertEqual(TOOL.MAX_PAGES_PER_PACKAGE, request.call_count)

    def test_http_redirects_are_refused_and_only_public_coordinates_are_sent(self):
        handler = next(handler for handler in TOOL.OSV_OPENER.handlers if isinstance(handler, TOOL.RejectRedirects))
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                with self.assertRaises(TOOL.CheckUnavailable):
                    handler.redirect_request(None, None, code, "redirect", {}, "http://other.test/")
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_pins(Path(directory), ["a" * 64 + "  g:artifact:1.2.3"])
            with patch.object(TOOL.OSV_OPENER, "open", return_value=FakeResponse({"results": [{}]})) as opened:
                self.assertEqual("no_advisories", TOOL.run(path)["status"])
        request = opened.call_args.args[0]
        self.assertEqual(TOOL.OSV_URL, request.full_url)
        self.assertEqual("POST", request.method)
        self.assertEqual({"content-type", "accept"}, {key.lower() for key, _ in request.header_items()})
        self.assertEqual(
            {"queries": [{"package": {"ecosystem": "Maven", "name": "g:artifact"}, "version": "1.2.3"}]},
            json.loads(request.data),
        )

    def test_unexpected_http_status_and_oversized_response_are_unavailable(self):
        status_response = FakeResponse({"results": [{}]})
        status_response.status = 503
        large_response = FakeResponse({"results": [{}]})
        large_response.raw = b" " * (TOOL.MAX_RESPONSE_BYTES + 1)
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_pins(Path(directory), ["a" * 64 + "  g:artifact:1.2.3"])
            for response in (status_response, large_response):
                with self.subTest(status=response.status, response_bytes=len(response.raw)):
                    with patch.object(TOOL.OSV_OPENER, "open", return_value=response):
                        self.assertEqual("unavailable", TOOL.run(path)["status"])

    def test_cli_exit_codes_distinguish_findings_unavailable_and_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            with patch.object(sys, "argv", ["checker", "--pins", "pins", "--output", str(output)]):
                with patch.object(TOOL, "run", return_value={"status": "no_advisories", "package_count": 1}):
                    self.assertEqual(0, TOOL.main())
                with patch.object(TOOL, "run", return_value={"status": "advisories_found", "advisory_count": 1}):
                    self.assertEqual(1, TOOL.main())
                with patch.object(TOOL, "run", return_value={"status": "unavailable", "error": "offline"}):
                    self.assertEqual(2, TOOL.main())


if __name__ == "__main__":
    unittest.main()
