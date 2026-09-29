import copy
import json
import unittest

from harsieve.core import HarError, sanitize
from harsieve.demo import capture
from harsieve.report import render, summary


class SanitizerTests(unittest.TestCase):
    def setUp(self):
        self.raw = capture()

    def test_removes_every_demo_canary_from_all_outputs(self):
        clean, audit = sanitize(self.raw)
        output = json.dumps(clean) + json.dumps(audit) + render(clean, audit)
        for private in (
            "DEMO_SECRET",
            "private.example",
            "metrics.example",
            "private-user",
            "192.0.2.42",
            "2026-01-01",
        ):
            self.assertNotIn(private, output)

    def test_no_mutation(self):
        before = copy.deepcopy(self.raw)
        sanitize(self.raw)
        self.assertEqual(before, self.raw)

    def test_repeatable(self):
        self.assertEqual(sanitize(self.raw), sanitize(self.raw))

    def test_unknown_fields_dropped_at_every_level(self):
        e = self.raw["log"]["entries"][0]
        for obj in (
            self.raw,
            self.raw["log"],
            e,
            e["request"],
            e["response"],
            e["response"]["content"],
            e["timings"],
        ):
            obj["_CANARY_EXTENSION"] = {"private": "DO_NOT_SHARE"}
            obj["comment"] = "DO_NOT_SHARE"
        self.raw["log"]["pages"] = [{"title": "DO_NOT_SHARE"}]
        out = json.dumps(sanitize(self.raw))
        self.assertNotIn("DO_NOT_SHARE", out)
        self.assertNotIn("CANARY", out)

    def test_all_headers_removed_including_unusual_names(self):
        e = self.raw["log"]["entries"][0]
        e["response"]["headers"] = [{"name": "innocent", "value": "secret"}]
        clean, _ = sanitize(self.raw)
        self.assertEqual(clean["log"]["entries"][0]["response"]["headers"], [])

    def test_urls_remove_userinfo_query_fragment_and_entire_path(self):
        self.raw["log"]["entries"][0]["request"]["url"] = (
            "https://alice:secret@internal.example:8443/users/alice@example.com?api_key=secret#secret"
        )
        out = json.dumps(sanitize(self.raw)[0])
        for token in ("alice", "secret", "internal.example", "8443", "api_key"):
            self.assertNotIn(token, out)

    def test_aliases_preserve_endpoint_equality(self):
        clean, _ = sanitize(self.raw)
        urls = [e["request"]["url"] for e in clean["log"]["entries"]]
        self.assertEqual(urls[4], urls[5])
        self.assertNotEqual(urls[0], urls[1])

    def test_origin_aliases_distinguish_ports_and_schemes(self):
        entries = self.raw["log"]["entries"][:3]
        self.raw["log"]["entries"] = entries
        for e, url in zip(
            entries,
            ("https://a.example/x", "https://a.example:8443/x", "http://a.example/x"),
            strict=True,
        ):
            e["request"]["url"] = url
        clean, audit = sanitize(self.raw)
        self.assertEqual(audit["origins_aliased"], 3)
        self.assertEqual(len({e["request"]["url"] for e in clean["log"]["entries"]}), 3)

    def test_equivalent_default_port_and_hostname_case(self):
        entries = self.raw["log"]["entries"][:2]
        self.raw["log"]["entries"] = entries
        entries[0]["request"]["url"] = "https://A.example/x"
        entries[1]["request"]["url"] = "https://a.example:443/x?secret=1"
        clean, audit = sanitize(self.raw)
        self.assertEqual(audit["origins_aliased"], 1)
        self.assertEqual(
            clean["log"]["entries"][0]["request"]["url"],
            clean["log"]["entries"][1]["request"]["url"],
        )

    def test_relative_timestamps_preserved_when_input_unsorted(self):
        self.raw["log"]["entries"].reverse()
        clean, _ = sanitize(self.raw)
        stamps = [e["startedDateTime"] for e in clean["log"]["entries"]]
        self.assertTrue(stamps[-1].startswith("2000-01-01T00:00:00.000"))
        self.assertTrue(stamps[0].startswith("2000-01-01T00:00:01.265"))

    def test_methods_mimes_versions_use_closed_vocabulary(self):
        e = self.raw["log"]["entries"][0]
        e["request"]["method"] = "CUSTOM_SECRET"
        e["request"]["httpVersion"] = "SECRET_PROTOCOL"
        e["response"]["content"]["mimeType"] = "application/SECRET"
        clean, _ = sanitize(self.raw)
        out = clean["log"]["entries"][0]
        self.assertEqual(out["request"]["method"], "OTHER")
        self.assertEqual(out["request"]["httpVersion"], "HTTP/1.1")
        self.assertEqual(out["response"]["content"]["mimeType"], "application/octet-stream")
        self.assertNotIn("SECRET", json.dumps(clean))

    def test_mime_parameters_removed(self):
        self.raw["log"]["entries"][0]["response"]["content"]["mimeType"] = (
            "application/json; secret=abc"
        )
        self.assertEqual(
            sanitize(self.raw)[0]["log"]["entries"][0]["response"]["content"]["mimeType"],
            "application/json",
        )

    def test_empty_capture(self):
        self.raw["log"]["entries"] = []
        clean, audit = sanitize(self.raw)
        self.assertEqual(summary(clean)["p95_ms"], 0)
        self.assertIn("No requests match", render(clean, audit))

    def test_summary_error_unknown_size_and_nearest_rank(self):
        stats = summary(sanitize(self.raw)[0])
        self.assertEqual(stats["http_errors"], 2)
        self.assertEqual(stats["no_response"], 1)
        self.assertEqual(stats["unknown_response_sizes"], 1)
        self.assertEqual(stats["p95_ms"], 1680)

    def test_audit_counts_actual_structures(self):
        _, audit = sanitize(self.raw)
        self.assertEqual(
            audit["removed"],
            dict(
                headers=12, cookies=12, query_parameters=12, request_bodies=12, response_bodies=12
            ),
        )

    def test_html_does_not_include_payload_markup(self):
        e = self.raw["log"]["entries"][0]
        e["response"]["content"]["text"] = '</script><script>alert("CANARY_XSS")</script>'
        clean, audit = sanitize(self.raw)
        report = render(clean, audit)
        self.assertNotIn("CANARY_XSS", report)
        self.assertIn("connect-src 'none'", report)

    def test_invalid_shapes(self):
        for data in (
            None,
            [],
            {},
            {"log": []},
            {"log": {"version": "1.1", "entries": []}},
            {"log": {"version": "1.2", "entries": {}}},
        ):
            with self.subTest(data=data), self.assertRaises(HarError):
                sanitize(data)

    def test_invalid_entry_structures(self):
        for key in ("request", "response", "timings"):
            for value in (None, [], "SECRET"):
                with self.subTest(key=key, value=value):
                    raw = capture()
                    raw["log"]["entries"][0][key] = value
                    with self.assertRaises(HarError):
                        sanitize(raw)

    def test_invalid_numbers(self):
        for number in (True, "123", float("nan"), float("inf"), -1, 10**500):
            with self.subTest(number=str(number)[:20]):
                self.raw["log"]["entries"][0]["time"] = number
                with self.assertRaises(HarError):
                    sanitize(self.raw)

    def test_invalid_status(self):
        for status in (-1, 600, "200", True, None):
            with self.subTest(status=status):
                self.raw["log"]["entries"][0]["response"]["status"] = status
                with self.assertRaises(HarError):
                    sanitize(self.raw)

    def test_invalid_sizes(self):
        for size in (-2, 1.5, "10", True, 2**53):
            with self.subTest(size=size):
                self.raw["log"]["entries"][0]["response"]["bodySize"] = size
                with self.assertRaises(HarError):
                    sanitize(self.raw)

    def test_invalid_timestamps(self):
        for stamp in ("secret", "2026-01-01T00:00:00", None, "x" * 100):
            with self.subTest(stamp=stamp):
                self.raw["log"]["entries"][0]["startedDateTime"] = stamp
                with self.assertRaises(HarError):
                    sanitize(self.raw)

    def test_invalid_urls_do_not_echo_values(self):
        for url in (
            "data:SECRET",
            "file:///SECRET",
            "https://[SECRET",
            "https://host:bad/SECRET",
            "https://a/\nSECRET",
            None,
        ):
            with self.subTest(url=url):
                self.raw["log"]["entries"][0]["request"]["url"] = url
                with self.assertRaises(HarError) as caught:
                    sanitize(self.raw)
                self.assertNotIn("SECRET", str(caught.exception))

    def test_missing_required_timing(self):
        del self.raw["log"]["entries"][0]["timings"]["wait"]
        with self.assertRaises(HarError):
            sanitize(self.raw)

    def test_websocket_scheme_without_messages(self):
        self.raw["log"]["entries"][0]["request"]["url"] = "wss://private.example/channel"
        clean, _ = sanitize(self.raw)
        self.assertTrue(clean["log"]["entries"][0]["request"]["url"].startswith("wss://"))
        self.assertNotIn("_webSocketMessages", json.dumps(clean))

    def test_metadata_is_preserved(self):
        clean, _ = sanitize(self.raw)
        for original, projected in zip(
            self.raw["log"]["entries"], clean["log"]["entries"], strict=True
        ):
            self.assertEqual(original["time"], projected["time"])
            self.assertEqual(original["timings"], projected["timings"])
            self.assertEqual(original["response"]["status"], projected["response"]["status"])
            self.assertEqual(original["response"]["bodySize"], projected["response"]["bodySize"])

    def test_unknown_nested_payloads_cannot_reenter_output(self):
        for index in range(100):
            raw = capture()
            canary = f"PRIVATE_CANARY_{index:04d}"
            raw["log"]["entries"][index % 12][f"_custom_{index}"] = {
                "text": canary,
                "deep": [{"secret": [canary]}],
            }
            clean, audit = sanitize(raw)
            self.assertNotIn(canary, json.dumps(clean) + json.dumps(audit) + render(clean, audit))

    def test_fractional_negative_timing_rejected(self):
        self.raw["log"]["entries"][0]["timings"]["dns"] = -0.5
        with self.assertRaises(HarError):
            sanitize(self.raw)

    def test_unavailable_timing_preserved(self):
        self.raw["log"]["entries"][0]["timings"]["dns"] = -1
        self.assertEqual(sanitize(self.raw)[0]["log"]["entries"][0]["timings"]["dns"], -1)

    def test_origins_do_not_collapse_port_zero(self):
        entries = self.raw["log"]["entries"][:2]
        self.raw["log"]["entries"] = entries
        entries[0]["request"]["url"] = "https://example.com/x"
        entries[1]["request"]["url"] = "https://example.com:0/x"
        self.assertEqual(sanitize(self.raw)[1]["origins_aliased"], 2)

    def test_capture_span_bounded(self):
        self.raw["log"]["entries"][0]["startedDateTime"] = "1900-01-01T00:00:00Z"
        with self.assertRaises(HarError):
            sanitize(self.raw)

    def test_nonstring_method_rejected(self):
        self.raw["log"]["entries"][0]["request"]["method"] = ["SECRET"]
        with self.assertRaises(HarError):
            sanitize(self.raw)

    def test_no_original_url_in_any_free_form_field(self):
        e = self.raw["log"]["entries"][0]
        e["response"]["redirectURL"] = "https://SECRET.example"
        e["response"]["statusText"] = "SECRET"
        e["cache"] = {"afterRequest": {"eTag": "SECRET"}}
        self.assertNotIn("SECRET", json.dumps(sanitize(self.raw)))
