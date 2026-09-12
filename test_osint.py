"""Offline OSINT parser, provenance and privacy boundary tests; no public requests."""
import contextlib
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import burhan as b
import burhan_osint as o
from test_burhan import policy, ROOT

CRT = [{"name_value": "dev.example.com\n*.example.com\nexample.com.evil.invalid", "not_before": "2024-02-01T00:00:00"}]
CDX = [["timestamp", "original", "statuscode"],
       ["20240201120000", "https://dev.example.com/api/old?token=SENSITIVE", "200"],
       ["20240201120000", "https://outside.invalid/", "200"]]


class DomainTests(unittest.TestCase):
    def test_domain_syntax_and_ip_rejection(self):
        self.assertEqual(o.domain_name("EXAMPLE.COM."), "example.com")
        for name in ["com", "https://example.com", "127.0.0.1", "a..com", "-a.com", "a-.com", "me@example.com"]:
            with self.subTest(name=name), self.assertRaises(b.GuardError):
                o.domain_name(name)

    def test_ct_wildcard_is_not_a_live_subdomain(self):
        rows, rejected, _ = o.parse_records("crtsh", CRT, "example.com")
        self.assertEqual(rejected, 1)
        self.assertTrue(any(r["wildcard"] and r["host"] == "example.com" for r in rows))
        self.assertEqual(rows[0]["time_meaning"], "certificate not_before, not live observation")

    def test_archive_scope_redaction_and_history(self):
        rows, rejected, _ = o.parse_records("wayback", CDX, "example.com")
        self.assertEqual(rejected, 1)
        self.assertEqual(rows[0]["historical_status"], "200")
        self.assertNotIn("SENSITIVE", json.dumps(rows))
        self.assertIn("2024-02-01", rows[0]["source_time"])

    def test_invalid_provider_schema_and_bad_dates(self):
        for provider in ["crtsh", "wayback", "certspotter"]:
            with self.subTest(provider=provider), self.assertRaises(b.GuardError):
                o.parse_records(provider, {"error": "unauthorized"}, "example.com")
        with self.assertRaises(b.GuardError):
            o.parse_records("wayback", [["wrong"]], "example.com")
        rows, rejected, _ = o.parse_records("wayback", [CDX[0], ["invalid", "https://example.com/", "200"]], "example.com")
        self.assertEqual(rows, [])
        self.assertEqual(rejected, 1)

    def test_duplicate_ct_sources_are_one_source_family(self):
        p = policy()
        engine = o.DomainIntel(p, "example.com", certspotter=True)
        def get(url, *, provider):
            self.assertTrue(provider)
            if url.startswith("https://crt.sh"):
                data = CRT
            elif url.startswith("https://api.certspotter.com"):
                data = [{"dns_names": ["dev.example.com"], "not_before": "2024-02-01T00:00:00Z"}]
            else:
                data = []
            return b.Response(url, 200, body=json.dumps(data).encode(), event_id="Etest")
        with patch.object(engine.transport, "get", side_effect=get):
            report = engine.run()
        asset = next(a for a in report["assets"] if a["host"] == "dev.example.com")
        self.assertEqual(len(asset["providers"]), 2)
        self.assertEqual(asset["source_families"], ["certificate_transparency"])
        self.assertTrue(asset["needs_scope_approval"])
        self.assertEqual(asset["live_status"], "not tested")

    def test_no_target_resolution_or_http(self):
        engine = o.DomainIntel(policy(), "example.com")
        seen = []
        def failed_dns(host, port, timeout):
            seen.append(host)
            raise b.GuardError("fixture refuses all external resolution")
        with patch.object(b, "resolve", side_effect=failed_dns), patch.object(socket, "create_connection") as connect:
            report = engine.run()
        connect.assert_not_called()
        self.assertEqual(set(seen), {"crt.sh", "web.archive.org"})
        self.assertEqual(report["target_http_requests"], 0)
        self.assertEqual(report["target_dns_lookups"], 0)
        self.assertEqual(report["provider_request_attempts"], 2)
        self.assertEqual(report["run_status"], "partial")

    def test_budget_records_remaining_providers_as_untested(self):
        p = policy(max_requests=1)
        engine = o.DomainIntel(p, "example.com", certspotter=True)
        with patch.object(b, "resolve", side_effect=b.GuardError("blocked")):
            report = engine.run()
        self.assertEqual(len(report["coverage"]), 3)
        self.assertEqual(report["coverage"][-1]["status"], "not_tested")
        self.assertEqual(report["provider_request_attempts"], 1)

    def test_requires_exact_domain_in_policy(self):
        with self.assertRaises(b.GuardError):
            o.DomainIntel(policy(), "sub.example.com")

    def test_certspotter_not_enabled_by_default(self):
        self.assertEqual(o.DomainIntel(policy(), "example.com").providers, ["crtsh", "wayback"])

    def test_domain_cli_requires_sharing_consent(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            path = Path(td) / "policy.json"
            path.write_text(json.dumps(b.dataclasses.asdict(policy())))
            with patch.object(b, "resolve") as resolver, contextlib.redirect_stderr(io.StringIO()):
                code = b.main(["osint", "domain", "--domain", "example.com", "--policy", str(path), "--out", str(Path(td) / "report")])
            self.assertEqual(code, 1)
            resolver.assert_not_called()

    def test_parser_cap_visible(self):
        rows, _, capped = o.parse_records("crtsh", [{"name_value": "example.com"}] * 501, "example.com")
        self.assertEqual(len(rows), 500)
        self.assertTrue(capped)


class SelfAuditTests(unittest.TestCase):
    def audit(self, kind, identifier, records):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            value, source = Path(td) / "value", Path(td) / "source.jsonl"
            value.write_text(identifier)
            source.write_text("\n".join(json.dumps(r) for r in records))
            with patch.object(socket, "create_connection") as connect, patch.object(b, "resolve") as resolver:
                result = o.local_audit(kind, value, source)
            connect.assert_not_called()
            resolver.assert_not_called()
            self.assertNotIn(identifier, json.dumps(result))
            return result

    def test_email_exact_occurrence_and_alias_preservation(self):
        result = self.audit("email", "Me+tag@example.com", [{"content": "Contact Me+tag@example.com"},
                                                            {"content": "Me@example.com"},
                                                            {"content": "me+tag@example.com"}])
        self.assertEqual([r["input_record"] for r in result["matches"]], [1])
        self.assertEqual(result["network_requests"], 0)

    def test_email_domain_case_normalized(self):
        self.assertEqual(o.normalize_identifier("email", "A@EXAMPLE.COM"), "A@example.com")

    def test_phone_explicit_international_normalization(self):
        result = self.audit("phone", "+12025550123", [{"content": "My number +1 (202) 555-0123"},
                                                      {"content": "+12025550124"}])
        self.assertEqual(len(result["matches"]), 1)
        with self.assertRaises(b.GuardError):
            o.normalize_identifier("phone", "2025550123")

    def test_no_fuzzy_person_identity_linking(self):
        result = self.audit("name", "Sample Person", [{"content": "Sample Person"},
                                                      {"content": "Sample Person II"},
                                                      {"content": "Sample Pers0n"}])
        self.assertEqual(len(result["matches"]), 1)
        self.assertEqual(result["matches"][0]["state"], "exact_text_occurrence_not_identity_proof")

    def test_unsupported_export_records_reported(self):
        result = self.audit("email", "self@example.com", [{"profile": "other data"}, {"content": 123}])
        self.assertEqual(len(result["rejected"]), 2)
        self.assertEqual(result["matches"], [])

    def test_identifier_is_not_added_to_html(self):
        result = self.audit("phone", "+12025550123", [{"content": "+12025550123"}])
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            out = Path(td) / "report"
            o.write_output(result, out)
            self.assertTrue(b.verify_report(out))
            self.assertNotIn("+12025550123", (out / "report.html").read_text())

    def test_cli_consent_failure_is_clean_in_subprocess(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            result = subprocess.run([sys.executable, "-B", str(ROOT / "burhan.py"), "osint", "self-audit",
                                     "--kind", "email", "--value-file", "missing", "--input", "missing",
                                     "--out", str(Path(td) / "report")], cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("Traceback", result.stderr)
            self.assertIn("--consented", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
