"""Deterministic regression suite. All live traffic stays on ephemeral loopback fixtures."""
import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import burhan as b

ROOT = Path(__file__).resolve().parent
TOKEN = "ghp_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2"
HEAD = b"ref: refs/heads/main\n"


def policy(site="https://example.com", **changes):
    values = dict(origins=[site], authorization_ref="SYNTHETIC-LOCAL-TEST",
                  expires_at=(b.utcnow() + dt.timedelta(hours=1)).isoformat(), automation_allowed=True)
    values.update(changes)
    result = b.Policy(**values)
    result.validate()
    return result


@contextlib.contextmanager
def fixture(mode="positive", tls=None):
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            requests.append((self.path, dict(self.headers)))
            if mode == "incomplete":
                self.connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\nConnection: close\r\n\r\n" + HEAD)
                return
            if mode == "slow_headers":
                try:
                    self.connection.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                    for _ in range(100):
                        self.connection.sendall(b"a")
                        time.sleep(0.025)
                except OSError:
                    pass
                return
            if mode == "slow_body":
                self.send_response(200)
                self.send_header("Content-Length", "100")
                self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b"a")
                        self.wfile.flush()
                        time.sleep(0.025)
                except OSError:
                    pass
                return
            status, body, headers = 200, b"", {"Content-Type": "text/plain"}
            if mode == "rate_limit":
                status, body = 429, b"slow down"
            elif mode == "unavailable":
                status, body = 503, b"unavailable"
            elif mode == "redirect":
                status, body = 302, b"redirect"
                headers["Location"] = "http://127.0.0.1:1/private?token=never-store"
            elif mode == "large":
                body = b"x" * 4096
            elif mode == "spa":
                body = b"<html><title>Portal</title><p>email password cloudflare</p></html>"
                headers["Content-Type"] = "text/html"
            elif mode == "catchall_git":
                body = HEAD
            elif self.path == "/":
                body = b'<html><title>Local test</title><script src="/app.js"></script><script src="https://outside.invalid/skip.js"></script><a href="/delete">skip</a></html>'
                headers.update({"Content-Type": "text/html", "Set-Cookie": "pref=not-a-secret; Path=/", "CF-Ray": "ordinary-cdn-header"})
            elif self.path == "/.git/HEAD":
                n = sum(path == self.path for path, _ in requests)
                body = HEAD if mode != "unstable" or n == 1 else b"ref: refs/heads/changed\n"
            elif self.path.startswith("/.git/"):
                status, body = 404, b"not found"
            elif self.path == "/app.js":
                body = ('const api="/api/catalog"; const sample="' + TOKEN + '";\n//# sourceMappingURL=app.js.map').encode()
                headers["Content-Type"] = "application/javascript"
            elif self.path == "/app.js.map":
                body = json.dumps({"version": 3, "sources": ["client.js"], "mappings": "AAAA", "sourcesContent": ["test source"]}).encode()
                headers["Content-Type"] = "application/json"
            elif self.path == "/.well-known/security.txt":
                body = b"Contact: mailto:security@example.invalid\n"
            elif self.path == "/sitemap.xml":
                body = b"<urlset/>"
            else:
                body = b"User-agent: *\n"
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    if tls:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    site = f"{'https' if tls else 'http'}://127.0.0.1:{server.server_port}"
    try:
        yield site, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def run_fixture(mode="positive", **changes):
    with fixture(mode) as (site, requests):
        p = policy(site, **changes)
        a = b.Assessment(p, lab=True)
        # Unit tests bypass waiting only; production policy rejects intervals below 0.5s.
        p.interval_seconds = 0
        report = a.run()
        return report, list(requests)


class ScopeTests(unittest.TestCase):
    def test_canonical_default_ports_idna_and_fragment(self):
        self.assertEqual(b.canonical("HTTPS://EXAMPLE.COM:443/a#part"), "https://example.com/a")
        self.assertEqual(b.canonical("https://bücher.example/"), "https://xn--bcher-kva.example/")

    def test_ambiguous_urls_rejected(self):
        urls = ["https://u:p@example.com", "file:///etc/passwd", "https://example.com/%252e%252e/x",
                "https://example.com/a\\b", "https://example.com/a/../b", "https://example.com/a//b",
                "https://example.com/%00", "https://example.com:70000/", "https://example.com/?token=x",
                "https://example.com/\r\nX:a", "http://[fe80::1%25eth0]/"]
        for value in urls:
            with self.subTest(value=value), self.assertRaises(b.GuardError):
                b.canonical(value)

    def test_scope_origin_port_scheme_and_suffix(self):
        p = policy()
        for raw in ["https://example.com.evil.test/", "https://sub.example.com/", "http://example.com/", "https://example.com:8443/"]:
            with self.subTest(raw=raw), self.assertRaises(b.GuardError):
                p.allowed(raw)

    def test_exclusions_apply_to_decoded_paths(self):
        p = policy(excluded_paths=["/private"])
        for raw in ["/private", "/private/data", "/%70rivate/data", "/%2570rivate/data"]:
            with self.subTest(raw=raw), self.assertRaises(b.GuardError):
                p.allowed("https://example.com" + raw)
        self.assertEqual(p.allowed("https://example.com/private-public"), "https://example.com/private-public")

    def test_exclude_all(self):
        with self.assertRaises(b.GuardError):
            policy(excluded_paths=["/"]).allowed("https://example.com/")

    def test_state_changing_route_rejected(self):
        with self.assertRaises(b.GuardError):
            policy().allowed("https://example.com/account/delete")

    def test_strict_config_types_and_bounds(self):
        for value in [float("nan"), float("inf"), -1, 0, True, "40"]:
            with self.subTest(value=value), self.assertRaises(b.GuardError):
                policy(max_requests=value)
        with self.assertRaises(b.GuardError):
            policy(interval_seconds=0.1)
        with self.assertRaises(b.GuardError):
            policy(automation_allowed="true")
        with self.assertRaises(b.GuardError):
            policy(expires_at="2027-01-01")

    def test_policy_load_unknown_field_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            path = Path(td) / "policy.json"
            path.write_text(json.dumps({"unknown": True}))
            with self.assertRaises(b.GuardError):
                b.Policy.load(path)

    def test_lab_rejects_hostnames_and_mixed_origins(self):
        p = policy()
        with self.assertRaises(b.GuardError):
            b.Transport(p, b.Budget(p), lab=True)
        p.origins = ["http://127.0.0.1", "https://example.com"]
        with self.assertRaises(b.GuardError):
            b.Transport(p, b.Budget(p), lab=True)


class BudgetTests(unittest.TestCase):
    def test_budget_enforced(self):
        p = policy(max_requests=1)
        budget = b.Budget(p)
        budget.acquire(p.origins[0])
        with self.assertRaises(b.StopScan):
            budget.acquire(p.origins[0])

    def test_expiry_enforced(self):
        p = policy(expires_at=(b.utcnow() - dt.timedelta(seconds=1)).isoformat())
        with self.assertRaises(b.StopScan):
            b.Budget(p).acquire(p.origins[0])

    def test_time_budget_enforced(self):
        p = policy()
        budget = b.Budget(p)
        budget.deadline = time.monotonic() - 1
        with self.assertRaises(b.StopScan):
            budget.acquire(p.origins[0])

    def test_spacing_is_global(self):
        p = policy(interval_seconds=0.5)
        budget = b.Budget(p)
        start = time.monotonic()
        budget.acquire("https://a.example")
        budget.acquire("https://b.example")
        self.assertGreaterEqual(time.monotonic() - start, 0.48)

    def test_error_circuit_opens_after_two_failures(self):
        p = policy()
        budget = b.Budget(p)
        site = p.origins[0]
        budget.observe(site, b.Response(site, error="TimeoutError"))
        self.assertNotIn(site, budget.blocked)
        budget.observe(site, b.Response(site, status=500))
        self.assertIn(site, budget.blocked)

    def test_cdn_presence_is_not_a_challenge(self):
        p = policy()
        budget = b.Budget(p)
        budget.observe(p.origins[0], b.Response(p.origins[0], status=200, headers={"cf-ray": "abc"}))
        self.assertFalse(budget.blocked)
        budget.observe(p.origins[0], b.Response(p.origins[0], status=200, headers={"cf-mitigated": "challenge"}))
        self.assertTrue(budget.blocked)


class TransportTests(unittest.TestCase):
    def test_out_of_scope_never_resolves_or_connects(self):
        p = policy()
        t = b.Transport(p, b.Budget(p))
        with patch.object(b, "resolve") as resolver, self.assertRaises(b.GuardError):
            t.get("https://outside.invalid/")
        resolver.assert_not_called()
        self.assertEqual(t.budget.count, 0)

    def test_private_and_mixed_dns_rejected_before_connect(self):
        p = policy()
        for ips in [["127.0.0.1"], ["93.184.216.34", "10.0.0.1"], ["169.254.169.254"], ["::1"]]:
            with self.subTest(ips=ips):
                t = b.Transport(p, b.Budget(p))
                with patch.object(b, "resolve", return_value=ips), patch.object(socket, "create_connection") as connect:
                    result = t.get("https://example.com/")
                connect.assert_not_called()
                self.assertEqual(result.error, "GuardError")
                self.assertEqual(len(t.budget.events), 1)

    def test_redirect_not_followed(self):
        with fixture("redirect") as (site, requests):
            p = policy(site)
            t = b.Transport(p, b.Budget(p), lab=True)
            r = t.get(site + "/")
            self.assertEqual(r.status, 302)
            self.assertEqual(len(requests), 1)
            self.assertNotIn("never-store", json.dumps(t.budget.events))

    def test_body_limit(self):
        with fixture("large") as (site, requests):
            p = policy(site, max_body_bytes=1024)
            t = b.Transport(p, b.Budget(p), lab=True)
            r = t.get(site + "/")
            self.assertTrue(r.truncated)
            self.assertFalse(r.usable)
            self.assertEqual(len(r.body), 1024)

    def test_premature_response_close_is_inconclusive(self):
        with fixture("incomplete") as (site, _):
            p = policy(site)
            t = b.Transport(p, b.Budget(p), lab=True)
            result = t.get(site + "/.git/HEAD")
            self.assertEqual(result.error, "IncompleteRead")
            self.assertFalse(b.git_head(result))

    def test_no_cookie_replay(self):
        with fixture() as (site, requests):
            p = policy(site)
            t = b.Transport(p, b.Budget(p), lab=True)
            p.interval_seconds = 0
            t.get(site + "/")
            t.get(site + "/app.js")
            self.assertTrue(all("Cookie" not in headers and "Authorization" not in headers for _, headers in requests))

    def test_total_timeout_slow_headers_and_body(self):
        for mode in ["slow_headers", "slow_body"]:
            with self.subTest(mode=mode), fixture(mode) as (site, _):
                p = policy(site, timeout_seconds=0.2)
                t = b.Transport(p, b.Budget(p), lab=True)
                start = time.monotonic()
                result = t.get(site + "/")
                self.assertLess(time.monotonic() - start, 1)
                self.assertTrue(result.error)
                self.assertFalse(result.usable)

    def test_tls_verification_is_not_disabled(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            key, cert = Path(td) / "key.pem", Path(td) / "cert.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                            "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            with fixture(tls=context) as (site, requests):
                p = policy(site)
                r = b.Transport(p, b.Budget(p), lab=True).get(site + "/")
                self.assertEqual(r.error, "SSLCertVerificationError")
                self.assertEqual(requests, [])

    def test_interrupt_retains_attempt_ledger(self):
        p = policy()
        t = b.Transport(p, b.Budget(p))
        with patch.object(b, "resolve", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            t.get("https://example.com/")
        self.assertEqual(t.budget.count, len(t.budget.events))
        self.assertEqual(t.budget.events[0]["error"], "Interrupted")

    def test_provider_host_allowlist(self):
        p = policy()
        t = b.Transport(p, b.Budget(p))
        with self.assertRaises(b.GuardError):
            t.get("https://crt.sh.evil.invalid/", provider=True)
        self.assertEqual(t.budget.count, 0)


class AssessmentTests(unittest.TestCase):
    def test_positive_fixture_has_four_distinct_git_events(self):
        report, requests = run_fixture()
        findings = [f for f in report["findings"] if f["rule"] == "git_head_exposure"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["state"], "verified_exposure")
        self.assertEqual(len(set(findings[0]["event_ids"])), 4)
        self.assertEqual(report["confirmed_vulnerabilities"], 0)
        self.assertEqual(report["requests_used"], len(requests))
        self.assertTrue(any(f["rule"] == "source_map" for f in report["findings"]))
        self.assertNotIn(TOKEN, json.dumps(report))
        self.assertNotIn("not-a-secret", json.dumps(report))
        self.assertFalse(any(path.startswith("/api") or path == "/delete" for path, _ in requests))

    def test_spa_and_generic_keyword_pages_do_not_confirm(self):
        report, _ = run_fixture("spa")
        self.assertFalse(any(f["state"] == "verified_exposure" for f in report["findings"]))
        self.assertFalse(any(f["state"] == "candidate" for f in report["findings"]))

    def test_git_looking_catchall_rejected(self):
        report, _ = run_fixture("catchall_git")
        self.assertFalse(any(f["rule"] == "git_head_exposure" for f in report["findings"]))
        self.assertTrue(any(c["status"] == "rejected" for c in report["coverage"]))

    def test_same_status_different_git_content_rejected(self):
        report, _ = run_fixture("unstable")
        self.assertFalse(any(f["rule"] == "git_head_exposure" for f in report["findings"]))

    def test_budget_partial_not_clean_bill_of_health(self):
        report, requests = run_fixture(max_requests=2)
        self.assertEqual(len(requests), 2)
        self.assertEqual(report["run_status"], "partial")
        self.assertTrue(any(c["status"] == "not_tested" for c in report["coverage"]))
        self.assertFalse(any(f["state"] == "verified_exposure" for f in report["findings"]))

    def test_429_and_503_stop_origin_immediately(self):
        for mode in ["rate_limit", "unavailable"]:
            with self.subTest(mode=mode):
                report, requests = run_fixture(mode)
                self.assertEqual(len(requests), 1)
                self.assertEqual(report["run_status"], "partial")
                self.assertTrue(report["circuit_breakers"])

    def test_full_exclusion_means_zero_requests(self):
        report, requests = run_fixture(excluded_paths=["/"])
        self.assertEqual(requests, [])
        self.assertEqual(report["requests_used"], 0)
        self.assertEqual(report["run_status"], "partial")

    def test_interrupt_is_reported_not_lost(self):
        p = policy()
        a = b.Assessment(p)
        with patch.object(b, "resolve", side_effect=KeyboardInterrupt):
            report = a.run()
        self.assertEqual(report["run_status"], "interrupted")
        self.assertEqual(report["coverage"][0]["status"], "inconclusive")
        self.assertEqual(report["requests_used"], len(report["events"]))

    def test_source_map_validation(self):
        for body in [b"<html>version 3</html>", b"{}", b'{"version":3,"sources":"a","mappings":""}', b"[]"]:
            with self.subTest(body=body):
                self.assertFalse(b.source_map(b.Response("https://example.com/a.map", 200, body=body)))

    def test_git_html_error_and_truncated_are_rejected(self):
        for result in [b.Response("https://example.com", 403, body=HEAD),
                       b.Response("https://example.com", 200, headers={"content-type": "text/html"}, body=HEAD),
                       b.Response("https://example.com", 200, body=HEAD, truncated=True)]:
            self.assertFalse(b.git_head(result))

    def test_challenge_response_cannot_support_exposure(self):
        result = b.Response("https://example.com/.git/HEAD", 200,
                            headers={"cf-mitigated": "challenge"}, body=HEAD)
        self.assertFalse(b.git_head(result))

    def test_provider_cve_stays_intelligence(self):
        p = policy("https://93.184.216.34")
        a = b.Assessment(p, intel=True)
        a.budget.events.append({"ip": "93.184.216.34", "url": p.origins[0], "audience": "target"})
        response = b.Response("https://internetdb.shodan.io/93.184.216.34", 200,
                              body=b'{"vulns":["CVE-2024-12345"]}', event_id="Etest")
        with patch.object(a.transport, "get", return_value=response):
            a.osint(p.origins[0])
        self.assertEqual(a.findings, [])
        self.assertEqual(a.leads[0]["kind"], "unverified_provider_cve")


class ReportAndImportTests(unittest.TestCase):
    def test_import_ignores_verified_flags_and_secrets(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            path = Path(td) / "input.jsonl"
            data = [{"matched-at": "https://example.com/a?token=VERYSECRET", "template-id": "a-test",
                     "verified": True, "info": {"severity": "critical"}, "extracted-results": [TOKEN]},
                    {"matched-at": "https://outside.invalid/"}, {"matched-at": "https://example.com/a?token=OTHER"}]
            path.write_text("\n".join(json.dumps(x) for x in data) + "\nnot-json\n")
            with patch.object(socket, "create_connection") as connect:
                report = b.import_results(path, "nuclei", policy())
            connect.assert_not_called()
            self.assertEqual(len(report["rejected"]), 2)
            self.assertTrue(all(r["state"] == "unverified_import" for r in report["records"]))
            self.assertNotIn("VERYSECRET", json.dumps(report))
            self.assertNotIn(TOKEN, json.dumps(report))
            self.assertNotIn("critical", json.dumps(report))

    def test_plain_url_and_subfinder_imports(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            path = Path(td) / "input.txt"
            path.write_text("https://example.com/a\nhttps://example.com/a\nhttps://sub.example.com/\n")
            result = b.import_results(path, "urls", policy())
            self.assertEqual(len(result["records"]), 1)
            self.assertEqual(len(result["rejected"]), 1)
            path.write_text('{"host":"example.com"}\n')
            self.assertEqual(len(b.import_results(path, "subfinder", policy())["records"]), 1)

    def test_report_integrity_permissions_and_safe_html(self):
        report, _ = run_fixture("spa")
        report["policy"]["authorization_ref"] = '<script>alert("x")</script>'
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            out = b.write_report(report, Path(td) / "report")
            self.assertTrue(b.verify_report(out))
            self.assertEqual((out.stat().st_mode & 0o777), 0o700)
            self.assertEqual(((out / "report.json").stat().st_mode & 0o777), 0o600)
            content = (out / "report.html").read_text()
            self.assertNotIn('<script>alert("x")</script>', content)
            self.assertIn("&lt;script&gt;", content)
            self.assertIn("default-src 'none'", content)
            with self.assertRaises(FileExistsError):
                b.write_report(report, out)
            (out / "report.md").write_text("changed")
            with self.assertRaises(b.GuardError):
                b.verify_report(out)

    def test_manifest_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            (Path(td) / "manifest.json").write_text('{"../secret":"abc"}')
            with self.assertRaises(b.GuardError):
                b.verify_report(td)

    def test_cli_auth_gate_runs_before_network(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            path = Path(td) / "policy.json"
            path.write_text(json.dumps(b.dataclasses.asdict(policy())))
            with patch.object(socket, "create_connection") as connect, contextlib.redirect_stderr(io.StringIO()):
                result = b.main(["scan", "--policy", str(path), "--out", str(Path(td) / "report")])
            self.assertEqual(result, 1)
            connect.assert_not_called()
            with patch.object(socket, "create_connection") as connect, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(b.main(["plan", "--policy", str(path)]), 0)
            connect.assert_not_called()

    def test_cli_automation_false_blocks_even_with_attestation(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            path = Path(td) / "policy.json"
            path.write_text(json.dumps(b.dataclasses.asdict(policy(automation_allowed=False))))
            with patch.object(socket, "create_connection") as connect, contextlib.redirect_stderr(io.StringIO()):
                result = b.main(["scan", "--policy", str(path), "--authorized", "--out", str(Path(td) / "report")])
            self.assertEqual(result, 1)
            connect.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
