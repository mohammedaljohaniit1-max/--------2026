#!/usr/bin/env python3
"""BURHAN: bounded, evidence-first external assessment. Python 3.11+, stdlib only."""
from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime as dt
import hashlib
import html
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from html.parser import HTMLParser
from urllib.parse import quote, unquote, urlencode, urljoin, urlsplit, urlunsplit

VERSION = "0.3.1"
BANNER = r"""
  +------------------------------------------------------+
  |   ____  _   _ ____  _   _    _    _   _               |
  |  | __ )| | | |  _ \| | | |  / \  | \ | |              |
  |  |  _ \| | | | |_) | |_| | / _ \ |  \| |              |
  |  | |_) | |_| |  _ <|  _  |/ ___ \| |\  |              |
  |  |____/ \___/|_| \_\_| |_/_/   \_\_| \_|              |
  |          EVIDENCE FIRST. CLAIMS SECOND.              |
  +------------------------------------------------------+
"""
LIMITATIONS = [
    "Point-in-time external assessment, not a complete penetration test or security warranty.",
    "No authentication, account creation, state-changing payloads, exploitation or WAF evasion.",
    "Authorization, business logic, blind injection and browser execution are not tested.",
    "GET can have side effects on poorly designed applications; obtain explicit approval.",
    "No automatically confirmed vulnerabilities. Verified exposure is a narrow technical fact, not proven business impact.",
    "No guarantee of zero false positives or false negatives; human review remains necessary.",
    "Response bodies are bounded and not persisted; hashing is integrity metadata, not a replayable packet capture.",
]
SENSITIVE = re.compile(r"(?i)(token|secret|password|passwd|api.?key|authorization|session|cookie)")
TOKEN_PATTERNS = {
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "stripe_secret_like": re.compile(r"\bsk_live_[A-Za-z0-9]{20,200}\b"),
    "private_key_marker": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def text_safe(value, limit=500):
    value = str(value)
    for pattern in TOKEN_PATTERNS.values():
        value = pattern.sub("[REDACTED]", value)
    return "".join(c for c in value if c in "\n\t" or ord(c) >= 32 and ord(c) != 127)[:limit]


class GuardError(ValueError):
    pass


class StopScan(RuntimeError):
    pass


def canonical(raw: str, *, queries=False) -> str:
    if not isinstance(raw, str) or len(raw) > 4096 or any(ord(c) <= 32 or ord(c) == 127 for c in raw):
        raise GuardError("invalid URL or control characters")
    if "\\" in raw:
        raise GuardError("backslashes are not accepted")
    try:
        u = urlsplit(raw)
        if u.scheme not in ("http", "https") or not u.hostname or u.username is not None or u.password is not None:
            raise GuardError("only explicit HTTP(S) URLs without credentials are allowed")
        host = u.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if "%" in host:
            raise GuardError("scoped IPv6 and escaped hostnames are not accepted")
        port = u.port or (443 if u.scheme == "https" else 80)
    except (ValueError, UnicodeError) as exc:
        raise GuardError("invalid URL authority") from exc
    path = u.path or "/"
    for _ in range(4):
        decoded = unquote(path, errors="strict")
        if decoded == path:
            break
        path = decoded
    if "%" in path or "\\" in path or any(ord(c) < 32 or ord(c) == 127 for c in path):
        raise GuardError("ambiguous encoded path")
    if any(p in (".", "..") for p in path.split("/")) or "//" in path:
        raise GuardError("ambiguous path segments")
    if u.query and not queries:
        raise GuardError("query-bearing URLs are inventoried only, not fetched")
    authority = f"[{host}]" if ":" in host else host
    if port != (443 if u.scheme == "https" else 80):
        authority += f":{port}"
    return urlunsplit((u.scheme, authority, quote(path, safe="/!$&'()*+,;=:@-._~"), u.query if queries else "", ""))


def origin(url):
    u = urlsplit(url)
    return f"{u.scheme}://{u.netloc}"


def safe_url(raw):
    """Do not export userinfo, query values, fragments, or token-shaped path material."""
    try:
        u = urlsplit(str(raw))
        host = u.hostname or "invalid"
        authority = f"[{host}]" if ":" in host else host
        if u.port:
            authority += f":{u.port}"
        return text_safe(urlunsplit((u.scheme, authority, u.path, "REDACTED" if u.query else "", "")), 1000)
    except ValueError:
        return "[invalid URL]"


@dataclasses.dataclass
class Policy:
    origins: list[str]
    authorization_ref: str
    expires_at: str
    automation_allowed: bool
    excluded_paths: list[str] = dataclasses.field(default_factory=list)
    max_requests: int = 40
    max_seconds: float = 180
    interval_seconds: float = 1.0
    timeout_seconds: float = 8
    max_body_bytes: int = 262144
    max_assets: int = 6

    @classmethod
    def load(cls, path):
        if Path(path).stat().st_size > 65536:
            raise GuardError("policy exceeds 64 KiB")
        data = json.loads(Path(path).read_text())
        if not isinstance(data, dict):
            raise GuardError("policy must be an object")
        fields = {f.name for f in dataclasses.fields(cls)}
        if data.keys() - fields:
            raise GuardError("unknown policy fields: " + ", ".join(sorted(data.keys() - fields)))
        try:
            obj = cls(**data)
        except TypeError as exc:
            raise GuardError("missing required policy fields") from exc
        obj.validate()
        return obj

    def validate(self):
        if not isinstance(self.origins, list) or not 1 <= len(self.origins) <= 10:
            raise GuardError("provide 1..10 exact origins; no wildcard scope")
        normalized = []
        for raw in self.origins:
            url = canonical(raw)
            if urlsplit(url).path != "/" or urlsplit(raw).fragment:
                raise GuardError("origins must not contain paths or fragments")
            normalized.append(origin(url))
        self.origins = sorted(set(normalized))
        if type(self.automation_allowed) is not bool:
            raise GuardError("automation_allowed must be boolean")
        if not isinstance(self.authorization_ref, str) or not self.authorization_ref.strip():
            raise GuardError("authorization_ref is required")
        if len(self.authorization_ref) > 200:
            raise GuardError("authorization_ref is too long")
        self.expiry()
        if not isinstance(self.excluded_paths, list) or len(self.excluded_paths) > 100:
            raise GuardError("invalid excluded_paths")
        for p in self.excluded_paths:
            if not isinstance(p, str) or not p.startswith("/") or "?" in p or "#" in p:
                raise GuardError("exclusions must be absolute path prefixes")
            canonical("https://scope.invalid" + p)
        ranges = {"max_requests": (1, 200), "max_seconds": (1, 1800),
                  "interval_seconds": (0.5, 30), "timeout_seconds": (0.2, 30),
                  "max_body_bytes": (1024, 1048576), "max_assets": (0, 20)}
        for key, (low, high) in ranges.items():
            value = getattr(self, key)
            if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
                raise GuardError(f"{key} must be in [{low}, {high}]")
        for key in ("max_requests", "max_body_bytes", "max_assets"):
            if type(getattr(self, key)) is not int:
                raise GuardError(f"{key} must be an integer")

    def expiry(self):
        try:
            d = dt.datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            if d.tzinfo is None:
                raise ValueError()
            return d
        except (ValueError, AttributeError) as exc:
            raise GuardError("expires_at must be an ISO timestamp with timezone") from exc

    def allowed(self, raw):
        url = canonical(raw)
        if origin(url) not in self.origins:
            raise GuardError("origin is outside explicit scope")
        path = unquote(urlsplit(url).path)
        for p in self.excluded_paths:
            p = unquote(urlsplit(canonical("https://scope.invalid" + p)).path).rstrip("/")
            if not p or path == p or path.startswith(p + "/"):
                raise GuardError("excluded path")
        if re.search(r"(?i)(?:^|[/_.-])(logout|delete|remove|destroy|purchase|checkout|unsubscribe|reset|signout)(?:$|[/_.-])", path):
            raise GuardError("potential state-changing route is not fetched")
        return url


class Budget:
    def __init__(self, policy):
        self.policy = policy
        self.start = time.monotonic()
        self.deadline = self.start + policy.max_seconds
        self.count = 0
        self.next_at = 0.0
        self.blocked = {}
        self.errors = collections.Counter()
        self.events = []

    def remaining(self):
        return min(self.deadline - time.monotonic(), (self.policy.expiry() - utcnow()).total_seconds())

    def check(self):
        if self.remaining() <= 0:
            raise StopScan("time budget or authorization expired")
        if self.count >= self.policy.max_requests:
            raise StopScan("request budget exhausted")

    def acquire(self, site):
        self.check()
        if site in self.blocked:
            raise GuardError("origin circuit open: " + self.blocked[site])
        delay = max(0, self.next_at - time.monotonic())
        if delay >= self.remaining():
            raise StopScan("time budget exhausted before next permitted request")
        if delay:
            time.sleep(delay)
        self.check()
        self.count += 1
        self.next_at = time.monotonic() + self.policy.interval_seconds

    def observe(self, site, result):
        if result.status == 429 or result.status == 503:
            self.blocked[site] = f"HTTP {result.status}; no automatic retry"
        elif result.error or result.status >= 500:
            self.errors[site] += 1
            if self.errors[site] >= 2:
                self.blocked[site] = "two consecutive transport/server failures"
        else:
            self.errors[site] = 0
        if result.headers.get("cf-mitigated", "").lower() == "challenge":
            self.blocked[site] = "explicit challenge response; no bypass attempted"


@dataclasses.dataclass
class Response:
    url: str
    status: int = 0
    headers: dict = dataclasses.field(default_factory=dict)
    body: bytes = b""
    truncated: bool = False
    error: str = ""
    event_id: str = ""

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")

    @property
    def usable(self):
        return (not self.error and not self.truncated and self.status == 200
                and self.headers.get("content-encoding", "identity").lower() in ("", "identity")
                and self.headers.get("cf-mitigated", "").lower() != "challenge")


def resolve(host, port, timeout):
    """Bound OS DNS in a child process; connect only to one returned literal IP."""
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    script = "import socket,json,sys; print(json.dumps(sorted({x[4][0] for x in socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)})))"
    try:
        result = subprocess.run([sys.executable, "-I", "-c", script, host, str(port)],
                                capture_output=True, timeout=timeout, check=True)
        ips = json.loads(result.stdout)
        if not ips:
            raise GuardError("DNS returned no addresses")
        return ips
    except (subprocess.SubprocessError, ValueError) as exc:
        raise GuardError("DNS resolution failed or timed out") from exc


class Transport:
    def __init__(self, policy, budget, *, lab=False):
        self.policy, self.budget, self.lab = policy, budget, lab
        if lab:
            for site in policy.origins:
                try:
                    ok = ipaddress.ip_address(urlsplit(site).hostname).is_loopback
                except ValueError:
                    ok = False
                if not ok:
                    raise GuardError("lab mode requires exclusively literal loopback origins")

    def get(self, raw, *, provider=False):
        if provider:
            if self.lab:
                raise GuardError("OSINT is disabled in loopback lab mode")
            url = canonical(raw, queries=True)
            if origin(url) not in ("https://crt.sh", "https://internetdb.shodan.io", "https://web.archive.org", "https://api.certspotter.com"):
                raise GuardError("provider is not allowlisted")
        else:
            url = self.policy.allowed(raw)
        site = origin(url)
        self.budget.acquire(site)
        r = Response(url=url, event_id=f"E{self.budget.count:04d}")
        started = time.monotonic()
        end = min(started + self.policy.timeout_seconds, started + self.budget.remaining())
        conn = wire = timer = None
        ip = None
        interrupted = False
        timed_out = threading.Event()

        def expire_socket():
            timed_out.set()
            if wire is not None:
                try:
                    wire.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        try:
            u = urlsplit(url)
            port = u.port or (443 if u.scheme == "https" else 80)
            ips = resolve(u.hostname, port, max(0.01, min(3, end - time.monotonic())))
            for address in ips:
                addr = ipaddress.ip_address(address)
                if self.lab and not addr.is_loopback or not self.lab and not addr.is_global:
                    raise GuardError("DNS/IP policy rejected a non-public or non-loopback address")
            ip = ips[0]
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            # No proxy inheritance, redirects, cookie jar, second DNS lookup or implicit retries.
            wire = socket.create_connection((ip, port), timeout=remaining)
            timer = threading.Timer(max(0.001, end - time.monotonic()), expire_socket)
            timer.daemon = True
            timer.start()
            if u.scheme == "https":
                wire.settimeout(max(0.01, end - time.monotonic()))
                wire = ssl.create_default_context().wrap_socket(wire, server_hostname=u.hostname)
            conn = http.client.HTTPConnection(u.hostname, port, timeout=remaining)
            conn.sock = wire
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
            wire.settimeout(max(0.01, end - time.monotonic()))
            conn.request("GET", path, headers={"Host": u.netloc, "User-Agent": f"BURHAN/{VERSION} authorized-assessment", "Accept": "*/*", "Accept-Encoding": "identity", "Connection": "close"})
            res = conn.getresponse()
            r.status = res.status
            # Keep headers only in memory. Duplicate headers are joined, never silently dropped.
            for k, v in res.getheaders():
                k = k.lower()
                r.headers[k] = r.headers[k] + "\n" + v if k in r.headers else v
            data = bytearray()
            while len(data) <= self.policy.max_body_bytes:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                wire.settimeout(remaining)
                chunk = res.read1(min(16384, self.policy.max_body_bytes + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                # HTTP/1.0 and Connection: close may close the final socket file
                # as soon as Content-Length bytes are consumed. Do not touch it again.
                if res.isclosed():
                    break
            r.truncated = len(data) > self.policy.max_body_bytes
            r.body = bytes(data[:self.policy.max_body_bytes])
            if not r.truncated and res.length not in (None, 0):
                raise http.client.IncompleteRead(b"", res.length)
            if timed_out.is_set() or time.monotonic() >= end:
                raise TimeoutError()
        except KeyboardInterrupt:
            interrupted = True
            r.error = "Interrupted"
        except (OSError, http.client.HTTPException, GuardError, ValueError) as exc:
            # Exception text can contain credentials or untrusted response lines: export category only.
            r.error = type(exc).__name__
        finally:
            if timer:
                timer.cancel()
                timer.join()
            if conn:
                conn.close()
            if wire:
                wire.close()
        self.budget.observe(site, r)
        self.budget.events.append({"id": r.event_id, "url": safe_url(url), "audience": "provider" if provider else "target",
                                   "at": utcnow().isoformat(), "status": r.status, "error": r.error,
                                   "ip": ip, "elapsed_ms": round((time.monotonic() - started) * 1000),
                                   "bytes_retained": len(r.body), "truncated": r.truncated,
                                   "body_sha256": sha(r.body), "hash_scope": "retained body bytes, not full response",
                                   "content_type": text_safe(r.headers.get("content-type", ""), 100)})
        if interrupted:
            raise KeyboardInterrupt()
        return r


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.title = ""
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "title":
            self.in_title = True
        for key in ("href", "src"):
            if attrs.get(key):
                self.links.append((tag, attrs[key]))

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data[:200]


def git_head(r):
    if not r.usable or "html" in r.headers.get("content-type", "").lower():
        return False
    return bool(re.fullmatch(rb"(?:ref: refs/heads/[A-Za-z0-9_./-]{1,180}|[0-9a-f]{40}|[0-9a-f]{64})\r?\n?", r.body))


def source_map(r):
    if not r.usable:
        return False
    try:
        data = json.loads(r.body)
        return (isinstance(data, dict) and data.get("version") == 3 and isinstance(data.get("sources"), list)
                and bool(data["sources"]) and all(isinstance(s, str) for s in data["sources"])
                and isinstance(data.get("mappings"), str))
    except (ValueError, UnicodeError, RecursionError):
        return False


def entropy(token):
    counts = collections.Counter(token)
    return -sum((n / len(token)) * math.log2(n / len(token)) for n in counts.values()) if token else 0


class Assessment:
    def __init__(self, policy, *, lab=False, intel=False):
        self.policy = policy
        self.budget = Budget(policy)
        self.transport = Transport(policy, self.budget, lab=lab)
        self.intel = intel
        self.findings, self.coverage, self.leads = [], [], []
        self.keys = set()
        self.started = utcnow().isoformat()
        self.state = "completed"
        self.stop_reason = "planned checks completed"

    def add(self, rule, url, state, title, evidence, events, remediation, impact):
        key = (rule, safe_url(url))
        if key in self.keys:
            return
        self.keys.add(key)
        self.findings.append({"id": "B-" + sha((rule + safe_url(url)).encode())[:12], "rule": rule,
                              "url": safe_url(url), "state": state, "title": title,
                              "severity": "unrated" if state != "observation" else "informational",
                              "evidence": evidence, "event_ids": events,
                              "impact": impact, "remediation": remediation,
                              "review_required": True})

    def lead(self, kind, raw, source):
        item = {"kind": kind, "value": safe_url(raw), "source": safe_url(source)}
        if len(self.leads) < 500 and item not in self.leads:
            self.leads.append(item)

    def request(self, url, check):
        row = {"check": check, "url": safe_url(url), "status": "pending", "reason": "", "event_ids": []}
        self.coverage.append(row)
        try:
            r = self.transport.get(url)
        except GuardError as exc:
            row.update(status="skipped", reason=str(exc))
            return None
        except StopScan as exc:
            row.update(status="not_tested", reason=str(exc))
            raise
        except KeyboardInterrupt:
            row.update(status="inconclusive", reason="operator interrupted")
            if self.budget.events and self.budget.events[-1]["url"] == safe_url(url):
                row["event_ids"] = [self.budget.events[-1]["id"]]
            raise
        row["event_ids"] = [r.event_id]
        row["status"] = "inconclusive" if r.error or r.truncated or r.status in (401, 403, 429) or r.status >= 500 else "observed"
        row["reason"] = r.error or ("body truncated" if r.truncated else f"HTTP {r.status}")
        if 300 <= r.status < 400:
            row.update(status="inconclusive", reason="redirect not followed; add destination as explicit scope if authorized")
            location = r.headers.get("location", "")
            if location:
                self.lead("redirect_not_followed", urljoin(url, location), url)
        return r

    def posture(self, r):
        if not r or not r.usable:
            return
        h = r.headers
        missing = []
        if r.url.startswith("https:") and "strict-transport-security" not in h:
            missing.append("Strict-Transport-Security")
        if "x-content-type-options" not in h:
            missing.append("X-Content-Type-Options")
        if missing:
            self.add("response_headers", r.url, "observation", "Response hardening headers absent",
                     {"missing_on_this_response": missing}, [r.event_id],
                     "Assess deployment requirements and configure appropriate response headers.",
                     "No exploit or business impact demonstrated. Header absence alone is not a confirmed vulnerability.")
        for i, cookie in enumerate(h.get("set-cookie", "").splitlines()):
            pieces = cookie.split(";")
            attrs = {x.strip().split("=", 1)[0].lower() for x in pieces[1:]}
            flags = sorted({"secure", "httponly", "samesite"} - attrs)
            if flags:
                self.add(f"cookie_attributes_{i}", r.url, "observation", "Cookie attributes require contextual review",
                         {"cookie_index": i, "missing_attributes": flags, "cookie_values": "not stored"}, [r.event_id],
                         "Identify the cookie's purpose before changing Secure, HttpOnly and SameSite attributes.",
                         "Cookie purpose and sensitivity are unknown; client-readable cookies may be intentional.")

    def js_analysis(self, r):
        if not r or not r.usable:
            return
        for kind, pattern in TOKEN_PATTERNS.items():
            found = pattern.search(r.text)
            if found and (kind == "private_key_marker" or entropy(found.group()) >= 3.5):
                self.add("js_" + kind, r.url, "candidate", "Credential-shaped material in public JavaScript",
                         {"pattern": kind, "matched_value": "REDACTED; not persisted", "line": r.text[:found.start()].count("\n") + 1},
                         [r.event_id], "Have the owner validate purpose and sensitivity; rotate and remove only if genuinely secret.",
                         "Pattern/entropy matching does not prove a working credential. No provider validation or credential use performed.")
        for match in re.finditer(r'''["'`]((?:https?://|/)[^\s"'`<>]{1,300})["'`]''', r.text):
            self.lead("javascript_reference_not_fetched", urljoin(r.url, match.group(1)), r.url)
        match = re.search(r"(?m)^\s*//[#@]\s*sourceMappingURL=([^\s]+)", r.text)
        if match and not match.group(1).startswith("data:"):
            self.lead("source_map_reference", urljoin(r.url, match.group(1)), r.url)

    def git_check(self, site):
        url = site + "/.git/HEAD"
        first = self.request(url, "git_head_signature")
        if not first or not git_head(first):
            return
        # Two independent random controls, same parent/extension, plus exact signature reproduction.
        controls = [self.request(site + "/.git/" + secrets.token_hex(12), "git_negative_control") for _ in range(2)]
        second = self.request(url, "git_head_reproduction")
        if any(r is None or r.error or r.truncated or r.status not in (200, 404, 410) for r in controls) or not second:
            return
        valid = (git_head(second) and first.body == second.body and all(not git_head(r) and r.body != first.body for r in controls))
        if valid:
            self.add("git_head_exposure", url, "verified_exposure", "Git HEAD metadata publicly retrievable",
                     {"signature": "strict Git HEAD grammar", "same_bytes_on_repeat": True,
                      "independent_negative_controls": 2, "repository_downloaded": False},
                     [first.event_id, *(r.event_id for r in controls), second.event_id],
                     "Remove repository metadata from deployment artifacts and deny web access to .git paths; inspect deployment history.",
                     "Only HEAD metadata availability was established. Repository/source access, secrets and downstream impact were not tested.")
        else:
            self.coverage.append({"check": "git_verdict", "url": safe_url(url), "status": "rejected",
                                  "reason": "signature did not reproduce or negative control returned the same content", "event_ids": []})

    def assets(self, r):
        if not r or not r.usable or "html" not in r.headers.get("content-type", "").lower():
            return
        parser = LinkParser()
        parser.feed(r.text)
        queue = []
        for tag, raw in parser.links[:300]:
            url = urljoin(r.url, raw)
            self.lead("html_reference_not_fetched", url, r.url)
            if tag == "script" and urlsplit(url).path.lower().endswith(".js"):
                if url not in queue:
                    queue.append(url)
        for url in queue[:self.policy.max_assets]:
            js = self.request(url, "linked_javascript")
            self.js_analysis(js)
        # Linked source maps only; no guessed .map expansion, no source-content export.
        maps = [x for x in self.leads if x["kind"] == "source_map_reference"]
        for item in maps[:self.policy.max_assets]:
            rmap = self.request(item["value"], "linked_source_map")
            if rmap and source_map(rmap):
                self.add("source_map", rmap.url, "candidate", "Structured source map publicly available",
                         {"version": 3, "source_contents": "not persisted"}, [rmap.event_id],
                         "Review whether publishing original client source is intentional; exclude sensitive build inputs.",
                         "A public source map is often intentional and does not establish disclosure of confidential information.")

    def osint(self, site):
        host = urlsplit(site).hostname
        urls = []
        try:
            ipaddress.ip_address(host)
        except ValueError:
            urls.append(("certificate_transparency", "https://crt.sh/?" + urlencode({"q": host, "output": "json"})))
        ips = sorted({e["ip"] for e in self.budget.events if e["audience"] == "target" and origin(e["url"]) == site and e["ip"]})
        if ips:
            urls.append(("internetdb", "https://internetdb.shodan.io/" + ips[0]))
        for kind, url in urls:
            row = {"check": kind, "url": safe_url(url), "status": "pending", "reason": "", "event_ids": []}
            self.coverage.append(row)
            try:
                r = self.transport.get(url, provider=True)
            except GuardError as exc:
                row.update(status="skipped", reason=str(exc))
                continue
            except StopScan as exc:
                row.update(status="not_tested", reason=str(exc))
                raise
            except KeyboardInterrupt:
                row.update(status="inconclusive", reason="operator interrupted")
                if self.budget.events and self.budget.events[-1]["url"] == safe_url(url):
                    row["event_ids"] = [self.budget.events[-1]["id"]]
                raise
            row["event_ids"] = [r.event_id]
            row.update(status="inconclusive", reason=r.error or f"HTTP {r.status}")
            if not r.usable:
                continue
            try:
                data = json.loads(r.body)
                if kind == "internetdb" and isinstance(data, dict):
                    for cve in data.get("vulns", [])[:100]:
                        if isinstance(cve, str) and re.fullmatch(r"CVE-\d{4}-\d{4,9}", cve):
                            self.leads.append({"kind": "unverified_provider_cve", "value": cve,
                                               "source": safe_url(url), "note": "May be stale or a shared/CDN IP. Not evidence of target vulnerability."})
                elif kind == "certificate_transparency" and isinstance(data, list):
                    for entry in data[:100]:
                        if not isinstance(entry, dict):
                            continue
                        for name in str(entry.get("name_value", "")).splitlines()[:20]:
                            if re.fullmatch(r"[a-zA-Z0-9.*-]{1,253}", name):
                                self.lead("ct_hostname_not_authorized", "https://" + name, url)
                else:
                    raise ValueError()
                row.update(status="observed", reason="provider data is intelligence only; scope not expanded")
            except (ValueError, TypeError, RecursionError):
                row.update(status="inconclusive", reason="invalid provider schema")

    def run(self):
        try:
            for site in self.policy.origins:
                root = self.request(site + "/", "root_response")
                self.posture(root)
                self.git_check(site)
                for path in ("/robots.txt", "/.well-known/security.txt", "/sitemap.xml"):
                    self.request(site + path, "public_metadata")
                self.assets(root)
                if self.intel:
                    self.osint(site)
        except StopScan as exc:
            self.state, self.stop_reason = "partial", str(exc)
        except KeyboardInterrupt:
            self.state, self.stop_reason = "interrupted", "operator interrupted; partial results preserved"
        if self.budget.blocked or any(c["status"] in ("inconclusive", "skipped", "not_tested") for c in self.coverage):
            if self.state == "completed":
                self.state, self.stop_reason = "partial", "one or more checks were blocked, skipped or inconclusive"
        return self.report()

    def report(self):
        return {"schema_version": 1, "tool": "BURHAN", "version": VERSION,
                "started_at": self.started, "finished_at": utcnow().isoformat(),
                "run_status": self.state, "stop_reason": self.stop_reason,
                "policy": dataclasses.asdict(self.policy), "third_party_intel_enabled": self.intel,
                "requests_used": self.budget.count, "confirmed_vulnerabilities": 0,
                "classification_note": "No automated vulnerability confirmation. Verified exposure is separate from demonstrated security impact.",
                "findings": self.findings, "coverage": self.coverage, "leads": self.leads,
                "events": self.budget.events, "circuit_breakers": self.budget.blocked,
                "limitations": LIMITATIONS,
                "unexecuted_scope_note": "Coverage lists attempted checks only. All omitted checks/origins are untested, never passed."}


def import_results(path, format_name, policy):
    """Offline import. External severity/verified flags are never trusted."""
    file = Path(path)
    if file.stat().st_size > 5 * 1024 * 1024:
        raise GuardError("import exceeds 5 MiB")
    rows, errors = [], []
    for number, line in enumerate(file.read_text().splitlines(), 1):
        if number > 10000:
            errors.append({"line": number, "reason": "10,000 line cap"})
            break
        if not line.strip():
            continue
        try:
            if len(line) > 65536:
                raise ValueError()
            data = {"url": line.strip()} if format_name == "urls" else json.loads(line)
            if not isinstance(data, dict):
                raise ValueError()
            raw = data.get("matched-at") or data.get("url") or data.get("host")
            if not isinstance(raw, str):
                raise ValueError()
            if "://" not in raw:
                raw = "https://" + raw
            clean = canonical(raw, queries=True)
            policy.allowed(urlunsplit((*urlsplit(clean)[:3], "", "")))
            identifier = data.get("template-id", format_name)
            # Never echo external free text, extracted results, headers, request or response blobs.
            identifier = identifier if isinstance(identifier, str) and re.fullmatch(r"[a-zA-Z0-9_.-]{1,100}", identifier) else "external"
            row = {"source_line": number, "url": safe_url(clean), "rule": identifier,
                   "state": "unverified_import", "review_required": True}
            if not any(x["url"] == row["url"] and x["rule"] == row["rule"] for x in rows):
                rows.append(row)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            errors.append({"line": number, "reason": "invalid or out-of-scope input"})
    return {"schema_version": 1, "tool": "BURHAN", "kind": "offline_import", "format": format_name,
            "source_sha256": sha(file.read_bytes()), "records": rows, "rejected": errors,
            "network_requests": 0, "note": "Imported detections are unverified; external flags and severity were ignored."}


def private_write(path, content):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)


def render_html(report):
    counts = collections.Counter(x["state"] for x in report["findings"])
    def esc(x):
        return html.escape(str(x))
    cards = "".join(f'<article><span class="badge">{esc(f["state"])}</span><h3>{esc(f["title"])}</h3><p class="url">{esc(f["url"])}</p><p>{esc(f["impact"])}</p><details><summary>Evidence & remediation</summary><pre>{esc(json.dumps(f["evidence"], ensure_ascii=False, indent=2))}</pre><p>Events: {esc(", ".join(f["event_ids"]))}</p><p>{esc(f["remediation"])}</p></details></article>' for f in report["findings"])
    rows = "".join(f'<tr><td>{esc(c["check"])}</td><td class="url">{esc(c["url"])}</td><td>{esc(c["status"])}</td><td>{esc(c["reason"])}</td></tr>' for c in report["coverage"])
    limits = "".join(f"<li>{esc(x)}</li>" for x in report["limitations"])
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>BURHAN | Evidence report</title><style>
:root{{color-scheme:dark;--bg:#0a111b;--panel:#111e2c;--line:#27394d;--muted:#a5b5c8;--accent:#63dfbd}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:#eef4fa;font:15px/1.65 system-ui,sans-serif}}main{{max-width:1150px;margin:auto;padding:40px 24px}}nav{{display:flex;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:20px;gap:20px}}.brand{{font-weight:800;letter-spacing:4px;color:var(--accent)}}.muted,.url{{color:var(--muted)}}h1{{font-size:clamp(32px,5vw,54px);line-height:1.1;margin:36px 0 12px}}.eyebrow{{color:var(--accent);text-transform:uppercase;letter-spacing:2px;font-size:12px}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:28px 0}}.stat,article{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:22px}}.stat strong{{display:block;font-size:34px}}.stat span{{font-size:12px;color:var(--muted)}}.notice{{border-left:3px solid var(--accent);padding:12px 20px;background:#13242b}}article{{margin:14px 0}}.badge{{font:11px ui-monospace,monospace;background:#203744;color:var(--accent);padding:4px 9px;border-radius:5px}}h3{{margin:12px 0 4px}}.url{{overflow-wrap:anywhere;font-family:ui-monospace,monospace;font-size:12px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}}summary{{cursor:pointer;color:var(--accent)}}.table{{overflow:auto}}table{{border-collapse:collapse;width:100%;font-size:12px}}td,th{{border-bottom:1px solid var(--line);padding:12px;text-align:left;vertical-align:top}}footer{{margin-top:40px;border-top:1px solid var(--line);padding-top:20px;color:var(--muted)}}@media(max-width:650px){{.stats{{grid-template-columns:repeat(2,1fr)}}main{{padding:24px 16px}}}}@media print{{:root{{color-scheme:light}}body{{background:white;color:black}}article,.stat{{background:white;border-color:#ccc}}.url,.muted,.stat span{{color:#444}}.notice{{background:#eee}}details{{display:block}}}}
</style></head><body><main><nav><div class="brand">BURHAN <span lang="ar">| بُرهان</span></div><span class="muted">EXTERNAL ASSESSMENT / {esc(report['version'])}</span></nav><p class="eyebrow">Evidence first. Claims second.</p><h1>Clarity, not a bigger<br>pile of alerts.</h1><p class="muted">{esc(report['started_at'])} / {esc(report['policy']['authorization_ref'])}</p><div class="stats"><div class="stat"><strong>{report['confirmed_vulnerabilities']}</strong><span>CONFIRMED VULNERABILITIES</span></div><div class="stat"><strong>{counts['verified_exposure']}</strong><span>VERIFIED EXPOSURES</span></div><div class="stat"><strong>{counts['candidate']}</strong><span>CANDIDATES TO REVIEW</span></div><div class="stat"><strong>{report['requests_used']}</strong><span>REQUEST ATTEMPTS / {report['policy']['max_requests']}</span></div></div><div class="notice"><strong>Run status: {esc(report['run_status'])}</strong><br>{esc(report['stop_reason'])}<br>Zero confirmed findings does not mean the target is secure.</div><h2>Evidence & observations</h2>{cards or '<p>No findings recorded. Review coverage and limitations before drawing conclusions.</p>'}<h2>Scope</h2><pre>{esc(json.dumps(report['policy'], ensure_ascii=False, indent=2))}</pre><h2>Coverage ledger</h2><p class="muted">Observed means a response was collected, not that a security test passed. Omitted checks are untested.</p><div class="table"><table><thead><tr><th>Check</th><th>URL</th><th>State</th><th>Reason</th></tr></thead><tbody>{rows}</tbody></table></div><h2>Limits of this assessment</h2><ul>{limits}</ul><footer>BURHAN / Confidential assessment material. Review before sharing. No third-party assets, scripts, fonts or telemetry.</footer></main></body></html>'''


def write_report(report, directory):
    out = Path(directory)
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    private_write(out / "report.json", json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    private_write(out / "report.html", render_html(report))
    lines = ["# BURHAN | External assessment", "", f"Status: {report['run_status']} — {report['stop_reason']}",
             f"Request attempts: {report['requests_used']}", "", "No automatically confirmed vulnerabilities. Verified exposures and candidates require impact review.",
             "", "## Findings"]
    for f in report["findings"]:
        lines.extend(["", f"### {f['id']} — {f['title']}", f"State: {f['state']}",
                      f"URL: `{f['url'].replace('`', '%60')}`", f"Impact: {f['impact']}",
                      f"Remediation: {f['remediation']}", f"Events: {', '.join(f['event_ids'])}",
                      "Evidence: " + json.dumps(f["evidence"], ensure_ascii=False)])
    lines.extend(["", "## Scope and coverage", "See report.json for the exact policy, evidence events and per-check coverage ledger.",
                  "", "## Limitations", *["- " + x for x in report["limitations"]]])
    private_write(out / "report.md", "\n".join(lines) + "\n")
    manifest = {name: sha((out / name).read_bytes()) for name in ("report.json", "report.html", "report.md")}
    private_write(out / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    return out


def verify_report(directory):
    out = Path(directory)
    manifest = json.loads((out / "manifest.json").read_text())
    names = {"report.json", "report.html", "report.md"}
    if not isinstance(manifest, dict) or set(manifest) != names:
        raise GuardError("manifest must list exactly the three report artifacts")
    for name in names:
        path = out / name
        if path.is_symlink() or sha(path.read_bytes()) != manifest[name]:
            raise GuardError("artifact integrity mismatch: " + name)
    return True


def filesystem_preflight(root=None):
    """Test disposable files inside the installation; do not chmod existing files."""
    root = Path(root if root is not None else Path(__file__).parent).resolve(strict=True)
    if not root.is_dir():
        raise GuardError("installation path must be a directory")
    if re.match(r"^/mnt/[a-zA-Z](?:/|$)", str(root)):
        raise GuardError("Windows-mounted installation path detected. Clone under your Linux home (cd ~), not /mnt/c. Do not use sudo git or chmod 777 to bypass Windows ACLs.")
    try:
        with tempfile.TemporaryDirectory(prefix=".burhan-preflight-", dir=root) as temporary:
            work = Path(temporary)
            work.chmod(0o700)
            if work.stat().st_mode & 0o777 != 0o700:
                raise GuardError("filesystem does not preserve private directory permissions")
            probe = work / "private-probe"
            private_write(probe, "disposable filesystem check\n")
            probe.chmod(0o600)
            if probe.stat().st_mode & 0o777 != 0o600:
                raise GuardError("filesystem does not preserve private file permissions")
            moved = work / "renamed-probe"
            probe.replace(moved)
            link = work / "link-probe"
            link.symlink_to(moved.name)
            if link.read_text() != "disposable filesystem check\n":
                raise GuardError("filesystem symlink/rename check failed")
            executable = work / "exec-probe"
            private_write(executable, "#!/bin/sh\nprintf 'BURHAN_PROBE_OK'\n")
            executable.chmod(0o700)
            result = subprocess.run([str(executable)], capture_output=True, timeout=5, check=True)
            if result.stdout != b"BURHAN_PROBE_OK":
                raise GuardError("filesystem executable check failed")
    except (OSError, subprocess.SubprocessError) as exc:
        raise GuardError("filesystem preflight failed (" + type(exc).__name__ + "). Use a writable Linux filesystem under your home supporting chmod, symlinks and execution. No existing file permissions were changed.") from exc
    return {"installation_directory": str(root), "filesystem_probe": "passed",
            "checked": ["write", "private modes", "rename", "symlink", "execute"],
            "network_requests": 0, "temporary_files_removed": True}


def doctor():
    tools = {name: bool(shutil.which(name)) for name in ("subfinder", "httpx", "nuclei", "katana", "nrich")}
    return {"python": sys.version.split()[0], "minimum_python": "3.11", "openssl": ssl.OPENSSL_VERSION,
            "dependencies": "Python standard library only", "optional_tools_present": tools,
            "note": "Presence is not capability verification. External tools are not launched; use offline import.",
            "live_dns_checked": False, "live_connectivity_checked": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="BURHAN — evidence-first, explicitly authorized external assessment")
    parser.add_argument("--version", action="version", version=f"BURHAN {VERSION}")
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("doctor", help="offline runtime and optional tool inventory")
    subs.add_parser("preflight", help="test installation filesystem using disposable local files; no network")
    from burhan_osint import add_parser, execute as execute_osint
    from burhan_programs import add_parser as add_programs_parser, execute as execute_programs
    add_parser(subs)
    add_programs_parser(subs)
    plan = subs.add_parser("plan", help="validate policy and show request bounds without network traffic")
    plan.add_argument("--policy", required=True)
    scan = subs.add_parser("scan", help="run bounded unauthenticated checks")
    scan.add_argument("--policy", required=True)
    scan.add_argument("--authorized", action="store_true", help="attest that you have explicit authorization for automated checks")
    scan.add_argument("--share-intel", action="store_true", help="explicitly disclose target host/IP to crt.sh and InternetDB")
    scan.add_argument("--lab-loopback-only", action="store_true")
    scan.add_argument("--out", required=True, help="new directory; existing directories are never overwritten")
    imp = subs.add_parser("import", help="offline import; external detections remain unverified")
    imp.add_argument("--policy", required=True)
    imp.add_argument("--format", choices=["nuclei", "httpx", "subfinder", "urls"], required=True)
    imp.add_argument("--input", required=True)
    imp.add_argument("--out", required=True, help="new JSON file")
    verify = subs.add_parser("verify", help="verify report hashes, not authenticity or finding validity")
    verify.add_argument("directory")
    args = parser.parse_args(argv)
    if sys.stdout.isatty():
        print(BANNER)
    try:
        if args.command == "preflight":
            print(json.dumps(filesystem_preflight(), indent=2))
        elif args.command == "programs":
            return execute_programs(args)
        elif args.command == "osint":
            return execute_osint(args)
        elif args.command == "doctor":
            print(json.dumps(doctor(), indent=2))
        elif args.command == "verify":
            verify_report(args.directory)
            print("Artifact hashes match. This is not a digital signature or proof of finding validity.")
        else:
            policy = Policy.load(args.policy)
            if args.command == "plan":
                print(json.dumps({"policy": dataclasses.asdict(policy), "network_requests": 0,
                                  "authorization_current": policy.expiry() > utcnow(),
                                  "checks": ["root response", "Git HEAD + conditional repeat/controls", "robots/security.txt/sitemap metadata", "linked JavaScript and source maps"],
                                  "maximum_target_request_attempts": min(policy.max_requests, len(policy.origins) * (8 + 2 * policy.max_assets)),
                                  "osint": "optional, at most two provider lookups per origin, consuming the same global budget",
                                  "no_automatic_redirects_or_scope_expansion": True}, indent=2))
            elif args.command == "import":
                data = import_results(args.input, args.format, policy)
                private_write(Path(args.out), json.dumps(data, ensure_ascii=False, indent=2) + "\n")
                print(f"Imported {len(data['records'])} unverified records; rejected {len(data['rejected'])}; network requests: 0")
            elif args.command == "scan":
                if not args.authorized or not policy.automation_allowed:
                    raise GuardError("scan requires --authorized AND automation_allowed=true in the engagement policy")
                if policy.expiry() <= utcnow():
                    raise GuardError("authorization expired")
                if Path(args.out).exists():
                    raise GuardError("output directory already exists; select a new run directory")
                if args.share_intel and args.lab_loopback_only:
                    raise GuardError("third-party intelligence is not available in lab mode")
                # Fail before making requests if report creation is impossible.
                parent = Path(args.out).absolute().parent
                if not parent.is_dir() or not os.access(parent, os.W_OK):
                    raise GuardError("output parent directory must already exist and be writable")
                assessment = Assessment(policy, lab=args.lab_loopback_only, intel=args.share_intel)
                report = assessment.run()
                out = write_report(report, args.out)
                print(f"BURHAN {VERSION} | {report['run_status']} | {report['requests_used']}/{policy.max_requests} request attempts")
                print(f"Findings: {dict(collections.Counter(f['state'] for f in report['findings']))}")
                print(f"Report: {out / 'report.html'}")
                return 0 if report["run_status"] == "completed" else 2
    except (GuardError, OSError, ValueError, TypeError, RecursionError) as exc:
        print("BURHAN error: " + text_safe(str(exc)), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    # Keep exception classes and transport shared with optional CLI modules.
    sys.modules["burhan"] = sys.modules[__name__]
    raise SystemExit(main())
