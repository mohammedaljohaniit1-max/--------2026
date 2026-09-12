"""Provider-only domain intelligence and local, consented identifier exposure audits.

No target requests, no person search, no private contact-book services. Provider
observations are facts about source records, not proof of ownership or weakness.
"""
from __future__ import annotations

import datetime as dt
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import unicodedata
from urllib.parse import urlencode, urlsplit

import burhan as b

PROVIDERS = {
    "crtsh": ("certificate_transparency", "https://crt.sh"),
    "wayback": ("web_archive", "https://web.archive.org"),
    "certspotter": ("certificate_transparency", "https://api.certspotter.com"),
}


def domain_name(raw):
    if not isinstance(raw, str) or not raw or len(raw) > 253:
        raise b.GuardError("provide a DNS domain, not a URL or individual identifier")
    try:
        host = raw.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise b.GuardError("invalid domain") from exc
    if len(host) > 253 or "." not in host or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
        raise b.GuardError("invalid domain")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise b.GuardError("domain OSINT expects a DNS name, not an IP")


def within(host, domain):
    return host == domain or host.endswith("." + domain)


def timestamp(value, *, cdx=False):
    if not isinstance(value, str):
        return None
    try:
        if cdx:
            parsed = dt.datetime.strptime(value, "%Y%m%d%H%M%S").replace(tzinfo=dt.timezone.utc)
        else:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.isoformat()
    except ValueError:
        return None


def provider_url(provider, domain):
    if provider == "crtsh":
        return "https://crt.sh/?" + urlencode({"q": "% .".replace(" ", "") + domain, "output": "json"})
    if provider == "certspotter":
        return "https://api.certspotter.com/v1/issuances?" + urlencode({"domain": domain, "include_subdomains": "true", "expand": "dns_names"})
    if provider == "wayback":
        return "https://web.archive.org/cdx/search/cdx?" + urlencode({"url": "*." + domain + "/*", "output": "json", "fl": "timestamp,original,statuscode", "collapse": "urlkey", "limit": "250"})
    raise b.GuardError("unsupported provider")


def parse_records(provider, data, domain):
    """Bounded first-page parsers; malformed rows are counted, never fabricated."""
    if not isinstance(data, list):
        raise b.GuardError("provider response is not a JSON array")
    rows, rejected = [], 0
    if provider in ("crtsh", "certspotter"):
        for entry in data[:500]:
            if not isinstance(entry, dict):
                rejected += 1
                continue
            raw_names = entry.get("name_value") if provider == "crtsh" else entry.get("dns_names")
            if provider == "crtsh" and isinstance(raw_names, str):
                raw_names = raw_names.splitlines()
            if not isinstance(raw_names, list) or len(raw_names) > 100:
                rejected += 1
                continue
            for name in raw_names:
                try:
                    if not isinstance(name, str):
                        raise b.GuardError("invalid hostname")
                    wildcard = name.startswith("*.")
                    host = domain_name(name[2:] if wildcard else name)
                    if not within(host, domain):
                        raise b.GuardError("outside research domain")
                    rows.append({"host": host, "url": None, "wildcard": wildcard,
                                 "source_time": timestamp(entry.get("not_before")),
                                 "time_meaning": "certificate not_before, not live observation", "historical_status": None})
                except b.GuardError:
                    rejected += 1
    elif provider == "wayback":
        if not data:
            return [], 0, False
        header = data[0]
        if not isinstance(header, list) or not all(key in header for key in ("timestamp", "original", "statuscode")):
            raise b.GuardError("archive response lacks required column names")
        for row in data[1:251]:
            try:
                if not isinstance(row, list) or len(row) != len(header):
                    raise b.GuardError("malformed archive row")
                record = dict(zip(header, row))
                url = b.canonical(record["original"], queries=True)
                host = domain_name(urlsplit(url).hostname)
                if not within(host, domain):
                    raise b.GuardError("outside research domain")
                when = timestamp(record["timestamp"], cdx=True)
                if when is None:
                    raise b.GuardError("invalid archive date")
                status = record["statuscode"]
                rows.append({"host": host, "url": b.safe_url(url), "wildcard": False,
                             "source_time": when, "time_meaning": "historical capture, not current availability",
                             "historical_status": status if isinstance(status, str) and re.fullmatch(r"[1-5][0-9]{2}", status) else None})
            except (ValueError, TypeError, KeyError):
                rejected += 1
    else:
        raise b.GuardError("unknown parser")
    capped = len(data) > (251 if provider == "wayback" else 500)
    return rows[:1000], rejected, capped or len(rows) > 1000


class DomainIntel:
    def __init__(self, policy, domain, *, certspotter=False):
        self.domain = domain_name(domain)
        self.policy = policy
        if self.domain not in {urlsplit(site).hostname for site in policy.origins}:
            raise b.GuardError("research domain must be an exact hostname in policy.origins")
        if policy.expiry() <= b.utcnow():
            raise b.GuardError("authorization expired")
        self.budget = b.Budget(policy)
        self.transport = b.Transport(policy, self.budget)
        self.providers = ["crtsh", "wayback"] + (["certspotter"] if certspotter else [])
        self.records, self.coverage = [], []
        self.started = b.utcnow().isoformat()

    def run(self):
        stop = "bounded provider queries completed; exhaustive collection not attempted"
        for provider in self.providers:
            row = {"provider": provider, "status": "pending", "records": 0,
                   "reason": "", "event_ids": [], "pagination": "first page/sample only"}
            self.coverage.append(row)
            try:
                # Critical invariant: no target GET and no target DNS resolution.
                result = self.transport.get(provider_url(provider, self.domain), provider=True)
                row["event_ids"] = [result.event_id]
                if not result.usable:
                    row.update(status="unavailable", reason=result.error or f"HTTP {result.status}; truncated={result.truncated}")
                    continue
                records, rejected, capped = parse_records(provider, json.loads(result.body), self.domain)
                for item in records:
                    item.update(provider=provider, source_family=PROVIDERS[provider][0],
                                event_id=result.event_id, collected_at=b.utcnow().isoformat())
                self.records.extend(records)
                row.update(status="observed", records=len(records), rejected_rows=rejected, locally_capped=capped,
                           reason="source records only; ownership, liveness and vulnerabilities unverified")
            except b.StopScan as exc:
                row.update(status="not_tested", reason=str(exc))
                stop = str(exc)
                break
            except KeyboardInterrupt:
                row.update(status="inconclusive", reason="operator interrupted")
                stop = "operator interrupted; partial intelligence preserved"
                break
            except (ValueError, TypeError, RecursionError) as exc:
                row.update(status="unavailable", reason=type(exc).__name__ + ": provider unavailable or invalid schema")
        for provider in self.providers[len(self.coverage):]:
            self.coverage.append({"provider": provider, "status": "not_tested", "records": 0, "reason": stop, "event_ids": []})
        assets = {}
        for record in self.records:
            key = record["host"]
            asset = assets.setdefault(key, {"host": key, "providers": set(), "source_families": set(), "event_ids": set(),
                                            "observed_paths": set(), "source_dates": set(), "wildcard_only": True})
            asset["providers"].add(record["provider"])
            asset["source_families"].add(record["source_family"])
            asset["event_ids"].add(record["event_id"])
            if record["url"]:
                asset["observed_paths"].add(record["url"])
            if record["source_time"]:
                asset["source_dates"].add(record["source_time"])
            asset["wildcard_only"] &= record["wildcard"]
        for asset in assets.values():
            for key, value in list(asset.items()):
                if isinstance(value, set):
                    asset[key] = sorted(value)
            asset["explicit_origins"] = [site for site in self.policy.origins if urlsplit(site).hostname == asset["host"]]
            asset["needs_scope_approval"] = not bool(asset["explicit_origins"])
            asset["live_status"] = "not tested"
            reasons = []
            if asset["observed_paths"]:
                reasons.append("historical URLs exist; review retirement/deployment inventory")
            if len(asset["source_families"]) > 1:
                reasons.append("seen in CT and archives; this is not evidence of weakness")
            if re.search(r"(?:^|[.-])(dev|staging|test|old|backup)(?:[.-]|$)", asset["host"]):
                reasons.append("environment-like hostname; purpose unverified")
            asset["review_reasons"] = reasons or ["reconcile source record with owner-maintained asset inventory"]
            asset["next_step"] = "Confirm ownership and exact authorized origin with asset owner; no automatic probing."
        return {"schema_version": 1, "tool": "BURHAN", "version": b.VERSION, "kind": "domain_osint",
                "domain": self.domain, "started_at": self.started, "finished_at": b.utcnow().isoformat(),
                "run_status": "completed_bounded_sample" if all(r["status"] == "observed" for r in self.coverage) else "partial",
                "stop_reason": stop, "target_http_requests": 0, "target_dns_lookups": 0,
                "provider_request_attempts": self.budget.count, "assets": sorted(assets.values(), key=lambda a: a["host"]),
                "records": self.records, "coverage": self.coverage, "events": self.budget.events,
                "limitations": ["First page/bounded samples, not exhaustive asset discovery.",
                                "CT sources share underlying logs and are not independent proof of ownership.",
                                "A certificate wildcard does not prove a concrete live host exists.",
                                "Archived status codes and certificate dates are not current liveness.",
                                "No discovered hostname automatically becomes authorized for active testing.",
                                "No key is supplied. Provider access/terms/rate limits may change; failures are reported.",
                                "No person lookup, contact-book extraction, private data acquisition or account deanonymization."]}


def normalize_identifier(kind, value):
    if not isinstance(value, str) or not value.strip() or len(value) > 254:
        raise b.GuardError("invalid identifier")
    value = unicodedata.normalize("NFKC", value.strip())
    if kind == "email":
        if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+", value):
            raise b.GuardError("supported email syntax is ASCII local-part@domain")
        local, domain = value.rsplit("@", 1)
        return local + "@" + domain_name(domain)
    if kind == "phone":
        if not re.fullmatch(r"\+[\d ()-]{7,30}", value):
            raise b.GuardError("phone must include explicit international +country code")
        digits = "".join(str(unicodedata.digit(c)) for c in value if c.isdecimal())
        if not re.fullmatch(r"[1-9][0-9]{6,14}", digits):
            raise b.GuardError("phone must have 7..15 digits with nonzero country prefix")
        return "+" + digits
    if kind == "name":
        if any(unicodedata.category(c).startswith("C") for c in value):
            raise b.GuardError("name contains control characters")
        return " ".join(value.split())
    raise b.GuardError("unsupported identifier kind")


def local_audit(kind, value_path, input_path):
    """Locate exact occurrences only in a user's supplied export; never fetch links."""
    value_file, source = Path(value_path), Path(input_path)
    if value_file.stat().st_size > 1024 or source.stat().st_size > 5 * 1024 * 1024:
        raise b.GuardError("identifier file cap 1 KiB; input export cap 5 MiB")
    identifier = normalize_identifier(kind, value_file.read_text())
    matches, rejected = [], []
    lines = source.read_text().splitlines()
    for number, line in enumerate(lines[:10000], 1):
        if not line.strip():
            continue
        try:
            if len(line) > 65536:
                raise b.GuardError("record too large")
            record = json.loads(line)
            if not isinstance(record, dict) or not isinstance(record.get("content"), str) or len(record["content"]) > 32768:
                raise b.GuardError("record must have bounded text content")
            content = unicodedata.normalize("NFKC", record["content"])
            occurrences = []
            if kind == "name":
                # Whole-field equality only. Same name != same individual.
                if normalize_identifier("name", content) == identifier:
                    occurrences = [1]
            else:
                pattern = r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~@-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+" if kind == "email" else r"(?<![\w+])\+[\d ()-]{7,30}"
                for match in re.finditer(pattern, content):
                    try:
                        same = normalize_identifier(kind, match.group()) == identifier
                    except b.GuardError:
                        same = False
                    if same:
                        occurrences.append(content[:match.start()].count("\n") + 1)
            if occurrences:
                matches.append({"input_record": number, "content_lines": sorted(set(occurrences))[:20],
                                "state": "exact_text_occurrence_not_identity_proof",
                                "next_step": "Review this record in your original export; remove unnecessary publication or request correction if appropriate."})
        except (ValueError, TypeError, RecursionError):
            rejected.append({"input_record": number, "reason": "unsupported or malformed local record"})
    return {"schema_version": 1, "tool": "BURHAN", "version": b.VERSION, "kind": "local_self_audit",
            "identifier_kind": kind, "identifier": "[NOT STORED]", "network_requests": 0,
            "input_sha256": b.sha(source.read_bytes()), "input_records_examined": min(len(lines), 10000),
            "capped": len(lines) > 10000, "matches": matches, "rejected": rejected,
            "limitations": ["Only the provided local export was searched. Not an online or comprehensive exposure search.",
                            "Exact text occurrence does not prove identity, current ownership, an account or a breach.",
                            "Email local-part case and +aliases are preserved. Names require whole-field equality; no fuzzy identity linking.",
                            "No identifier, snippet, source URL, private profile or third-party contact label is exported.",
                            "Input may be inaccurate or stale. Use only your data or exports you are authorized to audit."]}


def write_output(data, directory):
    out = Path(directory)
    if not out.parent.is_dir() or out.exists():
        raise b.GuardError("choose a new output directory under an existing parent")
    out.mkdir(mode=0o700)
    encoded = json.dumps(data, ensure_ascii=False, indent=2)
    b.private_write(out / "report.json", encoded + "\n")
    title = "Domain intelligence" if data["kind"] == "domain_osint" else "Local identifier exposure audit"
    # No JS or remote content; escaped JSON retains all provenance without inventing a severity.
    content = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>BURHAN | {title}</title><style>body{{background:#0a111b;color:#e6edf5;font:15px/1.6 system-ui;margin:0}}main{{max-width:1100px;margin:auto;padding:40px 24px}}h1{{font-size:38px}}.brand{{color:#63dfbd;letter-spacing:4px;font-weight:bold}}.notice{{border-left:3px solid #63dfbd;padding:15px;background:#13242b}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#111e2c;border:1px solid #27394d;padding:22px;border-radius:10px;font-size:12px}}@media print{{body,pre{{background:white;color:black}}}}</style></head><body><main><div class="brand">BURHAN | بُرهان</div><h1>{title}</h1><p class="notice">Evidence provenance, not vulnerability confirmation. No identity attribution from matching text.</p><pre>{html.escape(encoded)}</pre></main></body></html>'''
    b.private_write(out / "report.html", content)
    b.private_write(out / "report.md", "# BURHAN — " + title + "\n\nSee report.json for the complete provenance ledger.\n\n" + "\n".join("- " + x for x in data["limitations"]) + "\n")
    b.private_write(out / "manifest.json", json.dumps({name: b.sha((out / name).read_bytes()) for name in ("report.json", "report.html", "report.md")}, indent=2) + "\n")


def add_parser(subs):
    command = subs.add_parser("osint", help="separate provider-only domain research or local consented exposure audit")
    modes = command.add_subparsers(dest="osint_mode", required=True)
    domain = modes.add_parser("domain", help="CT/archive source records; no HTTP or DNS requests to target")
    domain.add_argument("--domain", required=True)
    domain.add_argument("--policy", required=True)
    domain.add_argument("--share-intel", action="store_true", help="consent to disclosure of research domain to providers")
    domain.add_argument("--certspotter-evaluation", action="store_true", help="limited unauthenticated evaluation queries only; see provider terms")
    domain.add_argument("--out", required=True)
    audit = modes.add_parser("self-audit", help="find exact occurrences in an authorized local JSONL export; no network")
    audit.add_argument("--kind", choices=["email", "phone", "name"], required=True)
    audit.add_argument("--value-file", required=True, help="read identifier privately from a local text file, not command history")
    audit.add_argument("--input", required=True, help="local JSONL with a content string per record")
    audit.add_argument("--consented", action="store_true", help="attest that you may audit these local records")
    audit.add_argument("--out", required=True)


def execute(args):
    out = Path(args.out)
    if out.exists() or not out.absolute().parent.is_dir() or not os.access(out.absolute().parent, os.W_OK):
        raise b.GuardError("output must be new and its parent must exist and be writable")
    if args.osint_mode == "domain":
        if not args.share_intel:
            raise b.GuardError("domain research requires --share-intel before contacting providers")
        data = DomainIntel(b.Policy.load(args.policy), args.domain, certspotter=args.certspotter_evaluation).run()
    else:
        if not args.consented:
            raise b.GuardError("local audit requires --consented for your own/authorized export")
        data = local_audit(args.kind, args.value_file, args.input)
    write_output(data, out)
    print(f"BURHAN OSINT | {data['kind']} | {out / 'report.html'}")
    print("Target HTTP requests: 0. Source observations do not prove vulnerabilities or identity.")
    return 2 if data.get("run_status") == "partial" else 0
