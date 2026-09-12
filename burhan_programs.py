"""Dated, reviewed bounty presets. Planning is offline; scan requires fresh consent."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import time
from urllib.parse import urlsplit

import burhan as b

CATALOG = Path(__file__).resolve().with_name("programs.json")


def load_catalog(path=CATALOG):
    path = Path(path)
    if path.stat().st_size > 131072:
        raise b.GuardError("program catalog exceeds 128 KiB")
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("programs"), list):
        raise b.GuardError("invalid program catalog")
    reviewed = dt.datetime.fromisoformat(data["reviewed_at"])
    expires = dt.datetime.fromisoformat(data["review_valid_until"])
    if reviewed.tzinfo is None or expires.tzinfo is None or not reviewed < expires:
        raise b.GuardError("invalid catalog review dates")
    identifiers = set()
    for program in data["programs"]:
        identifier = program["id"]
        if identifier not in ("clario", "cs-money") or identifier in identifiers:
            raise b.GuardError("unknown or duplicate program identifier")
        identifiers.add(identifier)
        origins = program["scan_origins"]
        if not isinstance(origins, list) or not origins or len(origins) != len(set(origins)):
            raise b.GuardError("empty or duplicate scope origins")
        for site in origins:
            url = b.canonical(site)
            if urlsplit(url).path != "/" or urlsplit(url).scheme != "https":
                raise b.GuardError("program preset requires exact HTTPS origins")
            if urlsplit(url).hostname in program["explicit_out_of_scope_assets"]:
                raise b.GuardError("preset overlaps explicit out-of-scope assets")
    return data


def selected_programs(catalog, selector):
    selected = [p for p in catalog["programs"] if selector == "all" or p["id"] == selector]
    if not selected:
        raise b.GuardError("unknown program")
    return selected


def build_plan(selector, catalog=None):
    catalog = load_catalog() if catalog is None else catalog
    stages = []
    for program in selected_programs(catalog, selector):
        for start in range(0, len(program["scan_origins"]), 10):
            sites = program["scan_origins"][start:start + 10]
            policy = b.Policy(origins=sites,
                              authorization_ref="PUBLIC-PROGRAM: " + program["policy_url"],
                              expires_at=catalog["review_valid_until"], automation_allowed=True,
                              excluded_paths=program["excluded_paths"], max_requests=14 * len(sites),
                              max_seconds=600, interval_seconds=2.0, timeout_seconds=8,
                              max_body_bytes=262144, max_assets=3)
            policy.validate()
            if 1 / policy.interval_seconds > program["published_rate_limit_rps"]:
                raise b.GuardError("preset pacing exceeds published rate limit")
            stages.append({"id": program["id"] + "-" + str(start // 10 + 1),
                           "program": program["id"], "policy": b.dataclasses.asdict(policy),
                           "policy_url": program["policy_url"], "scope_url": program["scope_url"],
                           "scope_completeness": program["scope_completeness"]})
    return {"reviewed_at": catalog["reviewed_at"], "review_valid_until": catalog["review_valid_until"],
            "review_current": dt.datetime.fromisoformat(catalog["review_valid_until"]) > b.utcnow(),
            "network_requests": 0, "stage_execution": "sequential, one network request at a time",
            "pacing_seconds": 2, "maximum_request_attempts": sum(s["policy"]["max_requests"] for s in stages),
            "stages": stages,
            "warning": "Not live policy verification or guaranteed full functional coverage. Confirm eligibility and current rules before scan.",
            "stop_policy": "Stop the entire batch for operator interruption or first candidate/verified exposure requiring human review."}


class ProgramAssessment(b.Assessment):
    """Stop after retaining a finding; never continue across programs after a review signal."""
    def __init__(self, policy):
        super().__init__(policy)
        self.review_stop = False

    def add(self, rule, url, state, title, evidence, events, remediation, impact):
        super().add(rule, url, state, title, evidence, events, remediation, impact)
        if state in ("candidate", "verified_exposure"):
            self.review_stop = True
            raise b.StopScan("manual review required; batch stopped after an exposure/candidate (not a confirmed vulnerability)")


def run_programs(selector, directory, acknowledged):
    if not acknowledged:
        raise b.GuardError("requires --acknowledge-current-rules: confirm current scope, eligibility, permission and all program rules")
    catalog = load_catalog()
    plan = build_plan(selector, catalog)
    if not plan["review_current"]:
        raise b.GuardError("program snapshot expired; re-review official policies and scope before updating the snapshot")
    out = Path(directory)
    if out.exists() or not out.absolute().parent.is_dir() or not os.access(out.absolute().parent, os.W_OK):
        raise b.GuardError("choose a new output directory under an existing writable parent")
    out.mkdir(mode=0o700)
    summary = {"tool": "BURHAN", "version": b.VERSION, "kind": "program_batch",
               "plan": plan, "runs": [], "unexecuted_stages": [], "stopped": False}
    for number, stage in enumerate(plan["stages"]):
        try:
            if number:
                time.sleep(2)  # Preserve gentle pacing even across independent stage budgets.
            policy = b.Policy(**stage["policy"])
            policy.validate()
            if policy.expiry() <= b.utcnow():
                raise b.StopScan("review cutoff reached")
            print("Stage " + stage["id"] + " | " + str(len(policy.origins)) + " exact origins | max 0.5 requests/s", flush=True)
            assessment = ProgramAssessment(policy)
            report = assessment.run()
            report["program_preset"] = {k: stage[k] for k in ("program", "policy_url", "scope_url", "scope_completeness")}
            report["program_preset"]["reviewed_at"] = catalog["reviewed_at"]
            b.write_report(report, out / stage["id"])
            summary["runs"].append({"stage": stage["id"], "status": report["run_status"],
                                    "requests_used": report["requests_used"], "report": stage["id"] + "/report.html"})
            if assessment.review_stop or report["run_status"] == "interrupted":
                summary.update(stopped=True, reason=report["stop_reason"])
                summary["unexecuted_stages"] = [s["id"] for s in plan["stages"][number + 1:]]
                break
        except (KeyboardInterrupt, b.StopScan):
            summary.update(stopped=True, reason="operator interruption or review cutoff reached")
            summary["unexecuted_stages"] = [s["id"] for s in plan["stages"][number:]]
            break
    b.private_write(out / "batch.json", json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print("Batch index: " + str(out / "batch.json"))
    return 2 if summary["stopped"] or any(r["status"] != "completed" for r in summary["runs"]) else 0


def add_parser(subs):
    command = subs.add_parser("programs", help="reviewed real-program scope presets; no hand-entered target list")
    modes = command.add_subparsers(dest="program_action", required=True)
    modes.add_parser("list", help="list reviewed programs without network access")
    show = modes.add_parser("show", help="read exact included/excluded assets, policy links and limitations")
    show.add_argument("program", choices=["clario", "cs-money"])
    plan = modes.add_parser("plan", help="show exact generated policies and maximum budget; no network")
    plan.add_argument("program", choices=["clario", "cs-money", "all"])
    scan = modes.add_parser("scan", help="run selected program presets sequentially after your policy confirmation")
    scan.add_argument("program", choices=["clario", "cs-money", "all"])
    scan.add_argument("--acknowledge-current-rules", action="store_true")
    scan.add_argument("--out", required=True)


def execute(args):
    if args.program_action == "list":
        catalog = load_catalog()
        for p in catalog["programs"]:
            print(p["id"] + " | " + p["name"] + " | " + str(len(p["scan_origins"])) + " HTTPS origins | " + p["policy_url"])
        print("Reviewed " + catalog["reviewed_at"] + " | Re-review required after " + catalog["review_valid_until"])
        print("CS Money is a subset, not full scope. No targets contacted.")
    elif args.program_action == "show":
        print(json.dumps(selected_programs(load_catalog(), args.program)[0], ensure_ascii=False, indent=2))
    elif args.program_action == "plan":
        print(json.dumps(build_plan(args.program), ensure_ascii=False, indent=2))
    else:
        return run_programs(args.program, args.out, args.acknowledge_current_rules)
    return 0
