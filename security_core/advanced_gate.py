#!/usr/bin/env python3
"""LAC Cybersecurity Suite v3: private findings -> redacted, minimal release-gate summary.
Never copy potential secret values, Semgrep snippets or raw scanner JSON into the artifact.
Developed by: Eng. Luiz Alberto Castro.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

VERSION = "3.0.0"

def evaluate(lac: dict, gitleaks: list, semgrep: dict) -> dict:
    if not isinstance(lac, dict) or not isinstance(lac.get("summary"), dict):
        raise ValueError("Invalid or missing LAC scanner report")
    if not isinstance(gitleaks, list):
        raise ValueError("Invalid or missing Gitleaks report")
    if not isinstance(semgrep, dict) or not isinstance(semgrep.get("results"), list):
        raise ValueError("Invalid or missing Semgrep report")
    severity = Counter(str(r.get("extra", {}).get("severity", "UNKNOWN")).upper()
                       for r in semgrep["results"] if isinstance(r, dict))
    lac_summary = lac["summary"]
    missing = int(lac_summary.get("unscanned_files", 0))
    errors = semgrep.get("errors", [])
    if not isinstance(errors, list):
        raise ValueError("Invalid Semgrep errors field")
    blocked = (int(lac_summary.get("critical", 0)) > 0 or
               int(lac_summary.get("high", 0)) > 0 or
               bool(gitleaks) or severity["ERROR"] > 0)
    if missing or errors:
        status = "INCOMPLETE"
    elif blocked:
        status = "BLOCKED_REVIEW"
    elif lac_summary.get("findings", 0) or semgrep["results"]:
        status = "REVIEW_REQUIRED"
    else:
        status = "AUTOMATED_CHECKS_CLEAR"
    return {
        "tool": "LAC Cybersecurity Suite", "version": VERSION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": status, "production_approved": False,
        "results": {
            "lac_files": int(lac_summary.get("files_scanned", 0)),
            "lac_findings": int(lac_summary.get("findings", 0)),
            "lac_high": int(lac_summary.get("high", 0)),
            "lac_critical": int(lac_summary.get("critical", 0)),
            "lac_unscanned": missing,
            "gitleaks_potential_secrets": len(gitleaks),
            "semgrep_findings": len(semgrep["results"]),
            "semgrep_error_severity": severity["ERROR"],
            "semgrep_warning_severity": severity["WARNING"],
            "semgrep_scan_errors": len(errors),
        },
        "scope": "Static source, local Semgrep rules, Git history secrets",
        "not_verified": [
            "Full dependency/CVE scan", "Running application and APIs",
            "Access controls and multiuser isolation", "Database permissions",
            "Backup restoration", "Production infrastructure", "AI agent red teaming",
        ],
    }

def render_markdown(report: dict) -> str:
    r = report["results"]
    rows = ["# LAC Cybersecurity Suite — Review summary", "",
            "Status: **" + report["status"] + "**",
            "Production approval: **NO**", "",
            "| Metric | Value |", "|---|---:|"]
    rows += ["| " + name.replace("_", " ") + " | " + str(value) + " |"
             for name, value in r.items()]
    rows += ["", "## Not verified", ""]
    rows += ["- " + item for item in report["not_verified"]]
    rows += ["", "No raw findings, excerpts, credentials or Git history were copied into this report.",
             "Developed by: Eng. Luiz Alberto Castro."]
    return "\n".join(rows) + "\n"

def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--lac", required=True)
    p.add_argument("--gitleaks", required=True)
    p.add_argument("--semgrep", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    try:
        lac = json.loads(Path(args.lac).read_text(encoding="utf-8"))
        leaks = json.loads(Path(args.gitleaks).read_text(encoding="utf-8"))
        semgrep = json.loads(Path(args.semgrep).read_text(encoding="utf-8"))
        report = evaluate(lac, leaks, semgrep)
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        (out / "summary.md").write_text(render_markdown(report), encoding="utf-8")
        print("LAC_V3_SUMMARY " + json.dumps({"status": report["status"], **report["results"]}))
        return 1 if report["status"] in ("BLOCKED_REVIEW", "INCOMPLETE") else 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("LAC_V3_ERROR Report missing or invalid: " + type(exc).__name__, file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
