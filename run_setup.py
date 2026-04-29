"""
ServiceNow Health Scanner — One-command setup + first scan
Runs setup_dashboard.py, then executes the full scan and pushes results.

Usage:
    python run_setup.py
"""
import sys
from setup_dashboard import DashboardSetup
from scanner.client import ServiceNowClient
from scanner.analyzers import business_rules, client_scripts, script_includes, acls, incidents
from scanner.models import AreaResult, Severity
from scanner.pusher import push_results
from report.generator import generate_report
import time
import os
import webbrowser

TABLE_RESULTS  = "sn_ap_apm_u_health_scan_results"
TABLE_FINDINGS = "sn_ap_apm_u_health_scan_findings"

WEIGHTS = {
    "Business Rules":  1.5,
    "Client Scripts":  1.5,
    "Script Includes": 1.0,
    "ACLs":            2.0,
    "Incidents":       2.0,
}

SEVERITY_ICON = {
    Severity.CRITICAL: "!! CRITICAL",
    Severity.WARNING:  " ! WARNING ",
    Severity.INFO:     "   INFO   ",
}


def score_bar(score):
    filled = score // 5
    return "#" * filled + "-" * (20 - filled)


def score_label(score):
    if score >= 75: return "GOOD"
    if score >= 50: return "FAIR"
    return "POOR"


def print_divider(char="=", width=65):
    print(char * width)


def run_scan(client):
    """Run all analyzers and return (results, overall_score, metadata)."""
    analyzers = [
        ("Business Rules",  business_rules),
        ("Client Scripts",  client_scripts),
        ("Script Includes", script_includes),
        ("ACLs",            acls),
        ("Incidents",       incidents),
    ]

    scan_start = time.time()
    results = []
    for name, module in analyzers:
        print(f"  [{name:<20}]  scanning...", end="", flush=True)
        try:
            result = module.analyze(client)
            print(f"\r  [{name:<20}]  score: {result.score}/100")
        except Exception as exc:
            result = AreaResult(name=name, score=0, error=str(exc))
            print(f"\r  [{name:<20}]  ERROR: {exc}")
        results.append(result)
    scan_duration = time.time() - scan_start

    print(f"  [{'Version check':<20}]  fetching...", end="", flush=True)
    snow_version = client.get_version()
    print(f"\r  [{'Version check':<20}]  {snow_version[:50]}")

    metadata = {
        "duration_seconds": scan_duration,
        "api_calls":        client.call_count,
        "snow_version":     snow_version,
        "tables_scanned": [
            "sys_script", "sys_script_client", "sys_script_include",
            "sys_security_acl", "incident",
        ],
    }

    total_weight = sum(WEIGHTS.get(r.name, 1.0) for r in results)
    overall = int(sum(r.score * WEIGHTS.get(r.name, 1.0) for r in results) / total_weight)

    return results, overall, metadata


def print_findings(results, overall):
    print()
    print_divider("-")
    print("  DETAILED FINDINGS")
    print_divider("-")
    for result in results:
        print()
        label = score_label(result.score)
        print(f"  {result.name:<20}  Score: {result.score:>3}/100  [{score_bar(result.score)}]  {label}")
        if result.error:
            print(f"    [ERROR] {result.error}")
            continue
        if not result.findings:
            print("    No issues found.")
            continue
        for f in result.findings:
            icon = SEVERITY_ICON[f.severity]
            print(f"\n    [{icon}]  {f.title}  ({f.count} found)")
            print(f"    {f.description}")
            if f.records:
                print("    Examples:")
                for rec in f.records[:3]:
                    print(f"      {rec}")
            print(f"    Recommendation: {f.recommendation}")

    print()
    print_divider()
    print(f"  OVERALL HEALTH SCORE:  {overall}/100  [{score_bar(overall)}]  {score_label(overall)}")
    print_divider()
    if overall >= 75:
        print("  Status: HEALTHY  — a few things to polish, no urgent risks.")
    elif overall >= 50:
        print("  Status: FAIR     — several issues need attention soon.")
    else:
        print("  Status: POOR     — critical issues require immediate action.")


def main():
    print("=" * 65)
    print("  ServiceNow Health Scanner — Full Setup + First Scan")
    print("=" * 65)

    # ── Phase 1: Dashboard setup ──────────────────────────────────────
    print("\n[PHASE 1 OF 3]  Dashboard Setup")
    setup = DashboardSetup()
    setup_ok = setup.run()

    if not setup_ok:
        print("\n  Setup incomplete. Fix the issues above and re-run.")
        print("  Scan will still run — push will be skipped if tables are missing.\n")

    # ── Phase 2: Scan ─────────────────────────────────────────────────
    print("\n[PHASE 2 OF 3]  Running Health Scan")
    print("=" * 65)

    client = ServiceNowClient()
    print(f"  Instance : {client.instance}")
    print(f"  Scanning 5 areas...\n")

    results, overall, metadata = run_scan(client)
    print_findings(results, overall)

    print()
    print("  Generating HTML report...", end="", flush=True)
    report_path = generate_report(results, overall, instance_url=client.instance, metadata=metadata)
    print(" done.")
    abs_path = os.path.abspath(report_path)
    print(f"  Report saved to: {abs_path}")
    webbrowser.open(f"file:///{abs_path.replace(os.sep, '/')}")

    # ── Phase 3: Push results ─────────────────────────────────────────
    print("\n[PHASE 3 OF 3]  Pushing Results to ServiceNow")
    print("=" * 65)
    print("  Inserting scan data into custom tables...", end="", flush=True)
    pushed, skip_reason = push_results(client, results, overall)
    if skip_reason:
        print(f"\r  Push skipped — {skip_reason}")
    else:
        print(f"\r  Pushed {pushed} records to ServiceNow.                    ")

    # ── Final instructions ────────────────────────────────────────────
    print()
    print("=" * 65)
    print("  SETUP COMPLETE")
    print("=" * 65)
    if setup.report_sys_ids:
        print()
        print("  Last step: add the reports to your dashboard.")
        print("  In ServiceNow: Reports > View / Run > open each report below")
        print('  > click "Add to Dashboard" > create new > name it')
        print('  "Instance Health Scanner"\n')
        for title, sid in setup.report_sys_ids.items():
            url = f"{client.instance}/sys_report.do?sys_id={sid}" if sid else "(no sys_id)"
            print(f"    {title}")
            print(f"      {url}")
        print()
        print("  Find your dashboard under:")
        print("  Self-Service > Dashboards  (search 'Instance Health')")
    print()
    print("  Going forward, run   python main.py   to refresh the dashboard data.")
    print("=" * 65)


if __name__ == "__main__":
    main()
