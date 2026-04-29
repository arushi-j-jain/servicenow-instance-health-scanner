import argparse
import os
import time
import webbrowser
from scanner.client import ServiceNowClient
from scanner.models import Severity
from report.generator import generate_report
from scanner.pusher import push_results
from scanner.analyzers import (
    business_rules,
    client_scripts,
    script_includes,
    acls,
    incidents,
)

# Weight of each area in the overall score (higher = more impact on final score)
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
    if score >= 75:
        return "GOOD"
    if score >= 50:
        return "FAIR"
    return "POOR"


def print_divider(char="=", width=65):
    print(char * width)


def print_area(result):
    print()
    print_divider("-")
    label = score_label(result.score)
    print(f"  {result.name:<20}  Score: {result.score:>3}/100  [{score_bar(result.score)}]  {label}")
    print_divider("-")

    if result.error:
        print(f"  [ERROR] {result.error}")
        return

    if not result.findings:
        print("  No issues found.")
        return

    for f in result.findings:
        icon = SEVERITY_ICON[f.severity]
        print(f"\n  [{icon}]  {f.title}  ({f.count} found)")
        print(f"  {f.description}")
        if f.records:
            print("  Examples:")
            for rec in f.records[:3]:
                print(f"    {rec}")
        print(f"  Recommendation: {f.recommendation}")


def main():
    parser = argparse.ArgumentParser(description="ServiceNow Instance Health Scanner")
    parser.add_argument(
        "--anonymize",
        action="store_true",
        help="Replace the instance URL with REDACTED in the HTML report (safe for sharing)",
    )
    args = parser.parse_args()

    print_divider()
    print("  ServiceNow Instance Health Scanner")
    print_divider()

    client = ServiceNowClient()
    report_url = "REDACTED" if args.anonymize else client.instance
    print(f"  Instance : {client.instance}")
    if args.anonymize:
        print("  Mode     : --anonymize  (instance URL will be redacted in report)")
    print(f"  Scanning 5 areas...\n")

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
            from scanner.models import AreaResult
            result = AreaResult(name=name, score=0, error=str(exc))
            print(f"\r  [{name:<20}]  ERROR: {exc}")
        results.append(result)
    scan_duration = time.time() - scan_start

    print(f"  [{'Version check':<20}]  fetching...", end="", flush=True)
    snow_version = client.get_version()
    print(f"\r  [{'Version check':<20}]  {snow_version[:50] if snow_version != 'Unknown' else 'Unknown'}")

    metadata = {
        "duration_seconds": scan_duration,
        "api_calls": client.call_count,
        "snow_version": snow_version,
        "tables_scanned": [
            "sys_script", "sys_script_client", "sys_script_include",
            "sys_security_acl", "incident",
        ],
    }

    # Weighted overall score
    total_weight = sum(WEIGHTS.get(r.name, 1.0) for r in results)
    overall = int(sum(r.score * WEIGHTS.get(r.name, 1.0) for r in results) / total_weight)

    print()
    print_divider()
    print("  DETAILED FINDINGS")
    print_divider()

    for result in results:
        print_area(result)

    # Action plan: collect all findings sorted by severity
    all_findings = []
    for result in results:
        for f in result.findings:
            all_findings.append((result.name, f))

    severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    all_findings.sort(key=lambda x: severity_order[x[1].severity])

    print()
    print_divider()
    print("  PRIORITISED ACTION PLAN")
    print_divider()
    for i, (area, finding) in enumerate(all_findings, 1):
        icon = SEVERITY_ICON[finding.severity]
        print(f"\n  {i}. [{icon}]  [{area}]  {finding.title}")
        print(f"     {finding.recommendation}")

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
    print()
    print("  Generating HTML report...", end="", flush=True)
    report_path = generate_report(results, overall, instance_url=report_url, metadata=metadata)
    print(f" done.")
    abs_path = os.path.abspath(report_path)
    print(f"  Report saved to: {abs_path}")
    webbrowser.open(f"file:///{abs_path.replace(os.sep, '/')}")

    print("  Pushing results to ServiceNow...", end="", flush=True)
    pushed, skip_reason = push_results(client, results, overall)
    if skip_reason:
        print(f"\r  ServiceNow push: skipped — {skip_reason}")
    else:
        print(f"\r  ServiceNow push: {pushed} records inserted into custom tables.")
    print()

    return results, overall, client


if __name__ == "__main__":
    main()
