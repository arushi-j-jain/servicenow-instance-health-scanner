"""
Push scan results into the ServiceNow custom tables created by setup_dashboard.py.
Imported by main.py and run_setup.py.
"""
from datetime import datetime, timezone
from scanner.models import Severity

TABLE_RESULTS  = "sn_ap_apm_u_health_scan_results"
TABLE_FINDINGS = "sn_ap_apm_u_health_scan_findings"


def tables_available(client):
    """Return True if both custom tables exist and are reachable."""
    for table in (TABLE_RESULTS, TABLE_FINDINGS):
        try:
            client.get_records(table, fields=["sys_id"], limit=1)
        except Exception:
            return False
    return True


def push_results(client, results, overall_score, verbose=True):
    """
    Write one u_health_scan_results row per domain and one
    u_health_scan_findings row per finding.

    Returns (rows_pushed, skipped_reason_or_None).
    """
    if not tables_available(client):
        return 0, (
            f"Custom tables not found ({TABLE_RESULTS}, {TABLE_FINDINGS}). "
            "Run python setup_dashboard.py first."
        )

    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    rows_pushed = 0
    errors = []

    for result in results:
        n_crit = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
        n_warn = sum(1 for f in result.findings if f.severity == Severity.WARNING)
        n_info = sum(1 for f in result.findings if f.severity == Severity.INFO)

        try:
            row = client.post_record(TABLE_RESULTS, {
                "u_scan_date":      scan_time,
                "u_domain":         result.name,
                "u_health_score":   str(result.score),
                "u_total_findings": str(len(result.findings)),
                "u_critical_count": str(n_crit),
                "u_warning_count":  str(n_warn),
                "u_info_count":     str(n_info),
                "u_overall_score":  str(overall_score),
            })
        except Exception as exc:
            errors.append(f"{result.name}: {exc}")
            continue

        result_sys_id = row.get("sys_id", "")
        rows_pushed += 1

        for finding in result.findings:
            examples = "; ".join(str(r) for r in finding.records[:3])
            try:
                client.post_record(TABLE_FINDINGS, {
                    "u_parent":         result_sys_id,
                    "u_domain":         result.name,
                    "u_severity":       finding.severity.value.capitalize(),
                    "u_title":          finding.title[:255],
                    "u_description":    finding.description[:1000],
                    "u_count":          str(finding.count),
                    "u_recommendation": finding.recommendation[:1000],
                    "u_examples":       examples[:4000],
                })
                rows_pushed += 1
            except Exception as exc:
                errors.append(f"  finding '{finding.title}': {exc}")

    if verbose and errors:
        print(f"  Push warnings ({len(errors)}):")
        for e in errors[:5]:
            print(f"    {e}")

    return rows_pushed, None
