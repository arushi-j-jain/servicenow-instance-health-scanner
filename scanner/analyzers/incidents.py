from datetime import datetime, timezone
from ..client import ServiceNowClient
from ..models import AreaResult, Finding, Severity

# ServiceNow state codes
STATE_LABELS   = {"1": "New", "2": "In Progress", "3": "On Hold", "6": "Resolved", "7": "Closed", "8": "Cancelled"}
# ServiceNow priority codes
PRIORITY_LABELS = {"1": "Critical", "2": "High", "3": "Moderate", "4": "Low", "5": "Planning"}


def analyze(client: ServiceNowClient) -> AreaResult:
    findings = []
    fields = ["number", "short_description", "state", "priority",
              "opened_at", "reassignment_count", "sys_updated_on"]

    # Only fetch open incidents (exclude Resolved/Closed/Cancelled)
    open_incidents = client.get_records(
        "incident", fields=fields,
        query="state!=6^state!=7^state!=8",
        limit=1000
    )
    total_open = len(open_incidents)

    # --- Critical open incidents ---
    critical = [i for i in open_incidents if i.get("priority") == "1"]

    # --- High reassignment count (bounced more than 3 times) ---
    high_reassign = [
        i for i in open_incidents
        if int(i.get("reassignment_count") or 0) > 3
    ]

    # --- Aging incidents: open more than 30 days ---
    now = datetime.now(timezone.utc)
    aging = []
    for inc in open_incidents:
        raw = inc.get("opened_at", "")
        if not raw:
            continue
        try:
            opened_dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            days_open = (now - opened_dt).days
            if days_open > 30:
                inc["_days_open"] = days_open
                aging.append(inc)
        except ValueError:
            pass

    # --- Priority breakdown for raw_data ---
    priority_counts = {label: 0 for label in PRIORITY_LABELS.values()}
    for inc in open_incidents:
        label = PRIORITY_LABELS.get(inc.get("priority", ""), "Unknown")
        priority_counts[label] = priority_counts.get(label, 0) + 1

    # --- State breakdown for raw_data ---
    state_counts = {label: 0 for label in STATE_LABELS.values()}
    for inc in open_incidents:
        label = STATE_LABELS.get(inc.get("state", ""), "Unknown")
        state_counts[label] = state_counts.get(label, 0) + 1

    if critical:
        findings.append(Finding(
            title="Open Critical Incidents",
            description=f"{len(critical)} Critical priority incidents are unresolved and need immediate attention.",
            severity=Severity.CRITICAL,
            count=len(critical),
            records=[
                {"number": i["number"], "description": i.get("short_description", "")[:60]}
                for i in critical[:10]
            ],
            recommendation="Assign dedicated resources immediately. Review the escalation and on-call process."
        ))

    if aging:
        sorted_aging = sorted(aging, key=lambda x: x.get("_days_open", 0), reverse=True)
        findings.append(Finding(
            title="Aging Incidents (Open > 30 Days)",
            description=f"{len(aging)} incidents have been open for over 30 days without resolution.",
            severity=Severity.WARNING,
            count=len(aging),
            records=[
                {"number": i["number"], "days_open": i["_days_open"], "description": i.get("short_description", "")[:50]}
                for i in sorted_aging[:10]
            ],
            recommendation="Set up automated escalation rules that trigger at 7, 14, and 30 days open."
        ))

    if high_reassign:
        findings.append(Finding(
            title="Incidents With High Reassignment Count",
            description=f"{len(high_reassign)} incidents have been reassigned more than 3 times, indicating routing problems.",
            severity=Severity.WARNING,
            count=len(high_reassign),
            records=[
                {"number": i["number"], "reassignments": i.get("reassignment_count", 0),
                 "description": i.get("short_description", "")[:50]}
                for i in high_reassign[:10]
            ],
            recommendation="Review assignment group skills and routing rules to reduce incident bouncing."
        ))

    score = 100
    if total_open > 0:
        score -= min(30, int(len(critical) / total_open * 60))
        score -= min(25, int(len(aging) / total_open * 50))
        score -= min(15, int(len(high_reassign) / total_open * 30))
    score = max(0, score)

    return AreaResult(
        name="Incidents",
        score=score,
        findings=findings,
        raw_data={
            "total_open": total_open,
            "critical_open": len(critical),
            "aging_over_30d": len(aging),
            "high_reassignment": len(high_reassign),
            "by_priority": priority_counts,
            "by_state": state_counts,
        }
    )
