from ..client import ServiceNowClient
from ..models import AreaResult, Finding, Severity


def _is_true(val):
    return str(val).lower() == "true"


def analyze(client: ServiceNowClient) -> AreaResult:
    findings = []
    fields = ["name", "collection", "active", "action_insert", "action_update",
              "action_delete", "action_query", "filter_condition", "when"]

    active_rules = client.get_records("sys_script", fields=fields, query="active=true")
    inactive_rules = client.get_records("sys_script", fields=["name", "collection"], query="active=false")
    total = len(active_rules)

    # Rules with no filter condition run on EVERY record — expensive
    no_filter = [r for r in active_rules if not r.get("filter_condition", "").strip()]

    # Rules that fire on all four operations at once
    all_ops = [
        r for r in active_rules
        if all(_is_true(r.get(op)) for op in ("action_insert", "action_update", "action_delete", "action_query"))
    ]

    if no_filter:
        findings.append(Finding(
            title="Business Rules Without Filter Conditions",
            description=(
                f"{len(no_filter)} active business rules have no filter condition, "
                "so they execute on every single record operation for their table."
            ),
            severity=Severity.WARNING,
            count=len(no_filter),
            records=[{"name": r["name"], "table": r.get("collection", "N/A")} for r in no_filter[:10]],
            recommendation="Add filter conditions to limit when each rule fires. This reduces unnecessary server processing."
        ))

    if all_ops:
        findings.append(Finding(
            title="Business Rules Firing on All Operations",
            description=(
                f"{len(all_ops)} rules are set to fire on insert, update, delete, AND query simultaneously."
            ),
            severity=Severity.WARNING,
            count=len(all_ops),
            records=[{"name": r["name"], "table": r.get("collection", "N/A")} for r in all_ops[:10]],
            recommendation="Restrict each rule to only the operations it actually needs (e.g. insert only)."
        ))

    if inactive_rules:
        findings.append(Finding(
            title="Inactive Business Rules",
            description=f"{len(inactive_rules)} business rules are inactive and may be abandoned dead code.",
            severity=Severity.INFO,
            count=len(inactive_rules),
            records=[{"name": r["name"], "table": r.get("collection", "N/A")} for r in inactive_rules[:10]],
            recommendation="Review and delete inactive rules that are no longer needed to keep the platform clean."
        ))

    score = 100
    if total > 0:
        score -= min(30, int(len(no_filter) / total * 60))
        score -= min(20, int(len(all_ops) / total * 40))
    score -= min(10, len(inactive_rules) // 5)
    score = max(0, score)

    return AreaResult(
        name="Business Rules",
        score=score,
        findings=findings,
        raw_data={
            "total_active": total,
            "no_filter_condition": len(no_filter),
            "fires_on_all_ops": len(all_ops),
            "inactive": len(inactive_rules),
        }
    )
