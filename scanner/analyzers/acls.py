from ..client import ServiceNowClient
from ..models import AreaResult, Finding, Severity


def analyze(client: ServiceNowClient) -> AreaResult:
    findings = []
    fields = ["name", "type", "operation", "active", "roles", "condition", "script", "admin_overrides"]

    records = client.get_records("sys_security_acl", fields=fields, query="active=true")
    total = len(records)

    # Wildcard ACLs match any table — extremely broad
    wildcard = [r for r in records if r.get("name", "").startswith("*")]

    # No roles + no condition + no script = anyone can perform this operation
    fully_open = [
        r for r in records
        if not r.get("roles", "").strip()
        and not r.get("condition", "").strip()
        and not r.get("script", "").strip()
        and not r.get("name", "").startswith("*")
    ]

    # No roles at all (may rely purely on condition/script — weaker than role-based)
    no_roles = [
        r for r in records
        if not r.get("roles", "").strip()
        and not r.get("name", "").startswith("*")
        and r not in fully_open
    ]

    if wildcard:
        findings.append(Finding(
            title="Wildcard ACLs Found",
            description=(
                f"{len(wildcard)} ACLs use a wildcard (*) name, meaning they apply to every table "
                "in the system and grant very broad access."
            ),
            severity=Severity.CRITICAL,
            count=len(wildcard),
            records=[
                {"name": r["name"], "operation": r.get("operation", "N/A"), "type": r.get("type", "")}
                for r in wildcard[:10]
            ],
            recommendation="Replace wildcard ACLs with specific table-level rules to enforce least-privilege access."
        ))

    if fully_open:
        findings.append(Finding(
            title="ACLs With No Restrictions (Fully Open)",
            description=(
                f"{len(fully_open)} ACLs have no roles, conditions, or scripts — "
                "they grant the operation to everyone unconditionally."
            ),
            severity=Severity.CRITICAL,
            count=len(fully_open),
            records=[{"name": r["name"], "operation": r.get("operation", "N/A")} for r in fully_open[:10]],
            recommendation="Add role requirements or access conditions to restrict who can perform these operations."
        ))

    if no_roles:
        findings.append(Finding(
            title="ACLs Without Role Restrictions",
            description=(
                f"{len(no_roles)} ACLs have no roles defined. "
                "They rely solely on a condition or script for access control, which is harder to audit."
            ),
            severity=Severity.WARNING,
            count=len(no_roles),
            records=[{"name": r["name"], "operation": r.get("operation", "N/A")} for r in no_roles[:10]],
            recommendation="Where possible, add explicit role requirements in addition to any conditions or scripts."
        ))

    score = 100
    score -= min(40, len(wildcard) * 10)
    score -= min(40, len(fully_open) * 8)
    if total > 0:
        score -= min(10, int(len(no_roles) / total * 20))
    score = max(0, score)

    return AreaResult(
        name="ACLs",
        score=score,
        findings=findings,
        raw_data={
            "total_active": total,
            "wildcard": len(wildcard),
            "fully_open": len(fully_open),
            "no_roles": len(no_roles),
        }
    )
