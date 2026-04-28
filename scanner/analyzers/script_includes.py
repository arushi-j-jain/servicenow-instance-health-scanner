from ..client import ServiceNowClient
from ..models import AreaResult, Finding, Severity


def analyze(client: ServiceNowClient) -> AreaResult:
    findings = []
    fields = ["name", "active", "api_name", "access"]

    all_records = client.get_records("sys_script_include", fields=fields)
    active   = [r for r in all_records if str(r.get("active", "")).lower() == "true"]
    inactive = [r for r in all_records if str(r.get("active", "")).lower() != "true"]

    # Duplicate names among active script includes
    names = [r.get("name", "").strip() for r in active]
    duplicate_names = {n for n in names if names.count(n) > 1}
    duplicates = [r for r in active if r.get("name", "").strip() in duplicate_names]

    # Public script includes are accessible without a login
    public_si = [r for r in active if r.get("access", "") == "public"]

    if inactive:
        findings.append(Finding(
            title="Inactive Script Includes",
            description=f"{len(inactive)} script includes are inactive and may be dead code cluttering the platform.",
            severity=Severity.WARNING,
            count=len(inactive),
            records=[{"name": r["name"], "api_name": r.get("api_name", "")} for r in inactive[:10]],
            recommendation="Review inactive script includes and delete any that are no longer called by other scripts."
        ))

    if duplicates:
        findings.append(Finding(
            title="Duplicate Script Include Names",
            description=(
                f"{len(duplicates)} active script includes share names with others: "
                f"{', '.join(list(duplicate_names)[:5])}. "
                "ServiceNow loads only one — behavior becomes unpredictable."
            ),
            severity=Severity.CRITICAL,
            count=len(duplicates),
            records=[{"name": r["name"], "api_name": r.get("api_name", "")} for r in duplicates[:10]],
            recommendation="Consolidate or rename duplicate script includes immediately to ensure predictable behavior."
        ))

    if public_si:
        findings.append(Finding(
            title="Publicly Accessible Script Includes",
            description=f"{len(public_si)} script includes are set to 'public' access (usable without login).",
            severity=Severity.WARNING,
            count=len(public_si),
            records=[{"name": r["name"]} for r in public_si[:10]],
            recommendation="Change access to 'private' unless the script is explicitly needed by unauthenticated users."
        ))

    total = len(all_records)
    score = 100
    if total > 0:
        score -= min(20, int(len(inactive) / total * 40))
    score -= min(30, len(duplicates) * 10)
    if active:
        score -= min(20, int(len(public_si) / len(active) * 40))
    score = max(0, score)

    return AreaResult(
        name="Script Includes",
        score=score,
        findings=findings,
        raw_data={
            "total": total,
            "active": len(active),
            "inactive": len(inactive),
            "duplicates": len(duplicates),
            "public_access": len(public_si),
        }
    )
