from ..client import ServiceNowClient
from ..models import AreaResult, Finding, Severity


def analyze(client: ServiceNowClient) -> AreaResult:
    findings = []
    fields = ["name", "table", "active", "script", "type"]

    active_scripts = client.get_records("sys_script_client", fields=fields, query="active=true")
    inactive_scripts = client.get_records("sys_script_client", fields=["name", "table", "type"], query="active=false")
    total = len(active_scripts)

    # GlideRecord on the client side makes a synchronous server round-trip — freezes the browser
    glide_record = [r for r in active_scripts if "GlideRecord" in r.get("script", "")]

    # Synchronous GlideAjax calls also block the UI
    sync_ajax = [
        r for r in active_scripts
        if "getXMLAnswer(" in r.get("script", "") or "getXML(" in r.get("script", "")
    ]

    if glide_record:
        findings.append(Finding(
            title="Client Scripts Using GlideRecord",
            description=(
                f"{len(glide_record)} client scripts use GlideRecord directly. "
                "This makes a synchronous (blocking) server call from the browser, freezing the UI for the user."
            ),
            severity=Severity.CRITICAL,
            count=len(glide_record),
            records=[
                {"name": r["name"], "table": r.get("table", "N/A"), "type": r.get("type", "")}
                for r in glide_record[:10]
            ],
            recommendation="Replace GlideRecord with asynchronous GlideAjax calls so the browser doesn't freeze."
        ))

    if sync_ajax:
        findings.append(Finding(
            title="Synchronous GlideAjax Calls",
            description=(
                f"{len(sync_ajax)} scripts use getXML() or getXMLAnswer(), which are synchronous "
                "GlideAjax patterns that block the browser UI."
            ),
            severity=Severity.WARNING,
            count=len(sync_ajax),
            records=[{"name": r["name"], "table": r.get("table", "N/A")} for r in sync_ajax[:10]],
            recommendation="Convert these to use a callback function with getXML(callback) instead."
        ))

    if inactive_scripts:
        findings.append(Finding(
            title="Inactive Client Scripts",
            description=f"{len(inactive_scripts)} client scripts are inactive.",
            severity=Severity.INFO,
            count=len(inactive_scripts),
            records=[{"name": r["name"], "table": r.get("table", "N/A")} for r in inactive_scripts[:10]],
            recommendation="Remove unused client scripts to reduce maintenance overhead."
        ))

    score = 100
    if total > 0:
        score -= min(40, int(len(glide_record) / total * 80))
        score -= min(20, int(len(sync_ajax) / total * 40))
    score -= min(10, len(inactive_scripts) // 5)
    score = max(0, score)

    return AreaResult(
        name="Client Scripts",
        score=score,
        findings=findings,
        raw_data={
            "total_active": total,
            "uses_glide_record": len(glide_record),
            "sync_ajax": len(sync_ajax),
            "inactive": len(inactive_scripts),
        }
    )
