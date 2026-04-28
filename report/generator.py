import json
import math
import re
from datetime import datetime
from scanner.models import AreaResult, Severity

_SYS_ID_RE = re.compile(r'^[0-9a-f]{32}$')


# ── Score / severity helpers ──────────────────────────────────────────────────

def _score_color(score):
    if score >= 75: return "#27ae60"
    if score >= 50: return "#e67e22"
    return "#e74c3c"

def _score_label(score):
    if score >= 75: return "Good"
    if score >= 50: return "Fair"
    return "Poor"

def _severity_order(sev):
    return {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}[sev]

def _severity_label(sev):
    return {Severity.CRITICAL: "Critical", Severity.WARNING: "Warning", Severity.INFO: "Info"}[sev]

def _severity_color(sev):
    return {Severity.CRITICAL: "#e74c3c", Severity.WARNING: "#e67e22", Severity.INFO: "#3498db"}[sev]

def _severity_bg(sev):
    return {Severity.CRITICAL: "#fdf3f3", Severity.WARNING: "#fef9f0", Severity.INFO: "#f0f7ff"}[sev]


# ── Record formatter ──────────────────────────────────────────────────────────

def _fmt(rec):
    """Convert a raw findings dict into a clean, readable string."""
    if not isinstance(rec, dict):
        return str(rec)

    # Incident records  {"number": "INC...", "description": "...", "days_open"?, "reassignments"?}
    if "number" in rec:
        line = rec["number"]
        desc = rec.get("description", "").strip()
        if desc:
            line += f" — {desc}"          # em-dash
        extras = []
        if "days_open" in rec:
            extras.append(f"open {rec['days_open']} days")
        if "reassignments" in rec:
            extras.append(f"reassigned {rec['reassignments']} times")
        if extras:
            line += f" ({', '.join(extras)})"
        return line

    # Script include records  {"name": ..., "api_name": ...}
    if "api_name" in rec:
        name = rec.get("name") or "(unnamed)"
        api  = rec.get("api_name", "")
        return f"{name} — {api}" if api else name

    # ACL records  {"name": ..., "operation": ..., "type"?}
    if "operation" in rec:
        name = rec.get("name") or "(unnamed)"
        op   = rec.get("operation", "")
        kind = rec.get("type", "")
        parts = []
        if op and not _SYS_ID_RE.match(str(op)):
            parts.append(f"op: {op}")
        if kind:
            parts.append(kind)
        return f"{name} ({', '.join(parts)})" if parts else name

    # Business rule / client script records  {"name": ..., "table": ..., "type"?}
    if "name" in rec:
        name    = rec.get("name") or "(unnamed)"
        table   = rec.get("table", "")
        stype   = rec.get("type", "")       # e.g. onChange, onLoad
        details = []
        if table and table not in ("N/A", ""):
            details.append(f"table: {table}")
        if stype:
            details.append(stype)
        return f"{name} ({', '.join(details)})" if details else name

    # CI records  {"sys_id": ..., "class": ...}
    if "sys_id" in rec:
        return f"Unnamed CI — class: {rec.get('class', '?')}"

    # Fallback: any non-empty values joined
    parts = [str(v) for v in rec.values() if v and str(v) not in ("N/A", "")]
    return " · ".join(parts) if parts else "(no detail)"


# ── Gauge SVG ─────────────────────────────────────────────────────────────────

def _gauge_svg(score):
    color = _score_color(score)
    r = 78
    cx = cy = 105
    circumference = 2 * math.pi * r
    filled = (score / 100) * circumference
    gap    = circumference - filled
    return f"""<svg viewBox="0 0 210 210" width="210" height="210" style="display:block;margin:auto">
      <circle cx="{cx}" cy="{cy}" r="{r}" fill="none"
              stroke="rgba(255,255,255,0.12)" stroke-width="16"/>
      <circle cx="{cx}" cy="{cy}" r="{r}" fill="none"
              stroke="{color}" stroke-width="16"
              stroke-dasharray="{filled:.2f} {gap:.2f}"
              stroke-linecap="round"
              transform="rotate(-90 {cx} {cy})"/>
      <text x="{cx}" y="{cy - 10}" text-anchor="middle" fill="white"
            font-size="44" font-weight="700"
            font-family="Segoe UI,Arial,sans-serif">{score}</text>
      <text x="{cx}" y="{cy + 16}" text-anchor="middle" fill="rgba(255,255,255,0.55)"
            font-size="13" font-family="Segoe UI,Arial,sans-serif">out of 100</text>
      <text x="{cx}" y="{cy + 38}" text-anchor="middle" fill="{color}"
            font-size="14" font-weight="700"
            font-family="Segoe UI,Arial,sans-serif"
            letter-spacing="1">{_score_label(score).upper()}</text>
    </svg>"""


# ── Executive summary ─────────────────────────────────────────────────────────

def _executive_summary(results, overall, instance_url):
    n_crit = sum(1 for r in results for f in r.findings if f.severity == Severity.CRITICAL)
    n_warn = sum(1 for r in results for f in r.findings if f.severity == Severity.WARNING)
    n_info = sum(1 for r in results for f in r.findings if f.severity == Severity.INFO)
    n_total = n_crit + n_warn + n_info
    worst = min(results, key=lambda r: r.score)
    best  = max(results, key=lambda r: r.score)
    domain = instance_url.replace("https://", "").replace("http://", "") or "the target instance"

    if overall >= 75:
        stance = "demonstrates a generally healthy configuration with targeted areas for improvement"
    elif overall >= 50:
        stance = "reveals a platform requiring moderate remediation across multiple domains"
    else:
        stance = "identifies critical systemic risks that warrant immediate remediation"

    paras = []
    paras.append(
        f"This automated health assessment of <strong>{domain}</strong> {stance}. "
        f"Across <strong>{len(results)} evaluated domains</strong>, the scan identified "
        f"<strong>{n_total} findings</strong>: {n_crit} critical, {n_warn} warnings, "
        f"and {n_info} informational items."
    )

    obs = []
    acl = next((r for r in results if r.name == "ACLs"), None)
    if acl and acl.score < 60:
        open_n = acl.raw_data.get("fully_open", 0)
        wc_n   = acl.raw_data.get("wildcard", 0)
        obs.append(
            f"The Access Control configuration carries the highest risk profile: "
            f"<strong>{open_n} ACL rules carry no role, condition, or script restriction</strong>, "
            f"and {wc_n} wildcard ACLs grant system-wide access. "
            f"Note that a portion of these are likely ServiceNow out-of-box defaults "
            f"and should be reviewed in context before remediation."
        )

    inc = next((r for r in results if r.name == "Incidents"), None)
    if inc:
        crit_open = inc.raw_data.get("critical_open", 0)
        aging     = inc.raw_data.get("aging_over_30d", 0)
        high_ra   = inc.raw_data.get("high_reassignment", 0)
        if crit_open > 0 or aging > 0:
            obs.append(
                f"Operationally, <strong>{crit_open} critical-priority incidents remain unresolved</strong> "
                f"and {aging} incidents have exceeded the 30-day aging threshold. "
                f"A further {high_ra} incident{'s' if high_ra != 1 else ''} "
                f"ha{'ve' if high_ra != 1 else 's'} been reassigned more than three times, "
                f"indicating routing inefficiencies."
            )

    br = next((r for r in results if r.name == "Business Rules"), None)
    if br and br.raw_data.get("no_filter_condition", 0) > 50:
        nf = br.raw_data["no_filter_condition"]
        obs.append(
            f"<strong>{nf} active business rules execute without filter conditions</strong>, "
            f"triggering on every qualifying table operation. Many may be OOB platform rules; "
            f"custom rules without filters should be prioritised for review."
        )

    cs = next((r for r in results if r.name == "Client Scripts"), None)
    if cs and cs.raw_data.get("uses_glide_record", 0) > 0:
        gr = cs.raw_data["uses_glide_record"]
        obs.append(
            f"End-user experience is at risk from <strong>{gr} client scripts invoking "
            f"GlideRecord directly in the browser</strong>, causing synchronous server calls "
            f"that freeze the UI during form interactions."
        )

    if obs:
        paras.append(" ".join(obs))

    paras.append(
        f"The <strong>{best.name}</strong> domain scored highest at {best.score}/100, "
        f"while <strong>{worst.name}</strong> requires the most urgent attention at {worst.score}/100. "
        f"The prioritised action plan below identifies the highest-impact remediation steps."
    )

    return "".join(f'<p style="margin-bottom:14px">{p}</p>' for p in paras)


# ── Critical actions ──────────────────────────────────────────────────────────

def _critical_actions(results):
    all_f = sorted(
        ((r.name, f) for r in results for f in r.findings),
        key=lambda x: (_severity_order(x[1].severity), -x[1].count)
    )
    html = ""
    for i, (area, f) in enumerate(all_f[:5], 1):
        c = _severity_color(f.severity)
        html += f"""
        <div style="display:flex;align-items:flex-start;gap:20px;padding:20px 22px;
                    border-left:5px solid {c};background:#fff;border-radius:8px;
                    box-shadow:0 1px 6px rgba(0,0,0,0.07);margin-bottom:14px">
          <div style="font-size:32px;font-weight:800;color:{c};min-width:38px;line-height:1;margin-top:2px">{i}</div>
          <div style="flex:1">
            <div style="font-size:11px;font-weight:700;color:{c};text-transform:uppercase;
                        letter-spacing:0.8px;margin-bottom:3px">
              {_severity_label(f.severity)}&nbsp;&nbsp;&middot;&nbsp;&nbsp;{area}
            </div>
            <div style="font-weight:700;color:#1e2d4e;font-size:16px;margin-bottom:5px">{f.title}</div>
            <div style="color:#555;font-size:14px;line-height:1.55">{f.recommendation}</div>
          </div>
          <div style="text-align:center;min-width:54px;padding:8px;
                      background:{_severity_bg(f.severity)};border-radius:8px">
            <div style="font-size:26px;font-weight:700;color:{c};line-height:1">{f.count}</div>
            <div style="font-size:11px;color:#888;margin-top:2px">found</div>
          </div>
        </div>"""
    return html


# ── Health overview table ─────────────────────────────────────────────────────

def _overview_table(results):
    rows = ""
    for r in sorted(results, key=lambda x: x.score):
        c     = _score_color(r.score)
        label = _score_label(r.score)
        n_crit = sum(1 for f in r.findings if f.severity == Severity.CRITICAL)
        n_warn = sum(1 for f in r.findings if f.severity == Severity.WARNING)
        badges  = ""
        if n_crit:
            badges += f'<span class="badge badge-critical">{n_crit} Critical</span> '
        if n_warn:
            badges += f'<span class="badge badge-warning">{n_warn} Warning</span>'
        if not badges:
            badges = '<span class="badge badge-ok">No Issues</span>'
        rows += f"""
        <tr>
          <td style="padding:14px 18px;font-weight:600;color:#1e2d4e;width:150px">{r.name}</td>
          <td style="padding:14px 18px">
            <div style="background:#eceff1;border-radius:20px;height:14px;max-width:320px;overflow:hidden">
              <div style="background:{c};width:{r.score}%;height:14px;border-radius:20px"></div>
            </div>
          </td>
          <td style="padding:14px 18px;font-weight:700;color:{c};width:70px">{r.score}/100</td>
          <td style="padding:14px 18px;width:220px">{badges}</td>
          <td style="padding:14px 18px;color:#6c757d;font-size:13px;width:70px">{label}</td>
        </tr>"""
    return rows


# ── Per-area findings table ───────────────────────────────────────────────────

def _findings_table(result):
    if not result.findings:
        return """<div style="padding:20px;color:#6c757d;font-style:italic;text-align:center">
                    No issues detected in this domain.</div>"""
    rows = ""
    for f in sorted(result.findings, key=lambda x: _severity_order(x.severity)):
        c   = _severity_color(f.severity)
        bg  = _severity_bg(f.severity)
        lbl = _severity_label(f.severity)

        example_html = ""
        if f.records:
            items = "".join(
                f'<li style="color:#444;font-size:13px;padding:2px 0">{_fmt(rec)}</li>'
                for rec in f.records[:5]
            )
            example_html = (
                '<div style="margin-top:8px">'
                '<div style="font-size:11px;font-weight:700;color:#999;text-transform:uppercase;'
                'letter-spacing:0.5px;margin-bottom:4px">Examples</div>'
                f'<ul style="margin:0 0 0 16px;padding:0;list-style:disc">{items}</ul></div>'
            )

        rows += f"""
        <tr style="border-bottom:1px solid #eef0f3">
          <td style="padding:14px 16px;vertical-align:top;width:96px">
            <span style="background:{c};color:#fff;padding:4px 10px;border-radius:4px;
                         font-size:11px;font-weight:700;text-transform:uppercase;
                         letter-spacing:0.5px;white-space:nowrap">{lbl}</span>
          </td>
          <td style="padding:14px 16px;vertical-align:top">
            <div style="font-weight:700;color:#1e2d4e;font-size:15px;margin-bottom:4px">{f.title}</div>
            <div style="color:#555;font-size:13px;line-height:1.55">{f.description}</div>
            {example_html}
          </td>
          <td style="padding:14px 16px;vertical-align:top;text-align:center;width:64px">
            <div style="background:{bg};border-radius:8px;padding:8px 4px">
              <div style="font-size:22px;font-weight:700;color:{c};line-height:1">{f.count}</div>
              <div style="font-size:11px;color:#999">found</div>
            </div>
          </td>
          <td style="padding:14px 16px;vertical-align:top;max-width:260px">
            <div style="font-size:11px;font-weight:700;color:#27ae60;text-transform:uppercase;
                        letter-spacing:0.5px;margin-bottom:4px">Recommendation</div>
            <div style="color:#444;font-size:13px;line-height:1.55">{f.recommendation}</div>
          </td>
        </tr>"""

    return f"""
    <table style="width:100%;border-collapse:collapse">
      <thead>
        <tr style="background:#f8f9fa;border-bottom:2px solid #dee2e6">
          <th class="sortable" style="padding:11px 16px;cursor:pointer;width:96px"
              onclick="sortTable(this)">Severity &#8597;</th>
          <th class="sortable" style="padding:11px 16px;cursor:pointer"
              onclick="sortTable(this)">Finding &#8597;</th>
          <th class="sortable" style="padding:11px 16px;cursor:pointer;width:64px;text-align:center"
              onclick="sortTable(this)">Count &#8597;</th>
          <th style="padding:11px 16px">Recommendation</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>"""


# ── Scan metadata card ────────────────────────────────────────────────────────

def _scan_metadata_card(metadata):
    if not metadata:
        return ""

    secs = int(metadata.get("duration_seconds", 0))
    mins, s = divmod(secs, 60)
    duration_str = f"{mins}m {s}s" if mins else f"{s}s"

    api_calls  = metadata.get("api_calls", "—")
    version    = metadata.get("snow_version", "Unknown")
    tables     = metadata.get("tables_scanned", [])

    # Shorten a long build-tag to something readable
    version_display = version
    if len(version) > 48:
        version_display = version[:45] + "..."

    table_pills = "".join(
        f'<span style="display:inline-block;background:#eef3ff;color:#3a5fd9;'
        f'border-radius:4px;padding:3px 10px;font-size:12px;margin:3px 4px 3px 0;'
        f'font-family:monospace">{t}</span>'
        for t in tables
    )

    def meta_box(value, label, color="#1e2d4e"):
        return (
            f'<div style="text-align:center;padding:18px 12px;background:#f8f9fa;'
            f'border-radius:8px;flex:1;min-width:120px">'
            f'<div style="font-size:26px;font-weight:700;color:{color};line-height:1">{value}</div>'
            f'<div style="font-size:12px;color:#888;margin-top:5px;letter-spacing:0.3px">{label}</div>'
            f'</div>'
        )

    return f"""
    <div class="card">
      <div class="card-title">
        <span style="font-size:20px">&#9881;</span> Scan Metadata
      </div>
      <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:20px">
        {meta_box(duration_str, "Scan Duration", "#0066cc")}
        {meta_box(api_calls, "API Calls Made", "#0066cc")}
        {meta_box(len(tables), "Tables Scanned", "#0066cc")}
      </div>
      <div style="margin-bottom:12px">
        <div style="font-size:12px;font-weight:700;color:#888;text-transform:uppercase;
                    letter-spacing:0.5px;margin-bottom:6px">ServiceNow Version</div>
        <div style="font-family:monospace;font-size:13px;color:#333;background:#f8f9fa;
                    display:inline-block;padding:5px 12px;border-radius:4px">{version_display}</div>
      </div>
      <div>
        <div style="font-size:12px;font-weight:700;color:#888;text-transform:uppercase;
                    letter-spacing:0.5px;margin-bottom:6px">Tables Scanned</div>
        <div>{table_pills}</div>
      </div>
    </div>"""


# ── Detailed findings sections ────────────────────────────────────────────────

def _detail_sections(results):
    html = ""
    for r in results:
        c     = _score_color(r.score)
        label = _score_label(r.score)
        n_crit = sum(1 for f in r.findings if f.severity == Severity.CRITICAL)
        n_warn = sum(1 for f in r.findings if f.severity == Severity.WARNING)
        n_info = sum(1 for f in r.findings if f.severity == Severity.INFO)
        html += f"""
        <div style="margin-bottom:40px">
          <div style="display:flex;align-items:center;gap:16px;
                      margin-bottom:18px;padding-bottom:14px;border-bottom:2px solid #eef0f3">
            <div>
              <h3 style="margin:0;color:#1e2d4e;font-size:20px;font-weight:700">{r.name}</h3>
              <div style="font-size:13px;color:#888;margin-top:2px">
                {n_crit} critical &nbsp;&middot;&nbsp; {n_warn} warnings &nbsp;&middot;&nbsp; {n_info} info
              </div>
            </div>
            <div style="margin-left:auto;display:flex;align-items:center;gap:12px">
              <div style="font-size:28px;font-weight:700;color:{c}">{r.score}/100</div>
              <span style="background:{c};color:#fff;padding:5px 14px;border-radius:20px;
                           font-size:13px;font-weight:600">{label}</span>
            </div>
          </div>
          {_findings_table(r)}
        </div>"""
    return html


# ── Main public function ──────────────────────────────────────────────────────

def generate_report(results, overall_score, instance_url="",
                    output_path="health_report.html", metadata=None):
    scan_date  = datetime.now().strftime("%B %d, %Y")
    scan_time  = datetime.now().strftime("%H:%M")
    domain     = instance_url.replace("https://", "").replace("http://", "") or "ServiceNow Instance"

    n_critical = sum(1 for r in results for f in r.findings if f.severity == Severity.CRITICAL)
    n_warning  = sum(1 for r in results for f in r.findings if f.severity == Severity.WARNING)
    n_info     = sum(1 for r in results for f in r.findings if f.severity == Severity.INFO)

    gauge_svg    = _gauge_svg(overall_score)
    exec_sum     = _executive_summary(results, overall_score, instance_url)
    crit_html    = _critical_actions(results)
    overview     = _overview_table(results)
    detail_html  = _detail_sections(results)
    metadata_card = _scan_metadata_card(metadata)

    area_names  = json.dumps([r.name  for r in results])
    area_scores = json.dumps([r.score for r in results])
    area_colors = json.dumps([_score_color(r.score) for r in results])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>ServiceNow Health Assessment &mdash; {domain}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    *, *::before, *::after {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{
      font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Arial, sans-serif;
      background: #f0f2f5; color: #333; font-size: 14px; line-height: 1.6;
    }}
    .container {{ max-width:1100px; margin:0 auto; padding:0 28px 60px; }}
    .card {{
      background:#fff; border-radius:12px;
      box-shadow:0 2px 16px rgba(0,0,0,0.07);
      padding:30px 32px; margin-bottom:28px;
    }}
    .card-title {{
      font-size:17px; font-weight:700; color:#1e2d4e;
      margin-bottom:22px; padding-bottom:14px;
      border-bottom:2px solid #f0f2f5;
      display:flex; align-items:center; gap:10px;
    }}
    .badge {{ display:inline-block; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:600; }}
    .badge-critical {{ background:#fde8e8; color:#c0392b; }}
    .badge-warning  {{ background:#fef3e2; color:#d35400; }}
    .badge-ok       {{ background:#e8f8f0; color:#1e8449; }}
    .metric-pill {{
      text-align:center; padding:18px 24px;
      background:rgba(255,255,255,0.10);
      border-radius:10px; flex:1; min-width:100px;
    }}
    .metric-value {{ font-size:34px; font-weight:700; line-height:1; }}
    .metric-label {{ font-size:12px; margin-top:5px; opacity:0.75; letter-spacing:0.3px; }}
    th {{ font-weight:600; color:#1e2d4e; font-size:13px; text-align:left; }}
    tr:hover td {{ background:#f9fbff !important; }}
    .sortable {{ user-select:none; cursor:pointer; }}
    .sortable:hover {{ background:#e9ecef !important; }}
    @media print {{
      body {{ background:white; }}
      .card {{ box-shadow:none; border:1px solid #e0e0e0; }}
    }}
  </style>
</head>
<body>

<!-- DISCLAIMER BANNER -->
<div style="background:#fff8e1;border-bottom:3px solid #ffc107;padding:10px 0">
  <div class="container" style="padding-top:0;padding-bottom:0">
    <div style="display:flex;align-items:flex-start;gap:10px;font-size:13px;color:#5d4037;line-height:1.5">
      <span style="font-size:16px;flex-shrink:0">&#9432;</span>
      <span>
        <strong>Note:</strong> Many findings &mdash; especially ACLs without restrictions and business rules
        without filter conditions &mdash; may be out-of-box ServiceNow defaults, not custom misconfigurations.
        A qualified administrator should review which findings apply to custom work versus platform defaults
        before taking remediation action.
      </span>
    </div>
  </div>
</div>

<!-- HEADER -->
<div style="background:linear-gradient(135deg,#0d1f3c 0%,#162e52 60%,#1a3a5c 100%);
            color:#fff;padding-bottom:48px">

  <div style="background:rgba(0,0,0,0.25);padding:14px 0;margin-bottom:44px">
    <div class="container" style="display:flex;justify-content:space-between;
                                   align-items:center;padding-top:0;padding-bottom:0">
      <div style="font-size:20px;font-weight:700;letter-spacing:-0.3px">
        <span style="color:#4da6ff;margin-right:8px">&#11044;</span>ServiceNow Health Assessment
      </div>
      <div style="font-size:12px;opacity:0.6;text-align:right">
        {domain}<br>{scan_date} at {scan_time}
      </div>
    </div>
  </div>

  <div class="container" style="padding-top:0;padding-bottom:0">
    <div style="display:flex;align-items:center;gap:52px;flex-wrap:wrap">
      <div style="min-width:210px">
        {gauge_svg}
        <div style="text-align:center;font-size:12px;opacity:0.5;margin-top:-4px;letter-spacing:0.3px">
          OVERALL HEALTH SCORE
        </div>
      </div>
      <div style="flex:1;min-width:300px">
        <h1 style="font-size:30px;font-weight:700;letter-spacing:-0.5px;margin-bottom:6px">
          Instance Health Report
        </h1>
        <p style="opacity:0.6;font-size:15px;margin-bottom:30px">
          Automated configuration &amp; operational analysis across {len(results)} domains
        </p>
        <div style="display:flex;gap:14px;flex-wrap:wrap">
          <div class="metric-pill" style="border:1px solid rgba(231,76,60,0.35)">
            <div class="metric-value" style="color:#ff6b6b">{n_critical}</div>
            <div class="metric-label">Critical Issues</div>
          </div>
          <div class="metric-pill" style="border:1px solid rgba(230,126,22,0.35)">
            <div class="metric-value" style="color:#ffa94d">{n_warning}</div>
            <div class="metric-label">Warnings</div>
          </div>
          <div class="metric-pill" style="border:1px solid rgba(77,166,255,0.35)">
            <div class="metric-value" style="color:#74c0fc">{n_info}</div>
            <div class="metric-label">Info Items</div>
          </div>
          <div class="metric-pill" style="border:1px solid rgba(255,255,255,0.18)">
            <div class="metric-value" style="color:#fff">{len(results)}</div>
            <div class="metric-label">Domains Scanned</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div><!-- /header -->


<div class="container" style="margin-top:-24px">

  <!-- PRINT BUTTON -->
  <div style="text-align:right;padding:16px 0 4px">
    <button onclick="window.print()"
            style="background:#fff;border:1px solid #d0d7de;color:#555;
                   padding:7px 18px;border-radius:6px;font-size:13px;font-weight:500;
                   cursor:pointer;box-shadow:0 1px 3px rgba(0,0,0,0.06);
                   display:inline-flex;align-items:center;gap:7px;transition:all 0.15s"
            onmouseover="this.style.background='#f6f8fa';this.style.boxShadow='0 2px 8px rgba(0,0,0,0.10)'"
            onmouseout="this.style.background='#fff';this.style.boxShadow='0 1px 3px rgba(0,0,0,0.06)'">
      &#9113; Print / Export PDF
    </button>
  </div>

  <!-- EXECUTIVE SUMMARY -->
  <div class="card">
    <div class="card-title">
      <span style="color:#0066cc;font-size:20px">&#9670;</span> Executive Summary
    </div>
    <div style="color:#444;line-height:1.85;font-size:14.5px">{exec_sum}</div>
  </div>

  <!-- SCAN METADATA -->
  {metadata_card}

  <!-- CRITICAL ACTIONS -->
  <div class="card">
    <div class="card-title">
      <span style="color:#e74c3c;font-size:20px">&#9888;</span>
      Critical Actions &mdash; Top 5 Priorities
    </div>
    <div style="font-size:13px;color:#888;margin-bottom:18px;margin-top:-12px">
      Address these items in order to achieve the greatest improvement in health score.
    </div>
    {crit_html}
  </div>

  <!-- HEALTH OVERVIEW -->
  <div class="card">
    <div class="card-title">
      <span style="color:#27ae60;font-size:20px">&#9776;</span> Health Overview by Domain
    </div>
    <table>
      <thead>
        <tr style="background:#f8f9fa;border-bottom:2px solid #dee2e6">
          <th style="padding:11px 18px">Domain</th>
          <th style="padding:11px 18px">Score</th>
          <th style="padding:11px 18px;width:80px">Value</th>
          <th style="padding:11px 18px">Findings</th>
          <th style="padding:11px 18px;width:80px">Status</th>
        </tr>
      </thead>
      <tbody>{overview}</tbody>
    </table>
  </div>

  <!-- CHARTS -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:28px;margin-bottom:28px">
    <div class="card" style="margin:0">
      <div class="card-title"><span style="font-size:20px">&#9685;</span> Domain Health Scores</div>
      <canvas id="barChart" style="max-height:240px"></canvas>
    </div>
    <div class="card" style="margin:0">
      <div class="card-title"><span style="font-size:20px">&#9685;</span> Findings by Severity</div>
      <canvas id="donutChart" style="max-height:240px"></canvas>
    </div>
  </div>

  <!-- DETAILED FINDINGS -->
  <div class="card">
    <div class="card-title">
      <span style="color:#1a3a5c;font-size:20px">&#9881;</span> Detailed Findings
      <span style="font-weight:400;font-size:13px;color:#888;margin-left:4px">
        &mdash; click column headers to sort
      </span>
    </div>
    {detail_html}
  </div>

  <!-- FOOTER -->
  <div style="text-align:center;color:#aaa;font-size:12px;padding:12px 0 0;line-height:1.8">
    <strong style="color:#888">
      ServiceNow Instance Health Scanner v1.0 &mdash; Built with Python + ServiceNow REST API
    </strong><br>
    Report generated {scan_date} at {scan_time} &nbsp;&middot;&nbsp; {domain}<br>
    This report is produced automatically. Findings should be reviewed by a qualified ServiceNow administrator.
  </div>

</div><!-- /container -->

<script>
new Chart(document.getElementById('barChart'), {{
  type: 'bar',
  data: {{
    labels: {area_names},
    datasets: [{{
      label: 'Health Score',
      data: {area_scores},
      backgroundColor: {area_colors},
      borderRadius: 8,
      borderSkipped: false
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{
      legend: {{ display: false }},
      tooltip: {{ callbacks: {{ label: ctx => ` Score: ${{ctx.parsed.y}}/100` }} }}
    }},
    scales: {{
      y: {{ min:0, max:100, grid:{{ color:'#f0f2f5' }},
             ticks:{{ callback: v => v+'/100', font:{{ size:12 }} }} }},
      x: {{ grid:{{ display:false }}, ticks:{{ font:{{ size:12 }} }} }}
    }}
  }}
}});

new Chart(document.getElementById('donutChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['Critical', 'Warning', 'Info'],
    datasets: [{{
      data: [{n_critical}, {n_warning}, {n_info}],
      backgroundColor: ['#e74c3c', '#e67e22', '#3498db'],
      borderWidth: 3, borderColor: '#fff', hoverOffset: 10
    }}]
  }},
  options: {{
    responsive: true, cutout: '68%',
    plugins: {{
      legend: {{ position:'bottom', labels:{{ padding:20, font:{{ size:13 }}, usePointStyle:true }} }},
      tooltip: {{ callbacks: {{ label: ctx => ` ${{ctx.label}}: ${{ctx.parsed}} finding${{ctx.parsed!==1?'s':''}}` }} }}
    }}
  }}
}});

const SEV_ORDER = {{ Critical:0, Warning:1, Info:2 }};
function sortTable(th) {{
  const tbody = th.closest('table').querySelector('tbody');
  const rows  = Array.from(tbody.querySelectorAll('tr'));
  const col   = Array.from(th.parentElement.children).indexOf(th);
  const asc   = th.dataset.asc !== 'true';
  th.dataset.asc = asc;
  rows.sort((a, b) => {{
    const at = (a.cells[col]?.innerText || '').trim();
    const bt = (b.cells[col]?.innerText || '').trim();
    if (col === 0 && (at in SEV_ORDER || bt in SEV_ORDER))
      return asc ? (SEV_ORDER[at]??9)-(SEV_ORDER[bt]??9) : (SEV_ORDER[bt]??9)-(SEV_ORDER[at]??9);
    const an = parseFloat(at), bn = parseFloat(bt);
    if (!isNaN(an) && !isNaN(bn)) return asc ? an-bn : bn-an;
    return asc ? at.localeCompare(bt) : bt.localeCompare(at);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path
