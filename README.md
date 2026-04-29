# ServiceNow Instance Health Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776ab.svg)](https://python.org)
[![ServiceNow REST API](https://img.shields.io/badge/ServiceNow-REST%20API-81b5a1.svg)](https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/c_TableAPI)

> Scan your ServiceNow instance for configuration health issues, score each area 0–100, generate a shareable single-file HTML report, and push results into custom ServiceNow tables for live tracking — all in under 30 seconds.

---

## Sample Report

![Sample Report](screenshot.png)

---

## Features

| Domain | What it checks |
|---|---|
| **Business Rules** | Rules without filter conditions (fires on every record), rules triggering all operations simultaneously, inactive/dead rules |
| **Client Scripts** | Scripts using `GlideRecord` (synchronous browser freeze), synchronous `GlideAjax` calls, inactive scripts |
| **Script Includes** | Inactive includes, duplicate names (unpredictable load order), publicly accessible includes |
| **ACLs** | Wildcard ACLs, rules with zero restrictions (no role/condition/script), rules missing role assignments |
| **Incidents** | Open critical incidents, aging tickets (>30 days), high reassignment counts |

## Outputs

Every `python main.py` run produces two outputs automatically:

### 1. HTML Report (auto-opens in browser)
- Overall health score (0–100) displayed as a circular gauge
- Executive summary written in consultant-style language, referencing your real numbers
- Top 5 prioritised actions ranked by severity and count
- Color-coded health bars per domain (green / amber / red)
- Bar chart of domain scores + donut chart of findings by severity
- Sortable findings tables with examples and recommendations
- Scan metadata: duration, API call count, ServiceNow version, tables scanned
- Disclaimer banner distinguishing OOB defaults from custom misconfigurations
- `--anonymize` flag to redact the instance URL for safe sharing

### 2. ServiceNow Custom Tables (live tracking)
After running `python setup_dashboard.py` once to create the tables, every scan automatically pushes results into two custom tables in your instance:

| Table | What it stores | Direct URL |
|---|---|---|
| `u_health_scan_results` | One row per scan per domain — date, scores, finding counts | `your-instance.service-now.com/sn_ap_apm_u_health_scan_results.list` |
| `u_health_scan_findings` | One row per finding — severity, title, description, recommendation | `your-instance.service-now.com/sn_ap_apm_u_health_scan_findings.list` |

> **Note:** ServiceNow automatically prefixes table names with your instance's application scope. If your scope is `sn_ap_apm`, the tables will be named `sn_ap_apm_u_health_scan_results` and `sn_ap_apm_u_health_scan_findings`. The scanner detects and uses whatever names your instance creates.

You can filter, sort, and export from these tables directly, or use them as data sources for your own reports and dashboards.

---

## Prerequisites

- **Python 3.10 or later** — [python.org/downloads](https://www.python.org/downloads/)
- **A ServiceNow instance** with REST API access — a free [Personal Developer Instance (PDI)](https://developer.servicenow.com/dev.do#!/guides/washingtondc/now-platform/pdi-guide/personal-developer-instance-guide-introduction) works perfectly
- **Admin credentials** (or a user with read access to `sys_script`, `sys_script_client`, `sys_script_include`, `sys_security_acl`, `incident`, and `sys_properties`)
- **Internet access** at report-open time (Chart.js loads from a CDN — no build step required)

---

## Quick Start

### 1. Get the code

```bash
git clone https://github.com/your-username/servicenow-health-scanner.git
cd servicenow-health-scanner
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

Installs: `requests`, `python-dotenv`. No other dependencies.

### 3. Configure your credentials

```bash
cp .env.example .env
```

Open `.env` and fill in your instance details:

```env
SNOW_INSTANCE=https://your-instance.service-now.com
SNOW_USERNAME=admin
SNOW_PASSWORD=your_password_here
```

> `.env` is listed in `.gitignore` and will never be committed.

### 4. Verify your connection

```bash
python test_connection.py
```

You should see 5 recent incidents printed to the terminal. If you get an authentication error, double-check your password.

### 5. (Optional) Set up ServiceNow tracking tables

To push scan results into your ServiceNow instance for live tracking, run this once:

```bash
python setup_dashboard.py
```

This creates two custom tables (`u_health_scan_results` and `u_health_scan_findings`) in your instance. After setup, every `python main.py` run automatically pushes results into those tables. You can view them at:

```
https://your-instance.service-now.com/sn_ap_apm_u_health_scan_results.list
https://your-instance.service-now.com/sn_ap_apm_u_health_scan_findings.list
```

If the tables can't be created via API (some instances restrict this), the script prints exact manual instructions for creating them in under 5 minutes via **System Definition > Tables**.

### 6. Run the full scan

```bash
python main.py
```

The scan takes 15–40 seconds. When it completes:
- The HTML report is saved as `health_report.html` and **opens automatically in your browser**
- If the tracking tables are set up, results are pushed to ServiceNow automatically

### 7. Share safely

To generate a report with the instance URL redacted (for screenshots or demos):

```bash
python main.py --anonymize
```

---

## How It Works

```
.env
 └─ SNOW_INSTANCE / SNOW_USERNAME / SNOW_PASSWORD
        │
        ▼
  ServiceNowClient          (scanner/client.py)
  requests.Session + Basic Auth
  call_count tracker + get_version()
        │
        ├── business_rules.analyze()   → sys_script
        ├── client_scripts.analyze()   → sys_script_client
        ├── script_includes.analyze()  → sys_script_include
        ├── acls.analyze()             → sys_security_acl
        └── incidents.analyze()        → incident
                │
                ▼
        List[AreaResult]
        score: int (0-100)
        findings: List[Finding]
          ├── title, description, severity
          ├── count, records (examples)
          └── recommendation
                │
                ▼
        Weighted overall score
        ACLs × 2.0, Incidents × 2.0
        Business Rules × 1.5, Client Scripts × 1.5
        Script Includes × 1.0
                │
                ▼
        report/generator.py
        Single self-contained HTML file
        Chart.js (CDN) + inline CSS + vanilla JS
```

Each analyzer is a standalone Python module in `scanner/analyzers/`. Adding a new area means creating one new file — the rest of the pipeline picks it up automatically.

---

## Project Structure

```
servicenow-health-scanner/
├── main.py                       # Orchestrator: scan → score → report → push
├── setup_dashboard.py            # One-time setup: creates custom tables + reports
├── run_setup.py                  # Single command: setup + first scan + push
├── fix_fields.py                 # Diagnostic: verify and repair custom table fields
├── test_connection.py            # Quick connectivity check
├── requirements.txt
├── .env.example                  # Credential template
├── .env                          # Your credentials (git-ignored)
├── health_report.html            # Generated report (git-ignored)
│
├── scanner/
│   ├── client.py                 # ServiceNow REST API client
│   ├── models.py                 # AreaResult + Finding + Severity
│   ├── pusher.py                 # Pushes results to custom ServiceNow tables
│   └── analyzers/
│       ├── business_rules.py     # Queries sys_script
│       ├── client_scripts.py     # Queries sys_script_client
│       ├── script_includes.py    # Queries sys_script_include
│       ├── acls.py               # Queries sys_security_acl
│       └── incidents.py          # Queries incident
│
└── report/
    └── generator.py              # HTML report with charts + sortable tables
```

---

## Roadmap

The following areas are planned for future releases:

- [ ] **CMDB Scanner** — orphan CIs, duplicate configuration items, missing mandatory fields, stale discovery records
- [ ] **Change Request Analysis** — success/failure rate, CAB approval trends, emergency change frequency
- [ ] **SLA Health** — breached SLAs by priority, SLA definition coverage gaps
- [ ] **Trend Tracking** — store scan results in SQLite and display score delta between runs
- [ ] **Multi-instance Comparison** — scan two instances side-by-side (e.g. dev vs prod)
- [ ] **Web Dashboard** — lightweight Flask UI for continuous monitoring with auto-refresh
- [ ] **PDF Export** — headless Chrome / Playwright integration for one-click PDF generation
- [ ] **Scheduled Scans** — built-in scheduler to run nightly and email the report

---

## A Note on OOB Findings

ServiceNow ships with hundreds of built-in business rules, ACLs, and script includes. Many findings flagged by this tool — particularly ACLs without restrictions and business rules without filter conditions — are **out-of-box platform defaults**, not custom misconfigurations.

The scanner flags them because they represent real patterns worth understanding, but **remediation should target custom or upgraded configurations first**. A ServiceNow administrator familiar with the instance's customisation scope should triage findings accordingly.

---

## Contributing

Pull requests are welcome. For significant changes, please open an issue first to discuss the approach. Each new analyzer should follow the existing pattern in `scanner/analyzers/` and return an `AreaResult` with a score and list of `Finding` objects.

---

## License

[MIT](LICENSE) — free to use, modify, and distribute.
