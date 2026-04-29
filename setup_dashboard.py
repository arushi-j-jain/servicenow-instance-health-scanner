"""
ServiceNow Health Scanner — Dashboard Setup
Creates the two custom tables, all dictionary fields, and four reports.
Dashboard widget placement requires 3 manual clicks (see Step 4 output).

Usage:
    python setup_dashboard.py
"""
import sys
import time
from scanner.client import ServiceNowClient

# ── Table names ───────────────────────────────────────────────────────────────

TABLE_RESULTS  = "sn_ap_apm_u_health_scan_results"
TABLE_FINDINGS = "sn_ap_apm_u_health_scan_findings"

# ── Field definitions ─────────────────────────────────────────────────────────
# Each dict: name, label, type, and optionally max_length / reference

RESULTS_FIELDS = [
    {"name": "u_scan_date",      "label": "Scan Date",       "type": "glide_date_time"},
    {"name": "u_domain",         "label": "Domain",          "type": "string",  "max_length": 100},
    {"name": "u_health_score",   "label": "Health Score",    "type": "integer"},
    {"name": "u_total_findings", "label": "Total Findings",  "type": "integer"},
    {"name": "u_critical_count", "label": "Critical Count",  "type": "integer"},
    {"name": "u_warning_count",  "label": "Warning Count",   "type": "integer"},
    {"name": "u_info_count",     "label": "Info Count",      "type": "integer"},
    {"name": "u_overall_score",  "label": "Overall Score",   "type": "integer"},
]

FINDINGS_FIELDS = [
    {"name": "u_parent",         "label": "Scan Result",     "type": "reference",
     "reference": TABLE_RESULTS},
    {"name": "u_domain",         "label": "Domain",          "type": "string",  "max_length": 100},
    {"name": "u_severity",       "label": "Severity",        "type": "string",  "max_length": 40},
    {"name": "u_title",          "label": "Title",           "type": "string",  "max_length": 255},
    {"name": "u_description",    "label": "Description",     "type": "string",  "max_length": 1000},
    {"name": "u_count",          "label": "Count",           "type": "integer"},
    {"name": "u_recommendation", "label": "Recommendation",  "type": "string",  "max_length": 1000},
    {"name": "u_examples",       "label": "Examples",        "type": "string",  "max_length": 4000},
]

# ── Report definitions ────────────────────────────────────────────────────────

REPORTS = [
    {
        "title":       "Health Score by Domain",
        "table":       TABLE_RESULTS,
        "type":        "bar",
        "field":       "u_health_score",
        "group_by":    "u_domain",
        "aggregation": "AVG",
    },
    {
        "title":       "Findings by Severity",
        "table":       TABLE_FINDINGS,
        "type":        "pie",
        "field":       "u_severity",
        "group_by":    "u_severity",
        "aggregation": "COUNT",
    },
    {
        "title":  "Critical Findings",
        "table":  TABLE_FINDINGS,
        "type":   "list",
        "field":  "u_title,u_domain,u_count,u_recommendation",
        "filter": "u_severity=Critical",
    },
    {
        "title":       "Overall Health Score",
        "table":       TABLE_RESULTS,
        "type":        "dial",
        "field":       "u_overall_score",
        "aggregation": "AVG",
    },
]


# ── Setup class ───────────────────────────────────────────────────────────────

class DashboardSetup:

    def __init__(self):
        self.client         = ServiceNowClient()
        self.tables_ready   = {TABLE_RESULTS: False, TABLE_FINDINGS: False}
        self.report_sys_ids = {}          # title → sys_id
        self.manual_needed  = []          # list of issues requiring manual action

    # ── helpers ───────────────────────────────────────────────────────────────

    def _div(self, char="-", width=62):
        print(char * width)

    def _table_exists(self, table_name):
        try:
            self.client.get_records(table_name, fields=["sys_id"], limit=1)
            return True
        except Exception:
            return False

    def _field_exists(self, table_name, field_name):
        rows = self.client.get_records(
            "sys_dictionary", fields=["sys_id"],
            query=f"name={table_name}^element={field_name}", limit=1,
        )
        return bool(rows)

    def _type_sys_id(self, type_name):
        """Return the sys_id of a type in sys_glide_object, or None."""
        rows = self.client.get_records(
            "sys_glide_object", fields=["sys_id"],
            query=f"name={type_name}", limit=1,
        )
        return rows[0]["sys_id"] if rows else None

    # ── Step 1 — Tables ───────────────────────────────────────────────────────

    def step1_tables(self):
        print("\n  STEP 1 — Custom Tables")
        self._div()

        table_specs = [
            (TABLE_RESULTS,  "Health Scan Results"),
            (TABLE_FINDINGS, "Health Scan Findings"),
        ]
        for tname, tlabel in table_specs:
            if self._table_exists(tname):
                print(f"  [OK      ]  {tname}  (already exists)")
                self.tables_ready[tname] = True
            else:
                ok = self._try_create_table(tname, tlabel)
                if ok:
                    print(f"  [CREATED ]  {tname}")
                    self.tables_ready[tname] = True
                else:
                    print(f"  [MANUAL  ]  {tname}  — see instructions at end")
                    self.manual_needed.append(("table", tname, tlabel))

    def _try_create_table(self, table_name, label):
        """Attempt table creation via sys_db_object. Returns True if queryable after."""
        try:
            self.client.post_record("sys_db_object", {
                "name":           table_name,
                "label":          label,
                "user_role":      "admin",
                "is_extendable":  "false",
                "create_module":  "false",
            })
            time.sleep(3)                          # give ServiceNow a moment
            return self._table_exists(table_name)
        except Exception:
            return False

    # ── Step 2 — Fields ───────────────────────────────────────────────────────

    def step2_fields(self):
        print("\n  STEP 2 — Dictionary Fields")
        self._div()

        specs = [
            (TABLE_RESULTS,  RESULTS_FIELDS),
            (TABLE_FINDINGS, FINDINGS_FIELDS),
        ]
        for tname, fields in specs:
            if not self.tables_ready[tname]:
                print(f"  [SKIP    ]  {tname}  (table not available)")
                continue

            created = skipped = failed = 0
            for f in fields:
                if self._field_exists(tname, f["name"]):
                    skipped += 1
                    continue
                if self._create_field(tname, f):
                    created += 1
                else:
                    failed += 1

            parts = []
            if created: parts.append(f"{created} created")
            if skipped: parts.append(f"{skipped} already existed")
            if failed:  parts.append(f"{failed} FAILED")
            print(f"  {tname:<42}  {', '.join(parts)}")

    def _create_field(self, table_name, fdef):
        try:
            type_id = self._type_sys_id(fdef["type"])
            payload = {
                "name":         table_name,
                "element":      fdef["name"],
                "column_label": fdef["label"],
                "active":       "true",
            }
            if type_id:
                payload["internal_type"] = type_id
            if "max_length" in fdef:
                payload["max_length"] = str(fdef["max_length"])
            if "reference" in fdef:
                payload["reference"] = fdef["reference"]
            self.client.post_record("sys_dictionary", payload)
            return True
        except Exception:
            return False

    # ── Step 3 — Reports ──────────────────────────────────────────────────────

    def step3_reports(self):
        print("\n  STEP 3 — Reports  (sys_report)")
        self._div()

        for r in REPORTS:
            existing = self.client.get_records(
                "sys_report", fields=["sys_id"],
                query=f"title={r['title']}", limit=1,
            )
            if existing:
                sid = existing[0]["sys_id"]
                self.report_sys_ids[r["title"]] = sid
                print(f"  [OK      ]  {r['title']:<42}  (already exists)")
                continue

            payload = {
                "title":        r["title"],
                "table":        r["table"],
                "type":         r.get("type", "list"),
                "field":        r.get("field", ""),
                "is_published": "true",
            }
            if r.get("group_by"):
                payload["group_by"]   = r["group_by"]
            if r.get("aggregation"):
                payload["sum_field"]  = r.get("field", "")
                payload["aggregation"]= r["aggregation"]
            if r.get("filter"):
                payload["filter"]     = r["filter"]

            try:
                result = self.client.post_record("sys_report", payload)
                sid = result.get("sys_id", "")
                self.report_sys_ids[r["title"]] = sid
                print(f"  [CREATED ]  {r['title']:<42}  {sid[:20]}...")
            except Exception as exc:
                print(f"  [FAILED  ]  {r['title']:<42}  {exc}")
                self.manual_needed.append(("report", r["title"], str(exc)))

    # ── Step 4 — Dashboard ────────────────────────────────────────────────────

    def step4_dashboard(self):
        print("\n  STEP 4 — Dashboard")
        self._div()
        print("  ServiceNow does not expose a stable REST API for placing")
        print("  report widgets on a dashboard. Three manual clicks required:\n")
        print("  1. Log in to ServiceNow.")
        print("  2. Navigate to:  Reports > View / Run")
        print("  3. For each report listed below, open it and click")
        print('     "Add to Dashboard" → create new → name it')
        print('     "Instance Health Scanner"\n')

        for title, sid in self.report_sys_ids.items():
            url = f"{self.client.instance}/sys_report.do?sys_id={sid}" if sid else "(no sys_id)"
            print(f"       {title}")
            print(f"         {url}")

        print()
        print("  After adding all four reports to the dashboard, find it under:")
        print("  Self-Service > Dashboards  (or type 'Instance Health' in the nav filter)")

    # ── Manual fallback instructions ──────────────────────────────────────────

    def _print_manual_steps(self):
        table_issues = [(t, l) for kind, t, l in self.manual_needed if kind == "table"]
        if not table_issues:
            return

        print("\n" + "=" * 62)
        print("  MANUAL TABLE CREATION REQUIRED")
        print("=" * 62)
        print("  The tables below could not be created via API.")
        print("  Create them in ServiceNow (takes ~3 minutes total):\n")

        for tname, tlabel in table_issues:
            print(f"  Table: {tname}  |  Label: {tlabel}")
            print(f"  Path: System Definition > Tables > New")
            print(f"  Fields to add after saving:\n")
            fields = RESULTS_FIELDS if tname == TABLE_RESULTS else FINDINGS_FIELDS
            for fdef in fields:
                ref = f"  → references {fdef['reference']}" if "reference" in fdef else ""
                ml  = f"  max {fdef['max_length']}" if "max_length" in fdef else ""
                print(f"    {fdef['name']:<25} {fdef['type']:<18}{ml}{ref}  ({fdef['label']})")
            print()

        print("  After creating the tables manually, re-run:")
        print("    python setup_dashboard.py")
        print("  The script will skip already-done steps and continue.")

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self):
        print("=" * 62)
        print("  ServiceNow Health Scanner — Dashboard Setup")
        print(f"  Instance: {self.client.instance}")
        print("=" * 62)

        self.step1_tables()
        self.step2_fields()
        self.step3_reports()
        self.step4_dashboard()
        self._print_manual_steps()

        tables_ok  = all(self.tables_ready.values())
        reports_ok = len(self.report_sys_ids) == len(REPORTS)

        print()
        print("=" * 62)
        if tables_ok and reports_ok:
            print("  Setup complete.")
            print("  Run  python run_setup.py  to push the first scan data,")
            print("  then follow the Step 4 instructions above to build the dashboard.")
        else:
            pending = []
            if not tables_ok:  pending.append("complete manual table creation")
            if not reports_ok: pending.append("check report errors above")
            print("  Partial setup — next steps:")
            for p in pending:
                print(f"    • {p}")
            print("  Then re-run python setup_dashboard.py to retry.")
        print("=" * 62)

        return tables_ok and reports_ok


if __name__ == "__main__":
    setup = DashboardSetup()
    ok = setup.run()
    sys.exit(0 if ok else 1)
