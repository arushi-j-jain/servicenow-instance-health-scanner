"""
Check what fields exist on the custom tables, create any missing ones,
then push one real scan record so the dashboard has data to display.
"""
from scanner.client import ServiceNowClient
from datetime import datetime, timezone

TABLE_RESULTS  = "sn_ap_apm_u_health_scan_results"
TABLE_FINDINGS = "sn_ap_apm_u_health_scan_findings"

RESULTS_FIELDS = [
    {"name": "u_scan_date",      "label": "Scan Date",      "type": "glide_date_time"},
    {"name": "u_domain",         "label": "Domain",         "type": "string",  "max_length": 100},
    {"name": "u_health_score",   "label": "Health Score",   "type": "integer"},
    {"name": "u_total_findings", "label": "Total Findings", "type": "integer"},
    {"name": "u_critical_count", "label": "Critical Count", "type": "integer"},
    {"name": "u_warning_count",  "label": "Warning Count",  "type": "integer"},
    {"name": "u_info_count",     "label": "Info Count",     "type": "integer"},
    {"name": "u_overall_score",  "label": "Overall Score",  "type": "integer"},
]

FINDINGS_FIELDS = [
    {"name": "u_parent",         "label": "Scan Result",    "type": "reference", "reference": TABLE_RESULTS},
    {"name": "u_domain",         "label": "Domain",         "type": "string",  "max_length": 100},
    {"name": "u_severity",       "label": "Severity",       "type": "string",  "max_length": 40},
    {"name": "u_title",          "label": "Title",          "type": "string",  "max_length": 255},
    {"name": "u_description",    "label": "Description",    "type": "string",  "max_length": 1000},
    {"name": "u_count",          "label": "Count",          "type": "integer"},
    {"name": "u_recommendation", "label": "Recommendation", "type": "string",  "max_length": 1000},
    {"name": "u_examples",       "label": "Examples",       "type": "string",  "max_length": 4000},
]


def check_and_fix(client, table_name, expected_fields):
    print(f"\n  Table: {table_name}")
    print("  " + "-" * 55)

    rows = client.get_records(
        "sys_dictionary",
        fields=["element", "column_label", "internal_type"],
        query=f"name={table_name}",
        limit=200,
    )
    existing = {r["element"] for r in rows if r.get("element")}

    our_fields   = [f["name"] for f in expected_fields]
    present      = [n for n in our_fields if n in existing]
    missing      = [f for f in expected_fields if f["name"] not in existing]

    print(f"  Custom fields present  ({len(present)}): {', '.join(present) or 'none'}")
    print(f"  Custom fields missing  ({len(missing)}): {', '.join(f['name'] for f in missing) or 'none'}")

    if not missing:
        print("  All fields OK — nothing to create.")
        return

    print(f"\n  Creating {len(missing)} missing field(s)...")
    for f in missing:
        type_rows = client.get_records(
            "sys_glide_object",
            fields=["sys_id"],
            query=f"name={f['type']}",
            limit=1,
        )
        payload = {
            "name":         table_name,
            "element":      f["name"],
            "column_label": f["label"],
            "active":       "true",
        }
        if type_rows:
            payload["internal_type"] = type_rows[0]["sys_id"]
        if "max_length" in f:
            payload["max_length"] = str(f["max_length"])
        if "reference" in f:
            payload["reference"] = f["reference"]

        try:
            client.post_record("sys_dictionary", payload)
            print(f"  [CREATED]  {f['name']}")
        except Exception as exc:
            print(f"  [FAILED]   {f['name']} — {exc}")


def push_sample(client):
    print("\n  Pushing sample scan record...")
    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    try:
        row = client.post_record(TABLE_RESULTS, {
            "u_scan_date":      scan_time,
            "u_domain":         "Business Rules",
            "u_health_score":   "72",
            "u_total_findings": "4",
            "u_critical_count": "1",
            "u_warning_count":  "2",
            "u_info_count":     "1",
            "u_overall_score":  "72",
        })
        result_sid = row.get("sys_id", "")
        print(f"  [OK]  Results row created  — sys_id: {result_sid[:20]}...")

        client.post_record(TABLE_FINDINGS, {
            "u_parent":         result_sid,
            "u_domain":         "Business Rules",
            "u_severity":       "Critical",
            "u_title":          "Rules missing filter condition",
            "u_description":    "Business rules with no filter condition run on every record save.",
            "u_count":          "3",
            "u_recommendation": "Add a filter condition to limit execution scope.",
            "u_examples":       "Example rule 1; Example rule 2",
        })
        print(f"  [OK]  Findings row created")
    except Exception as exc:
        print(f"  [FAILED]  {exc}")


def main():
    print("=" * 60)
    print("  Field Check + Fix")
    print("=" * 60)

    client = ServiceNowClient()
    print(f"  Instance: {client.instance}")

    check_and_fix(client, TABLE_RESULTS,  RESULTS_FIELDS)
    check_and_fix(client, TABLE_FINDINGS, FINDINGS_FIELDS)

    push_sample(client)

    print()
    print("=" * 60)
    print("  Done.")
    print("  In ServiceNow, open your PA visualization builder,")
    print("  select the table, and the custom fields should now")
    print("  appear in the Metric / Group by dropdowns.")
    print()
    print("  Run  python main.py  to push real scan data.")
    print("=" * 60)


if __name__ == "__main__":
    main()
