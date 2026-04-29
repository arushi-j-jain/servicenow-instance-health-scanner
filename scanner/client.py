import os
import requests
from dotenv import load_dotenv

load_dotenv()


class ServiceNowClient:
    """Reusable connection layer for the ServiceNow Table API."""

    def __init__(self):
        self.instance = os.getenv("SNOW_INSTANCE", "").rstrip("/")
        username = os.getenv("SNOW_USERNAME")
        password = os.getenv("SNOW_PASSWORD")

        if not all([self.instance, username, password]):
            raise ValueError("Missing credentials. Check SNOW_INSTANCE, SNOW_USERNAME, SNOW_PASSWORD in .env")

        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({"Accept": "application/json"})
        self.call_count = 0

    def get_records(self, table, fields=None, query=None, limit=1000):
        """Fetch records from a ServiceNow table."""
        url = f"{self.instance}/api/now/table/{table}"
        params = {"sysparm_limit": limit, "sysparm_exclude_reference_link": "true"}
        if fields:
            params["sysparm_fields"] = ",".join(fields)
        if query:
            params["sysparm_query"] = query

        self.call_count += 1
        response = self.session.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json().get("result", [])

    def post_record(self, table, payload):
        """Insert a new record into a ServiceNow table."""
        url = f"{self.instance}/api/now/table/{table}"
        self.call_count += 1
        response = self.session.post(url, json=payload, timeout=30)
        response.raise_for_status()
        return response.json().get("result", {})

    def get_version(self):
        """Detect instance version from sys_properties, trying several known property names."""
        prop_names = ["glide.war", "glide.buildtag", "glide.war.build.tag", "glide.build.tag"]
        try:
            query = "^OR".join(f"name={p}" for p in prop_names)
            records = self.get_records(
                "sys_properties",
                fields=["name", "value"],
                query=query,
                limit=len(prop_names),
            )
            for r in records:
                val = r.get("value", "").strip()
                if val:
                    return val
        except Exception:
            pass
        return "Could not detect"
