import os
import requests
from dotenv import load_dotenv

load_dotenv()

INSTANCE = os.getenv("SNOW_INSTANCE")
USERNAME = os.getenv("SNOW_USERNAME")
PASSWORD = os.getenv("SNOW_PASSWORD")


def test_connection():
    url = f"{INSTANCE}/api/now/table/incident"
    params = {
        "sysparm_limit": 5,
        "sysparm_fields": "number,short_description,state,priority,opened_at",
        "sysparm_query": "ORDERBYDESCopened_at",
    }
    headers = {"Accept": "application/json"}

    print(f"Connecting to: {INSTANCE}")
    print("-" * 50)

    response = requests.get(
        url,
        auth=(USERNAME, PASSWORD),
        headers=headers,
        params=params,
        timeout=15,
    )

    if response.status_code == 200:
        incidents = response.json().get("result", [])
        print(f"Connection successful! Found {len(incidents)} recent incident(s):\n")
        for inc in incidents:
            state_map = {"1": "New", "2": "In Progress", "3": "On Hold", "6": "Resolved", "7": "Closed"}
            state = state_map.get(inc.get("state", ""), inc.get("state", "Unknown"))
            priority_map = {"1": "Critical", "2": "High", "3": "Moderate", "4": "Low", "5": "Planning"}
            priority = priority_map.get(inc.get("priority", ""), inc.get("priority", "Unknown"))
            print(f"  [{inc.get('number')}]  {inc.get('short_description', 'No description')}")
            print(f"    State: {state}  |  Priority: {priority}  |  Opened: {inc.get('opened_at')}")
            print()
    elif response.status_code == 401:
        print("ERROR: Authentication failed. Check your username and password in .env")
    elif response.status_code == 403:
        print("ERROR: Access denied. Your account may lack permission to read incidents.")
    else:
        print(f"ERROR: Unexpected response — HTTP {response.status_code}")
        print(response.text[:500])


if __name__ == "__main__":
    if not all([INSTANCE, USERNAME, PASSWORD]):
        print("ERROR: Missing credentials. Make sure .env has SNOW_INSTANCE, SNOW_USERNAME, SNOW_PASSWORD.")
    else:
        test_connection()
