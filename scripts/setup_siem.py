#!/usr/bin/env python3
"""
SIEM Setup Script — Detection Rules via Kibana API
=====================================================
Loads 4 detection rules into the Kibana Detection Engine to detect:
  1. Brute Force Attack      (threshold rule — T1110)
  2. Privilege Escalation     (query rule — T1068)
  3. Port Scan Detection      (threshold rule — T1046)
  4. Breach Confirmation      (EQL sequence rule — T1078)

These rules monitor the security-logs-* index and map to MITRE ATT&CK techniques.

Usage:
    make siem
    # or: docker-compose run --rm setup bash -c "pip install --quiet requests && python scripts/setup_siem.py"
"""

import json
import os
import sys
import time

import requests

# =============================================================================
# Configuration
# =============================================================================

KIBANA_HOST = "http://kibana:5601"
ES_HOST = "http://elasticsearch:9200"
USERNAME = "elastic"
PASSWORD = os.environ.get("ELASTIC_PASSWORD", "changeme")
AUTH = (USERNAME, PASSWORD)

# Retry settings — Kibana may take a while to be fully ready
MAX_RETRIES = 40
RETRY_INTERVAL = 10  # seconds

# Common headers for Kibana API (kbn-xsrf is required for all mutations)
KIBANA_HEADERS = {
    "Content-Type": "application/json",
    "kbn-xsrf": "true",
}


# =============================================================================
# Helper Functions
# =============================================================================


def wait_for_kibana():
    """Block until Kibana is ready and responding."""
    print(f"[siem] Waiting for Kibana at {KIBANA_HOST}...")
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(
                f"{KIBANA_HOST}/api/status",
                auth=AUTH,
                timeout=10,
            )
            if resp.status_code == 200:
                status = resp.json().get("status", {}).get("overall", {}).get("level", "unknown")
                print(f"[siem] Kibana is ready — status: {status}")
                return True
        except (requests.ConnectionError, requests.Timeout):
            pass

        print(f"[siem] Attempt {attempt}/{MAX_RETRIES} — retrying in {RETRY_INTERVAL}s...")
        time.sleep(RETRY_INTERVAL)

    print("[siem] ERROR: Kibana did not become ready in time.")
    sys.exit(1)


def init_detection_engine():
    """
    Initialize the Kibana Detection Engine (creates the signals index).
    This must be called before creating any detection rules.
    The signals index (.siem-signals-*) stores fired alerts.
    """
    print("[siem] Initializing Detection Engine (creating signals index)...")

    for attempt in range(1, 10):
        resp = requests.post(
            f"{KIBANA_HOST}/api/detection_engine/index",
            auth=AUTH,
            headers=KIBANA_HEADERS,
            timeout=15,
        )

        if resp.status_code == 200:
            print("[siem] ✅ Detection Engine initialized.")
            return
        elif resp.status_code == 409:
            # Already initialized
            print("[siem] Detection Engine already initialized (409).")
            return
        else:
            print(f"[siem] Detection Engine init attempt {attempt}: {resp.status_code} — {resp.text}")
            time.sleep(5)

    print("[siem] WARNING: Could not initialize Detection Engine. Rules may fail to create.")


def create_data_view():
    """
    Create a Kibana data view for security-logs-* if it doesn't exist.
    This is needed for the detection rules and Discover UI.
    """
    print("[siem] Creating data view for security-logs-*...")

    body = {
        "data_view": {
            "title": "security-logs-*",
            "timeFieldName": "@timestamp",
            "name": "Security Logs",
        }
    }

    resp = requests.post(
        f"{KIBANA_HOST}/api/data_views/data_view",
        auth=AUTH,
        headers=KIBANA_HEADERS,
        json=body,
        timeout=10,
    )

    if resp.status_code in (200, 201):
        print("[siem] ✅ Data view 'security-logs-*' created.")
    elif resp.status_code == 409:
        print("[siem] Data view already exists (409).")
    else:
        print(f"[siem] WARNING: Could not create data view: {resp.status_code} — {resp.text}")


def create_rule(rule_body: dict) -> bool:
    """
    Create a single detection rule via the Kibana Detection Engine API.
    Returns True if created successfully, False otherwise.
    """
    rule_name = rule_body.get("name", "Unknown")
    print(f"[siem] Creating rule: '{rule_name}'...")

    resp = requests.post(
        f"{KIBANA_HOST}/api/detection_engine/rules",
        auth=AUTH,
        headers=KIBANA_HEADERS,
        json=rule_body,
        timeout=15,
    )

    if resp.status_code == 200:
        rule_id = resp.json().get("id", "?")
        print(f"[siem] ✅ Rule '{rule_name}' created (id={rule_id})")
        return True
    elif resp.status_code == 409:
        print(f"[siem] Rule '{rule_name}' already exists (409). Skipping.")
        return True
    else:
        print(f"[siem] ❌ Failed to create rule '{rule_name}': {resp.status_code}")
        print(f"[siem]    Response: {resp.text[:500]}")
        return False


# =============================================================================
# Detection Rule Definitions
# =============================================================================

# Each rule maps to a specific MITRE ATT&CK technique.
# Rules use the security-logs-* index which contains enriched security events.

DETECTION_RULES = [
    # -------------------------------------------------------------------------
    # Rule 1: Brute Force Detection
    # -------------------------------------------------------------------------
    # Detects credential stuffing / brute force attacks by counting AUTH_FAIL
    # events from the same source_ip. Threshold: >10 in 1 minute.
    # MITRE ATT&CK: T1110 — Brute Force (Credential Access)
    # -------------------------------------------------------------------------
    {
        "rule_id": "secops-brute-force-001",
        "name": "Potential Brute Force Attack Detected",
        "description": (
            "Detects more than 10 AUTH_FAIL events from the same source IP "
            "within a 1-minute window. This pattern indicates credential stuffing "
            "or brute force login attempts against the authentication service."
        ),
        "type": "threshold",
        "language": "kuery",
        "index": ["security-logs-*"],
        "query": "action:AUTH_FAIL",
        "threshold": {
            "field": ["source_ip"],
            "value": 10,
            "cardinality": [],
        },
        "severity": "high",
        "risk_score": 73,
        "from": "now-2m",
        "to": "now",
        "interval": "1m",
        "enabled": True,
        "tags": ["SecOps", "Brute Force", "MITRE ATT&CK: T1110"],
        "threat": [
            {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": "TA0006",
                    "name": "Credential Access",
                    "reference": "https://attack.mitre.org/tactics/TA0006",
                },
                "technique": [
                    {
                        "id": "T1110",
                        "name": "Brute Force",
                        "reference": "https://attack.mitre.org/techniques/T1110",
                        "subtechnique": [],
                    }
                ],
            }
        ],
    },

    # -------------------------------------------------------------------------
    # Rule 2: Privilege Escalation Attempt
    # -------------------------------------------------------------------------
    # Detects any event where a user attempts to access resources beyond their
    # privilege level. Fires on any PRIV_ESC_ATTEMPT action.
    # MITRE ATT&CK: T1068 — Exploitation for Privilege Escalation
    # -------------------------------------------------------------------------
    {
        "rule_id": "secops-priv-esc-002",
        "name": "Privilege Escalation Attempt",
        "description": (
            "Detects attempts to access admin endpoints or modify user roles "
            "without proper authorization. Any PRIV_ESC_ATTEMPT action triggers this rule."
        ),
        "type": "query",
        "language": "kuery",
        "index": ["security-logs-*"],
        "query": "action:PRIV_ESC_ATTEMPT",
        "severity": "critical",
        "risk_score": 91,
        "from": "now-2m",
        "to": "now",
        "interval": "1m",
        "enabled": True,
        "tags": ["SecOps", "Privilege Escalation", "MITRE ATT&CK: T1068"],
        "threat": [
            {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": "TA0004",
                    "name": "Privilege Escalation",
                    "reference": "https://attack.mitre.org/tactics/TA0004",
                },
                "technique": [
                    {
                        "id": "T1068",
                        "name": "Exploitation for Privilege Escalation",
                        "reference": "https://attack.mitre.org/techniques/T1068",
                        "subtechnique": [],
                    }
                ],
            }
        ],
    },

    # -------------------------------------------------------------------------
    # Rule 3: Port Scan Detection
    # -------------------------------------------------------------------------
    # Detects network reconnaissance by counting PORT_SCAN events from the
    # same source_ip. Threshold: >5 in 1 minute.
    # MITRE ATT&CK: T1046 — Network Service Discovery
    # -------------------------------------------------------------------------
    {
        "rule_id": "secops-port-scan-003",
        "name": "Potential Port Scan Detected",
        "description": (
            "Detects more than 5 PORT_SCAN events from the same source IP "
            "within a 1-minute window. This pattern indicates network "
            "reconnaissance to discover open services."
        ),
        "type": "threshold",
        "language": "kuery",
        "index": ["security-logs-*"],
        "query": "action:PORT_SCAN",
        "threshold": {
            "field": ["source_ip"],
            "value": 5,
            "cardinality": [],
        },
        "severity": "medium",
        "risk_score": 47,
        "from": "now-2m",
        "to": "now",
        "interval": "1m",
        "enabled": True,
        "tags": ["SecOps", "Port Scan", "MITRE ATT&CK: T1046"],
        "threat": [
            {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": "TA0007",
                    "name": "Discovery",
                    "reference": "https://attack.mitre.org/tactics/TA0007",
                },
                "technique": [
                    {
                        "id": "T1046",
                        "name": "Network Service Discovery",
                        "reference": "https://attack.mitre.org/techniques/T1046",
                        "subtechnique": [],
                    }
                ],
            }
        ],
    },

    # -------------------------------------------------------------------------
    # Rule 4: Breach Confirmation (EQL Sequence)
    # -------------------------------------------------------------------------
    # Uses EQL (Event Query Language) to correlate two events in sequence:
    #   1. AUTH_FAIL from a source_ip  →  2. AUTH_SUCCESS from the SAME source_ip
    # This detects the critical moment when a brute force attack succeeds.
    #
    # EQL sequence queries are Elastic's built-in correlation engine — they
    # detect multi-step attack patterns that simple threshold rules cannot.
    # MITRE ATT&CK: T1078 — Valid Accounts
    # -------------------------------------------------------------------------
    {
        "rule_id": "secops-breach-confirm-004",
        "name": "Successful Login After Brute Force — Possible Breach",
        "description": (
            "Detects a successful authentication (AUTH_SUCCESS) from an IP address "
            "that previously had failed login attempts (AUTH_FAIL) within the last "
            "5 minutes. This sequence strongly indicates that a brute force attack "
            "has succeeded and an account may be compromised."
        ),
        "type": "eql",
        "language": "eql",
        "index": ["security-logs-*"],
        # EQL sequence: correlate AUTH_FAIL → AUTH_SUCCESS by source_ip within 5 min
        "query": (
            'sequence by source_ip with maxspan=5m\n'
            '  [any where action == "AUTH_FAIL"]\n'
            '  [any where action == "AUTH_SUCCESS"]'
        ),
        "severity": "critical",
        "risk_score": 99,
        "from": "now-6m",
        "to": "now",
        "interval": "1m",
        "enabled": True,
        "tags": ["SecOps", "Breach", "Credential Compromise", "MITRE ATT&CK: T1078"],
        "threat": [
            {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": "TA0001",
                    "name": "Initial Access",
                    "reference": "https://attack.mitre.org/tactics/TA0001",
                },
                "technique": [
                    {
                        "id": "T1078",
                        "name": "Valid Accounts",
                        "reference": "https://attack.mitre.org/techniques/T1078",
                        "subtechnique": [],
                    }
                ],
            }
        ],
    },
]


# =============================================================================
# Main
# =============================================================================


def main():
    print("=" * 60)
    print("[siem] SIEM Detection Rules Setup")
    print("=" * 60)

    wait_for_kibana()
    create_data_view()
    init_detection_engine()

    # Create each detection rule
    success_count = 0
    for rule in DETECTION_RULES:
        if create_rule(rule):
            success_count += 1

    print()
    print(f"[siem] Results: {success_count}/{len(DETECTION_RULES)} rules created successfully.")

    # Verify rules are loaded
    print("[siem] Verifying loaded rules...")
    resp = requests.get(
        f"{KIBANA_HOST}/api/detection_engine/rules/_find?per_page=10",
        auth=AUTH,
        headers=KIBANA_HEADERS,
        timeout=10,
    )
    if resp.status_code == 200:
        total = resp.json().get("total", 0)
        print(f"[siem] ✅ Total detection rules in Kibana: {total}")
    else:
        print(f"[siem] WARNING: Could not verify rules: {resp.status_code}")

    print("=" * 60)
    print("[siem] ✅ SIEM setup complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
