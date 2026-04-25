#!/usr/bin/env python3
"""
Setup Script — Trial License, ILM Policy, Index Templates
============================================================
One-shot init container script that runs at stack startup.

Steps:
1. Wait for Elasticsearch to be healthy
2. Activate a 30-day trial license (unlocks ML + SIEM features)
3. Apply ILM policy from ilm-policy.json
4. Create index template for app-logs-* (backward compatibility)
5. Create index template for security-logs-* (with geo_point mapping for GeoIP)
6. Verify ElastAlert2 writeback index status
"""

import json
import os
import sys
import time

import requests

# =============================================================================
# Configuration
# =============================================================================

ES_HOST = "http://elasticsearch:9200"
ES_USER = "elastic"
ES_PASS = os.environ.get("ELASTIC_PASSWORD", "changeme")
ES_AUTH = (ES_USER, ES_PASS)

ILM_POLICY_NAME = "app-logs-policy"
ILM_POLICY_FILE = "elasticsearch/ilm-policy.json"

# Retry settings for waiting on Elasticsearch
MAX_RETRIES = 60
RETRY_INTERVAL = 5  # seconds


# =============================================================================
# Helper: Elasticsearch API wrapper with auth
# =============================================================================


def es_get(path: str, **kwargs):
    """GET request to Elasticsearch with authentication."""
    return requests.get(f"{ES_HOST}{path}", auth=ES_AUTH, timeout=10, **kwargs)


def es_put(path: str, **kwargs):
    """PUT request to Elasticsearch with authentication."""
    return requests.put(
        f"{ES_HOST}{path}",
        auth=ES_AUTH,
        headers={"Content-Type": "application/json"},
        timeout=10,
        **kwargs,
    )


def es_post(path: str, **kwargs):
    """POST request to Elasticsearch with authentication."""
    return requests.post(
        f"{ES_HOST}{path}",
        auth=ES_AUTH,
        headers={"Content-Type": "application/json"},
        timeout=10,
        **kwargs,
    )


# =============================================================================
# Step 1: Wait for Elasticsearch
# =============================================================================


def wait_for_elasticsearch():
    """Block until Elasticsearch cluster health is green or yellow."""
    print(f"[setup] Waiting for Elasticsearch at {ES_HOST}...")
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = es_get("/_cluster/health")
            if resp.status_code == 200:
                health = resp.json()
                status = health.get("status", "unknown")
                print(f"[setup] Elasticsearch is up — cluster status: {status}")
                if status in ("green", "yellow"):
                    return True
        except requests.ConnectionError:
            pass
        except requests.Timeout:
            pass

        print(f"[setup] Attempt {attempt}/{MAX_RETRIES} — retrying in {RETRY_INTERVAL}s...")
        time.sleep(RETRY_INTERVAL)

    print("[setup] ERROR: Elasticsearch did not become ready in time.")
    sys.exit(1)


# =============================================================================
# Step 2: Activate Trial License
# =============================================================================


def activate_trial_license():
    """
    Activate a 30-day trial license to unlock Platinum features.
    This enables:
      - Machine Learning anomaly detection (no hardcoded thresholds)
      - SIEM Detection Engine (Kibana security rules)
      - EQL (Event Query Language) for sequence-based detection
    """
    print("[setup] Activating 30-day trial license...")

    resp = es_post("/_license/start_trial?acknowledge=true")

    if resp.status_code == 200:
        result = resp.json()
        if result.get("trial_was_started"):
            print("[setup] ✅ Trial license activated successfully!")
        elif result.get("acknowledged"):
            print("[setup] Trial license already active.")
        else:
            print(f"[setup] Trial license response: {result}")
    elif resp.status_code == 403:
        # Trial may already be activated or expired
        print("[setup] Trial license already used or active (403). Continuing...")
    else:
        print(f"[setup] WARNING: Could not activate trial: {resp.status_code} — {resp.text}")
        print("[setup] ML and SIEM features may not be available without a trial/platinum license.")

    # Verify current license
    verify = es_get("/_license")
    if verify.status_code == 200:
        lic = verify.json().get("license", {})
        print(f"[setup] Current license: type={lic.get('type')}, status={lic.get('status')}")


# =============================================================================
# Step 3: Apply ILM Policy
# =============================================================================


def apply_ilm_policy():
    """Create or update the ILM policy in Elasticsearch."""
    print(f"[setup] Applying ILM policy '{ILM_POLICY_NAME}'...")

    with open(ILM_POLICY_FILE, "r", encoding="utf-8") as f:
        policy_body = json.load(f)

    resp = es_put(f"/_ilm/policy/{ILM_POLICY_NAME}", json=policy_body)

    if resp.status_code in (200, 201):
        print(f"[setup] ✅ ILM policy '{ILM_POLICY_NAME}' applied successfully.")
    else:
        print(f"[setup] ERROR applying ILM policy: {resp.status_code} — {resp.text}")
        sys.exit(1)

    # Verify
    verify = es_get(f"/_ilm/policy/{ILM_POLICY_NAME}")
    if verify.status_code == 200:
        print(f"[setup] ILM policy verified.")


# =============================================================================
# Step 4: Create app-logs Index Template
# =============================================================================


def create_app_logs_template():
    """Create index template for app-logs-* with ILM policy link."""
    template_name = "app-logs-template"
    print(f"[setup] Creating index template '{template_name}'...")

    template_body = {
        "index_patterns": ["app-logs-*"],
        "template": {
            "settings": {
                "index.lifecycle.name": ILM_POLICY_NAME,
                "number_of_shards": 1,
                "number_of_replicas": 0,
            },
            "mappings": {
                "properties": {
                    "log_level": {"type": "keyword"},
                    "service_name": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "user": {"type": "keyword"},
                    "action": {"type": "keyword"},
                    "message": {"type": "text"},
                    "@timestamp": {"type": "date"},
                }
            },
        },
        "priority": 500,
    }

    resp = es_put(f"/_index_template/{template_name}", json=template_body)

    if resp.status_code in (200, 201):
        print(f"[setup] ✅ Index template '{template_name}' created.")
    else:
        print(f"[setup] ERROR creating template: {resp.status_code} — {resp.text}")
        sys.exit(1)


# =============================================================================
# Step 5: Create security-logs Index Template
# =============================================================================


def create_security_logs_template():
    """
    Create index template for security-logs-* with:
      - ILM policy link
      - Explicit geo_point mapping for geoip.location (powers the threat map)
      - IP type mapping for source_ip (enables CIDR queries)
      - Keyword mappings for security-relevant fields
    """
    template_name = "security-logs-template"
    print(f"[setup] Creating index template '{template_name}'...")

    template_body = {
        "index_patterns": ["security-logs-*"],
        "template": {
            "settings": {
                "index.lifecycle.name": ILM_POLICY_NAME,
                "number_of_shards": 1,
                "number_of_replicas": 0,
            },
            "mappings": {
                "properties": {
                    # Core log fields
                    "log_level": {"type": "keyword"},
                    "service_name": {"type": "keyword"},
                    "message": {"type": "text"},
                    "@timestamp": {"type": "date"},
                    # Security-specific fields
                    "source_ip": {"type": "ip"},
                    "user": {"type": "keyword"},
                    "action": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    # GeoIP fields — populated by Logstash geoip filter
                    # The geo_point mapping is critical for Kibana Maps visualization
                    "geoip": {
                        "properties": {
                            "location": {"type": "geo_point"},
                            "country_name": {"type": "keyword"},
                            "city_name": {"type": "keyword"},
                            "country_code2": {"type": "keyword"},
                            "continent_code": {"type": "keyword"},
                            "region_name": {"type": "keyword"},
                            "latitude": {"type": "float"},
                            "longitude": {"type": "float"},
                        }
                    },
                }
            },
        },
        # Higher priority than app-logs template
        "priority": 600,
    }

    resp = es_put(f"/_index_template/{template_name}", json=template_body)

    if resp.status_code in (200, 201):
        print(f"[setup] ✅ Index template '{template_name}' created with geo_point mapping.")
    else:
        print(f"[setup] ERROR creating template: {resp.status_code} — {resp.text}")
        sys.exit(1)


# =============================================================================
# Step 6: Verify ElastAlert2 Status
# =============================================================================


def verify_elastalert_status():
    """Check whether the ElastAlert2 writeback index exists."""
    print("[setup] Checking ElastAlert2 writeback index...")
    resp = es_get("/elastalert_status")
    if resp.status_code == 200:
        print("[setup] ElastAlert2 writeback index 'elastalert_status' exists.")
    else:
        print(
            "[setup] ElastAlert2 writeback index not yet created "
            "(will be auto-created when ElastAlert2 starts)."
        )


# =============================================================================
# Main
# =============================================================================


def main():
    """Run all setup steps in sequence."""
    print("=" * 60)
    print("[setup] ELK Stack Setup Script — SecOps Edition")
    print("=" * 60)

    wait_for_elasticsearch()
    activate_trial_license()
    apply_ilm_policy()
    create_app_logs_template()
    create_security_logs_template()
    verify_elastalert_status()

    print("=" * 60)
    print("[setup] ✅ Setup complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
