#!/usr/bin/env python3
"""
ML Anomaly Detection Setup — Elastic Machine Learning
========================================================
Uses the Elasticsearch ML API to create an anomaly detection job that
automatically detects IPs generating abnormally high event volumes.

This is Elastic's built-in AI — no external LLM needed.
It learns a normal baseline of event counts per source_ip and flags
statistical anomalies automatically. This catches brute force attacks,
port scans, and any other unusual traffic patterns WITHOUT hardcoded
threshold rules.

How it works:
  1. Creates an anomaly detection job with a "high_count" detector
  2. Partitions by source_ip so each IP gets its own baseline
  3. Uses 1-minute bucket spans for near-real-time detection
  4. Creates a datafeed that reads from security-logs-*
  5. Starts the datafeed to begin continuous analysis

The ML model adapts over time — as it sees more normal traffic, its
baseline becomes more accurate and it can detect subtler anomalies.

Usage:
    make ml
    # or: docker-compose run --rm setup bash -c "pip install --quiet requests && python scripts/setup_ml.py"
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
USERNAME = "elastic"
PASSWORD = os.environ.get("ELASTIC_PASSWORD", "changeme")
AUTH = (USERNAME, PASSWORD)

JOB_ID = "security-anomaly-detector"
DATAFEED_ID = f"datafeed-{JOB_ID}"

# Retry settings
MAX_RETRIES = 30
RETRY_INTERVAL = 5  # seconds


# =============================================================================
# Helper Functions
# =============================================================================


def es_get(path: str, **kwargs):
    """GET request to Elasticsearch with authentication."""
    return requests.get(f"{ES_HOST}{path}", auth=AUTH, timeout=10, **kwargs)


def es_put(path: str, **kwargs):
    """PUT request to Elasticsearch with authentication."""
    return requests.put(
        f"{ES_HOST}{path}",
        auth=AUTH,
        headers={"Content-Type": "application/json"},
        timeout=10,
        **kwargs,
    )


def es_post(path: str, **kwargs):
    """POST request to Elasticsearch with authentication."""
    return requests.post(
        f"{ES_HOST}{path}",
        auth=AUTH,
        headers={"Content-Type": "application/json"},
        timeout=10,
        **kwargs,
    )


def wait_for_elasticsearch():
    """Block until Elasticsearch is ready."""
    print(f"[ml] Waiting for Elasticsearch at {ES_HOST}...")
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = es_get("/_cluster/health")
            if resp.status_code == 200:
                status = resp.json().get("status", "unknown")
                if status in ("green", "yellow"):
                    print(f"[ml] Elasticsearch is ready — cluster status: {status}")
                    return True
        except (requests.ConnectionError, requests.Timeout):
            pass
        print(f"[ml] Attempt {attempt}/{MAX_RETRIES} — retrying in {RETRY_INTERVAL}s...")
        time.sleep(RETRY_INTERVAL)

    print("[ml] ERROR: Elasticsearch did not become ready in time.")
    sys.exit(1)


def verify_license():
    """Verify that a trial or platinum license is active (required for ML)."""
    print("[ml] Verifying license supports ML features...")
    resp = es_get("/_license")
    if resp.status_code == 200:
        lic = resp.json().get("license", {})
        lic_type = lic.get("type", "unknown")
        lic_status = lic.get("status", "unknown")
        print(f"[ml] License: type={lic_type}, status={lic_status}")

        if lic_type in ("trial", "platinum", "enterprise", "gold"):
            print("[ml] ✅ License supports ML features.")
            return True
        else:
            print(f"[ml] ❌ License type '{lic_type}' does not support ML.")
            print("[ml]    Run 'make up' first — setup_alerts.py activates a trial license.")
            sys.exit(1)
    else:
        print(f"[ml] WARNING: Could not check license: {resp.status_code}")
        return False


# =============================================================================
# Step 1: Create Anomaly Detection Job
# =============================================================================


def create_anomaly_job():
    """
    Create an ML anomaly detection job that monitors event volume per source_ip.

    The job uses a "high_count" detector partitioned by source_ip:
      - Each unique source_ip gets its own learned baseline
      - The model detects when an IP generates significantly more events
        than its historical norm
      - Bucket span of 1 minute provides near-real-time detection

    Why this works for security:
      - Brute force attacks: attacker IP generates 15-20 events in 30 seconds
        (far above the normal ~1 event per second baseline)
      - Port scans: attacker IP generates rapid sequential events
      - Any new attack pattern: automatically detected without writing new rules

    This is the power of Elastic ML — it adapts to YOUR data, not predefined rules.
    """
    print(f"[ml] Creating anomaly detection job '{JOB_ID}'...")

    job_body = {
        # Human-readable description
        "description": (
            "Detects IPs generating abnormally high event volume in security logs. "
            "Catches brute force attacks, port scans, and other anomalous traffic "
            "patterns without hardcoded thresholds. This is Elastic's built-in AI — "
            "no external LLM needed. It learns a baseline and flags statistical "
            "anomalies automatically."
        ),
        # Analysis configuration: what to detect
        "analysis_config": {
            # Bucket span: how often to compute anomaly scores
            # 1 minute gives near-real-time detection granularity
            "bucket_span": "1m",
            # Detectors: what patterns to look for
            "detectors": [
                {
                    # high_count: detect unusually high event volume
                    "function": "high_count",
                    # Partition by source_ip: each IP gets its own model
                    # The ML engine learns what's "normal" for each IP separately
                    "partition_field_name": "source_ip",
                    # Friendly name for the detector
                    "detector_description": "High event count per source IP",
                }
            ],
            # Influencers: fields that help explain anomalies
            # These appear in the anomaly results to help analysts investigate
            "influencers": ["source_ip", "action", "service_name", "user"],
        },
        # Data description: tell ML about the timestamp field
        "data_description": {
            "time_field": "@timestamp",
            "time_format": "epoch_ms",
        },
        # Results are stored in the shared ML results index
        # Accessible at .ml-anomalies-shared for dashboard visualizations
        "results_index_name": "shared",
    }

    resp = es_put(f"/_ml/anomaly_detectors/{JOB_ID}", json=job_body)

    if resp.status_code == 200:
        print(f"[ml] ✅ Anomaly detection job '{JOB_ID}' created.")
        return True
    elif resp.status_code == 409:
        print(f"[ml] Job '{JOB_ID}' already exists (409).")
        return True
    else:
        print(f"[ml] ❌ Failed to create job: {resp.status_code} — {resp.text}")
        return False


# =============================================================================
# Step 2: Create Datafeed
# =============================================================================


def create_datafeed():
    """
    Create a datafeed that continuously reads from security-logs-*.

    The datafeed is the bridge between your data and the ML job:
      - It queries security-logs-* on a schedule
      - Passes the data to the anomaly detection job for analysis
      - Handles pagination, time ranges, and query optimization automatically
    """
    print(f"[ml] Creating datafeed '{DATAFEED_ID}'...")

    datafeed_body = {
        # Link to the anomaly detection job
        "job_id": JOB_ID,
        # Index pattern to read from
        "indices": ["security-logs-*"],
        # Query: read all documents (the ML job handles filtering/analysis)
        "query": {"match_all": {}},
        # Frequency: how often to query for new data
        "frequency": "30s",
        # Scroll size: batch size for each query
        "scroll_size": 1000,
    }

    resp = es_put(f"/_ml/datafeeds/{DATAFEED_ID}", json=datafeed_body)

    if resp.status_code == 200:
        print(f"[ml] ✅ Datafeed '{DATAFEED_ID}' created.")
        return True
    elif resp.status_code == 409:
        print(f"[ml] Datafeed '{DATAFEED_ID}' already exists (409).")
        return True
    else:
        print(f"[ml] ❌ Failed to create datafeed: {resp.status_code} — {resp.text}")
        return False


# =============================================================================
# Step 3: Open Job and Start Datafeed
# =============================================================================


def start_job_and_datafeed():
    """
    Open the ML job and start the datafeed to begin real-time analysis.

    Once started:
      - The ML model immediately begins learning what "normal" looks like
      - Within a few minutes, it builds initial baselines per source_ip
      - Attack simulations (brute force, port scans) create clear anomalies
      - Anomaly scores appear in .ml-anomalies-* for dashboard visualization
    """
    # Open the job (moves it from 'closed' to 'opened' state)
    print(f"[ml] Opening job '{JOB_ID}'...")
    resp = es_post(f"/_ml/anomaly_detectors/{JOB_ID}/_open")
    if resp.status_code == 200:
        print(f"[ml] ✅ Job '{JOB_ID}' opened.")
    else:
        print(f"[ml] Job open response: {resp.status_code} — {resp.text}")

    # Start the datafeed (begins reading from security-logs-*)
    print(f"[ml] Starting datafeed '{DATAFEED_ID}'...")
    resp = es_post(f"/_ml/datafeeds/{DATAFEED_ID}/_start")
    if resp.status_code == 200:
        print(f"[ml] ✅ Datafeed '{DATAFEED_ID}' started — ML analysis is now running!")
    else:
        print(f"[ml] Datafeed start response: {resp.status_code} — {resp.text}")


# =============================================================================
# Step 4: Verify
# =============================================================================


def verify_job():
    """Verify the ML job is running and processing data."""
    print(f"[ml] Verifying job '{JOB_ID}'...")

    resp = es_get(f"/_ml/anomaly_detectors/{JOB_ID}/_stats")
    if resp.status_code == 200:
        stats = resp.json()
        jobs = stats.get("jobs", [])
        if jobs:
            job = jobs[0]
            state = job.get("state", "unknown")
            processed = job.get("data_counts", {}).get("processed_record_count", 0)
            print(f"[ml] Job state: {state}")
            print(f"[ml] Records processed: {processed}")
            print(f"[ml] ✅ ML anomaly detection is {'active' if state == 'opened' else state}.")
    else:
        print(f"[ml] WARNING: Could not verify job: {resp.status_code}")

    # Check datafeed status
    resp = es_get(f"/_ml/datafeeds/{DATAFEED_ID}/_stats")
    if resp.status_code == 200:
        feeds = resp.json().get("datafeeds", [])
        if feeds:
            feed_state = feeds[0].get("state", "unknown")
            print(f"[ml] Datafeed state: {feed_state}")


# =============================================================================
# Main
# =============================================================================


def main():
    print("=" * 60)
    print("[ml] Elastic ML Anomaly Detection Setup")
    print("=" * 60)

    wait_for_elasticsearch()
    verify_license()
    create_anomaly_job()
    create_datafeed()
    start_job_and_datafeed()

    # Give it a moment to start processing
    time.sleep(3)
    verify_job()

    print()
    print("=" * 60)
    print("[ml] ✅ ML setup complete!")
    print("[ml] The model will build baselines over the next few minutes.")
    print("[ml] Attack simulations will show as anomaly spikes in Kibana.")
    print("=" * 60)


if __name__ == "__main__":
    main()
