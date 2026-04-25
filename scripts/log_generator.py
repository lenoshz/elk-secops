#!/usr/bin/env python3
"""
Security Log Generator — Realistic Attack Simulation
=======================================================
Generates security-enriched application logs with periodic attack simulations.
All logs are written to ./logs/app.log for Filebeat to ship to the ELK stack.

Enriched log format:
    [TIMESTAMP] [LEVEL] [service] [source_ip=x.x.x.x] [user=username] [action=ACTION] - message

Attack simulations run every 5 minutes:
    1. Brute Force    — 15-20 AUTH_FAIL burst from one attacker IP, then AUTH_SUCCESS
    2. Privilege Esc.  — PRIV_ESC_ATTEMPT from auth-service
    3. Port Scan       — Rapid PORT_SCAN errors with incrementing ports

Normal traffic baseline (between attacks):
    INFO  70% | WARN  20% | ERROR  10%
"""

import os
import random
import time
from datetime import datetime, timezone
from pathlib import Path

# =============================================================================
# Configuration
# =============================================================================

# Output file path (relative to working directory)
LOG_FILE = os.environ.get("LOG_OUTPUT", "./logs/app.log")

# Delay between normal log entries (seconds)
MIN_DELAY = 0.5
MAX_DELAY = 2.0

# How often attack simulations run (seconds) — every 5 minutes
ATTACK_INTERVAL = 300

# Delay before the first attack cycle (seconds) — allow stack to warm up
FIRST_ATTACK_DELAY = 60

# =============================================================================
# IP Address Pools
# =============================================================================

# Normal/legitimate user IPs — private ranges, won't produce GeoIP data
NORMAL_IPS = [
    "10.0.1.50",
    "10.0.1.51",
    "10.0.2.100",
    "10.0.2.101",
    "10.0.3.25",
    "192.168.1.10",
]

# Attacker IPs — real routable public IPs that resolve in GeoLite2 database
# These will appear on the Kibana threat map with geographic locations
ATTACKER_IPS = [
    "91.108.4.1",       # Telegram IP range (Europe)
    "1.180.0.1",        # APNIC range (Asia-Pacific)
    "185.220.101.33",   # Known Tor exit node (Europe)
]

# =============================================================================
# User Pools
# =============================================================================

# Legitimate application users
NORMAL_USERS = ["jsmith", "agarcia", "mchen", "kpatel", "rwilson", "ljohnson"]

# Usernames targeted by attackers (high-value accounts)
ATTACKER_TARGETS = ["admin", "root", "administrator", "sysadmin"]

# =============================================================================
# Service Names (simulates a microservices environment)
# =============================================================================

SERVICES = [
    "auth-service",
    "payment-service",
    "order-service",
    "notification-service",
    "api-gateway",
]

# =============================================================================
# Weighted Log Levels for normal traffic
# =============================================================================

LOG_LEVELS = [
    ("INFO", 70),
    ("WARN", 20),
    ("ERROR", 10),
]

# =============================================================================
# Normal Traffic — Actions and Messages per Level
# =============================================================================

NORMAL_TRAFFIC = {
    "INFO": {
        "auth-service": [
            ("LOGIN", "User login successful"),
            ("LOGOUT", "User session ended gracefully"),
            ("TOKEN_REFRESH", "Session token refreshed"),
            ("PASSWORD_RESET", "Password reset email sent"),
            ("OAUTH_VALIDATE", "OAuth2 token validated"),
            ("PROFILE_LOAD", "User profile loaded successfully"),
            ("MFA_PASS", "Two-factor authentication passed"),
        ],
        "payment-service": [
            ("PAYMENT_OK", "Payment processed successfully"),
            ("INVOICE_GEN", "Invoice generated for order"),
            ("REFUND_INIT", "Refund initiated for transaction"),
            ("METHOD_VERIFY", "Payment method verified"),
            ("SUBSCRIPTION_RENEW", "Subscription renewed successfully"),
            ("CURRENCY_CONVERT", "Currency conversion completed"),
        ],
        "order-service": [
            ("ORDER_CREATE", "Order created successfully"),
            ("ORDER_SHIP", "Order status updated to shipped"),
            ("INVENTORY_CHECK", "Inventory check passed"),
            ("ORDER_CONFIRM", "Order confirmation email queued"),
            ("CART_CHECKOUT", "Cart checkout completed"),
            ("DISCOUNT_APPLY", "Discount code applied to order"),
        ],
        "notification-service": [
            ("PUSH_SEND", "Push notification delivered"),
            ("EMAIL_SEND", "Email sent to user"),
            ("SMS_QUEUE", "SMS notification queued"),
            ("WEBHOOK_OK", "Webhook callback processed"),
            ("PREF_UPDATE", "Notification preferences updated"),
            ("BATCH_COMPLETE", "Batch email job completed"),
        ],
        "api-gateway": [
            ("REQUEST_OK", "Request processed in 45ms"),
            ("RATE_CHECK", "Rate limit check passed"),
            ("ROUTE_OK", "Request routed to upstream service"),
            ("HEALTH_OK", "Health check endpoint responded OK"),
            ("API_KEY_OK", "API key validated successfully"),
            ("CORS_OK", "CORS preflight request handled"),
        ],
    },
    "WARN": {
        "auth-service": [
            ("LOGIN_WARN", "Failed login attempt detected"),
            ("SESSION_WARN", "Session nearing expiration"),
            ("DEPRECATED_CALL", "Deprecated auth endpoint called"),
            ("GEO_ANOMALY", "Unusual login location detected"),
        ],
        "payment-service": [
            ("PAYMENT_RETRY", "Payment retry attempt #2"),
            ("GATEWAY_SLOW", "Slow response from payment gateway"),
            ("RATE_STALE", "Currency conversion rate stale"),
            ("LIMIT_WARN", "Payment amount exceeds daily limit"),
        ],
        "order-service": [
            ("LOW_INVENTORY", "Low inventory for product SKU-4821"),
            ("ORDER_DELAY", "Order processing delayed"),
            ("SHIP_UNAVAIL", "Shipping estimate unavailable"),
            ("DUP_DETECT", "Duplicate order detection triggered"),
        ],
        "notification-service": [
            ("EMAIL_DELAY", "Email delivery delayed"),
            ("PUSH_DEGRADED", "Push notification service degraded"),
            ("SMS_SLOW", "SMS gateway response slow"),
            ("QUEUE_BACKLOG", "Notification queue backlog growing"),
        ],
        "api-gateway": [
            ("LATENCY_WARN", "Request latency exceeded 500ms"),
            ("RATE_LIMIT_80", "Rate limit threshold at 80%"),
            ("UPSTREAM_SLOW", "Upstream service response slow"),
            ("TLS_EXPIRING", "TLS certificate expires in 7 days"),
        ],
    },
    "ERROR": {
        "auth-service": [
            ("AUTH_ERROR", "Authentication service unavailable"),
            ("TOKEN_FAIL", "Token validation failed: signature mismatch"),
            ("DB_POOL_EXHAUSTED", "Database connection pool exhausted"),
            ("LDAP_REFUSED", "LDAP server connection refused"),
        ],
        "payment-service": [
            ("GATEWAY_TIMEOUT", "Payment gateway timeout after 30s"),
            ("PAYMENT_FAIL", "Payment failed: insufficient funds"),
            ("DB_TIMEOUT", "Database timeout during transaction commit"),
            ("STRIPE_500", "Stripe API returned 500 Internal Server Error"),
        ],
        "order-service": [
            ("DEADLOCK", "Order processing failed: database deadlock"),
            ("INVENTORY_503", "Inventory service returned 503"),
            ("STATUS_FAIL", "Failed to update order status"),
            ("CART_ERROR", "Cart validation error: item out of stock"),
        ],
        "notification-service": [
            ("EMAIL_REFUSED", "Email service connection refused"),
            ("PUSH_FAIL", "Push notification delivery failed"),
            ("SMS_429", "SMS gateway returned error code 429"),
            ("WEBHOOK_FAIL", "Webhook delivery failed after 3 retries"),
        ],
        "api-gateway": [
            ("BAD_GATEWAY", "Upstream service returned 502 Bad Gateway"),
            ("CIRCUIT_OPEN", "Circuit breaker opened for order-service"),
            ("API_KEY_FAIL", "Request authentication failed: invalid API key"),
            ("CONN_POOL_FULL", "Connection pool exhausted — dropping request"),
        ],
    },
}


# =============================================================================
# Formatting
# =============================================================================


def timestamp_now() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def format_log(
    level: str, service: str, source_ip: str, user: str, action: str, message: str
) -> str:
    """Format a single enriched log line."""
    ts = timestamp_now()
    return f"[{ts}] [{level}] [{service}] [source_ip={source_ip}] [user={user}] [action={action}] - {message}"


def write_log(
    f,
    level: str,
    service: str,
    source_ip: str,
    user: str,
    action: str,
    message: str,
) -> None:
    """Write a formatted log entry to the output file."""
    entry = format_log(level, service, source_ip, user, action, message)
    f.write(entry + "\n")
    f.flush()


# =============================================================================
# Normal Traffic Generation
# =============================================================================


def pick_level() -> str:
    """Select a log level based on weighted distribution (INFO 70%, WARN 20%, ERROR 10%)."""
    levels, weights = zip(*LOG_LEVELS)
    return random.choices(levels, weights=weights, k=1)[0]


def generate_normal_log(f) -> None:
    """Generate a single normal traffic log entry with random service/level/action."""
    level = pick_level()
    service = random.choice(SERVICES)
    source_ip = random.choice(NORMAL_IPS)
    user = random.choice(NORMAL_USERS)
    action, message = random.choice(NORMAL_TRAFFIC[level][service])
    write_log(f, level, service, source_ip, user, action, message)


# =============================================================================
# Attack Simulations
# =============================================================================

# --- Attack 1: Brute Force ---------------------------------------------------
# Simulates a credential stuffing/brute force attack:
#   - 15-20 rapid AUTH_FAIL events from the same attacker IP
#   - All targeting the same high-value account (admin/root)
#   - Followed by one AUTH_SUCCESS (simulating a successful breach)
# MITRE ATT&CK: T1110 (Brute Force)
# -----------------------------------------------------------------------------

def simulate_brute_force(f) -> None:
    """Simulate a brute force attack followed by a successful login."""
    attacker_ip = random.choice(ATTACKER_IPS)
    target_user = random.choice(ATTACKER_TARGETS)
    num_attempts = random.randint(15, 20)

    print(f"[secops] 🔴 Brute force attack: {num_attempts} attempts from {attacker_ip} targeting '{target_user}'")

    for i in range(num_attempts):
        write_log(
            f, "ERROR", "auth-service", attacker_ip, target_user, "AUTH_FAIL",
            f"Brute force login attempt #{i + 1} failed for user {target_user}"
        )
        # ~1.0-1.8s between attempts → 15-20 events in ~25-30 seconds
        time.sleep(random.uniform(1.0, 1.8))

    # Successful breach after brute force storm
    # MITRE ATT&CK: T1078 (Valid Accounts) — breach confirmation
    print(f"[secops] 🔴 Breach simulation: AUTH_SUCCESS from attacker {attacker_ip}")
    write_log(
        f, "INFO", "auth-service", attacker_ip, target_user, "AUTH_SUCCESS",
        f"User {target_user} logged in successfully after multiple failed attempts"
    )


# --- Attack 2: Privilege Escalation -------------------------------------------
# Simulates a user attempting to access resources beyond their privilege level.
# MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation)
# -----------------------------------------------------------------------------

def simulate_privilege_escalation(f) -> None:
    """Simulate a privilege escalation attempt."""
    attacker_ip = random.choice(ATTACKER_IPS)
    user = random.choice(["jdoe", "temp_contractor", "intern01"])

    print(f"[secops] 🟡 Privilege escalation attempt from {attacker_ip} as '{user}'")
    write_log(
        f, "WARN", "auth-service", attacker_ip, user, "PRIV_ESC_ATTEMPT",
        "User attempted to access admin endpoint without privilege"
    )
    # Additional suspicious follow-up actions
    write_log(
        f, "WARN", "auth-service", attacker_ip, user, "PRIV_ESC_ATTEMPT",
        "Unauthorized access to /api/admin/users endpoint blocked"
    )
    write_log(
        f, "WARN", "auth-service", attacker_ip, user, "PRIV_ESC_ATTEMPT",
        "Attempted to modify user role from 'viewer' to 'admin'"
    )


# --- Attack 3: Port Scan -----------------------------------------------------
# Simulates a network reconnaissance scan testing sequential ports.
# Appears as rapid ERROR logs from the api-gateway with incrementing port numbers.
# MITRE ATT&CK: T1046 (Network Service Discovery)
# -----------------------------------------------------------------------------

def simulate_port_scan(f) -> None:
    """Simulate a port scan with rapidly incrementing port numbers."""
    attacker_ip = random.choice(ATTACKER_IPS)
    start_port = random.randint(1000, 8000)
    num_ports = random.randint(8, 15)

    print(f"[secops] 🟠 Port scan from {attacker_ip}: ports {start_port}-{start_port + num_ports}")

    for i in range(num_ports):
        port = start_port + i
        write_log(
            f, "ERROR", "api-gateway", attacker_ip, "-", "PORT_SCAN",
            f"Connection refused on port {port}"
        )
        # Very rapid — port scans are fast
        time.sleep(random.uniform(0.1, 0.3))


def run_attack_cycle(f, cycle_num: int) -> None:
    """Run all three attack simulations in sequence."""
    print(f"\n{'='*60}")
    print(f"[secops] ⚔️  Attack simulation cycle #{cycle_num}")
    print(f"{'='*60}")

    # Attack 1: Brute force with breach
    simulate_brute_force(f)

    # Brief pause between attacks (looks more realistic)
    time.sleep(random.uniform(2.0, 5.0))

    # Attack 2: Privilege escalation
    simulate_privilege_escalation(f)

    time.sleep(random.uniform(1.0, 3.0))

    # Attack 3: Port scan
    simulate_port_scan(f)

    print(f"[secops] ✅ Attack cycle #{cycle_num} complete\n")


# =============================================================================
# Main Loop
# =============================================================================


def main():
    """Main loop: generate normal traffic with periodic attack simulations."""
    log_path = Path(LOG_FILE)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[log-generator] Writing logs to: {log_path.resolve()}")
    print(f"[log-generator] Normal traffic: INFO=70%, WARN=20%, ERROR=10%")
    print(f"[log-generator] Attack simulations every {ATTACK_INTERVAL}s")
    print(f"[log-generator] First attack in {FIRST_ATTACK_DELAY}s")
    print(f"[log-generator] Attacker IPs: {', '.join(ATTACKER_IPS)}")
    print()

    start_time = time.time()
    last_attack_time = start_time - ATTACK_INTERVAL + FIRST_ATTACK_DELAY
    attack_cycle = 0
    normal_count = 0

    with open(log_path, "a", buffering=1, encoding="utf-8") as f:
        while True:
            current_time = time.time()

            # Check if it's time for an attack simulation
            if current_time - last_attack_time >= ATTACK_INTERVAL:
                attack_cycle += 1
                run_attack_cycle(f, attack_cycle)
                last_attack_time = time.time()
            else:
                # Normal baseline traffic between attacks
                generate_normal_log(f)
                normal_count += 1

                if normal_count % 50 == 0:
                    elapsed = int(current_time - start_time)
                    next_attack = int(ATTACK_INTERVAL - (current_time - last_attack_time))
                    print(
                        f"[log-generator] {normal_count} normal logs | "
                        f"{attack_cycle} attack cycles | "
                        f"next attack in {next_attack}s | "
                        f"uptime {elapsed}s"
                    )

                time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))


if __name__ == "__main__":
    main()
