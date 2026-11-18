"""
Single source of truth for every AEGIS detection rule.

Detections (utils/detections.py, utils/analytics.py), the Detection Rules
page, the Command Center and the Incident Queue all read their thresholds,
rule IDs and MITRE mappings from this file. Change a value here and it
changes everywhere.
"""

DETECTION_RULES = {
    "brute_force": {
        "rule_id": "AEGIS-001",
        "category": "Identity",
        "name": "Brute Force",
        "incident_type": "Brute Force Attempt",
        "threshold": 5,
        "window_minutes": 15,
        "severity": "High / Critical",
        "mitre": "T1110",
        "mitre_name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Detects repeated failed authentication attempts "
            "against the same user from the same source IP."
        ),
        "condition": (
            "5+ failed authentication attempts against the "
            "same user from the same source IP within 15 minutes."
        ),
    },

    "password_spray": {
        "rule_id": "AEGIS-002",
        "category": "Identity",
        "name": "Password Spray",
        "incident_type": "Password Spray",
        "unique_user_threshold": 5,
        "window_minutes": 15,
        "severity": "High",
        "mitre": "T1110.003",
        "mitre_name": "Password Spraying",
        "tactic": "Credential Access",
        "description": (
            "Detects a single source IP attempting authentication "
            "against multiple user accounts."
        ),
        "condition": (
            "Failed authentication attempts from the same source "
            "IP against 5+ unique user accounts within 15 minutes."
        ),
    },

    "account_takeover": {
        "rule_id": "AEGIS-003",
        "category": "Identity",
        "name": "Potential Account Takeover",
        "incident_type": "Potential Account Takeover",
        "failure_threshold": 5,
        "window_minutes": 15,
        "severity": "Critical",
        "mitre": "T1078",
        "mitre_name": "Valid Accounts",
        "tactic": (
            "Initial Access / Persistence / "
            "Privilege Escalation / Defense Evasion"
        ),
        "description": (
            "Detects repeated failed authentication attempts "
            "followed by a successful authentication."
        ),
        "condition": (
            "5+ failed authentication attempts followed by a "
            "successful login for the same user and source IP "
            "within 15 minutes."
        ),
    },

    "impossible_travel": {
        "rule_id": "AEGIS-004",
        "category": "Identity",
        "name": "Impossible Travel",
        "incident_type": "Impossible Travel",
        "max_speed_kmh": 900,
        "min_distance_km": 500,
        "window_minutes": 15,
        "severity": "High",
        "mitre": "T1078",
        "mitre_name": "Valid Accounts",
        "tactic": (
            "Initial Access / Persistence / "
            "Privilege Escalation / Defense Evasion"
        ),
        "description": (
            "Detects consecutive successful authentications for the "
            "same user from locations too far apart to travel between "
            "in the time elapsed."
        ),
        "condition": (
            "Consecutive successful logins for the same user more than "
            "500 km apart, requiring travel faster than 900 km/h "
            "(commercial airliner speed)."
        ),
    },

    # =====================================================
    # NETWORK DETECTIONS
    # =====================================================

    "port_scan": {
        "rule_id": "AEGIS-005",
        "name": "Port Scan",
        "incident_type": "Port Scan",
        "category": "Network",
        "unique_port_threshold": 15,
        "unique_host_threshold": 10,
        "window_minutes": 15,
        "severity": "Medium / High",
        "mitre": "T1046",
        "mitre_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": (
            "Detects a single source probing many ports or hosts "
            "through the edge firewall."
        ),
        "condition": (
            "One source IP connecting to 15+ unique ports or 10+ "
            "unique hosts within 15 minutes."
        ),
    },

    "vpn_brute_force": {
        "rule_id": "AEGIS-006",
        "name": "VPN Brute Force",
        "incident_type": "VPN Brute Force",
        "category": "Network",
        "threshold": 5,
        "window_minutes": 15,
        "severity": "High / Critical",
        "mitre": "T1133",
        "mitre_name": "External Remote Services",
        "tactic": "Initial Access / Persistence",
        "description": (
            "Detects repeated failed VPN authentication for one account "
            "from one source; escalates to Critical if a VPN session "
            "is then established."
        ),
        "condition": (
            "5+ failed VPN logins for the same user from the same "
            "source IP within 15 minutes."
        ),
    },

    "beaconing": {
        "rule_id": "AEGIS-007",
        "name": "C2 Beaconing",
        "incident_type": "C2 Beaconing",
        "category": "Network",
        "min_connections": 8,
        "max_jitter": 0.15,
        "window_minutes": 15,
        "severity": "High",
        "mitre": "T1071",
        "mitre_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": (
            "Detects an internal host contacting the same external "
            "destination at machine-regular intervals, a common sign "
            "of malware check-ins."
        ),
        "condition": (
            "8+ outbound connections from one internal host to the same "
            "external IP and port, with interval variation of 15% or less."
        ),
    },
}


# Window used by pages when selecting recent events for detection
DETECTION_WINDOW_MINUTES = DETECTION_RULES["brute_force"]["window_minutes"]


def mitre_label(rule_key):
    rule = DETECTION_RULES[rule_key]
    return f"{rule['mitre']} - {rule['mitre_name']}"
