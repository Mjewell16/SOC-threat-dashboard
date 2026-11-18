MITRE_TECHNIQUES = {
    "T1110": {
        "technique_id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use repeated authentication attempts to obtain valid "
            "credentials for an account."
        ),
        "recommended_actions": [
            "Review the source IP and targeted account for related activity.",
            "Check whether any successful authentication followed the failures.",
            "Temporarily block or monitor the source if activity continues.",
            "Reset credentials if account compromise is suspected.",
        ],
    },
    "T1110.003": {
        "technique_id": "T1110.003",
        "name": "Password Spraying",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may try one or a small number of commonly used passwords "
            "against many accounts to avoid lockout thresholds."
        ),
        "recommended_actions": [
            "Review all accounts targeted by the source IP.",
            "Check for successful authentications from the same source.",
            "Inspect authentication logs for repeated low-volume failures across users.",
            "Enforce MFA or password resets for accounts showing suspicious success activity.",
        ],
    },
    "T1078": {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence / Privilege Escalation / Defense Evasion",
        "description": (
            "Adversaries may obtain and abuse valid credentials to access systems, "
            "services, or data while appearing to be a legitimate user."
        ),
        "recommended_actions": [
            "Validate whether the authentication activity is expected for the user.",
            "Compare source IP, country, device, and timing with the user's normal activity.",
            "Review successful sessions and related events for signs of follow-on activity.",
            "Revoke sessions and reset credentials if compromise is confirmed or strongly suspected.",
        ],
    },
    "T1046": {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may scan for services running on remote hosts and "
            "network devices to find openings for further attack."
        ),
        "recommended_actions": [
            "Confirm the scanning source is not an authorized vulnerability scanner.",
            "Block the source IP at the edge firewall if it is external.",
            "Review which ports were allowed and whether those services are exposed intentionally.",
            "Watch for follow-on connections from the same source to the open ports.",
        ],
    },
    "T1133": {
        "technique_id": "T1133",
        "name": "External Remote Services",
        "tactic": "Initial Access / Persistence",
        "description": (
            "Adversaries may use external remote services such as VPNs to "
            "gain initial access to or persist within a network."
        ),
        "recommended_actions": [
            "Check whether any VPN session was established from the source IP.",
            "Lock or reset the targeted account and confirm MFA is enforced on the VPN.",
            "Block or geo-restrict the source at the VPN gateway.",
            "Review VPN logs for other accounts targeted from the same source.",
        ],
    },
    "T1071": {
        "technique_id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using common application layer "
            "protocols such as HTTPS to blend command-and-control traffic "
            "in with normal network activity."
        ),
        "recommended_actions": [
            "Isolate the internal host from the network pending investigation.",
            "Block the destination IP and domain at the firewall and DNS layer.",
            "Check other hosts for connections to the same destination.",
            "Collect host artifacts (processes, scheduled tasks) for malware analysis.",
        ],
    },
}


def _extract_technique_id(mitre_value):
    if not mitre_value:
        return None

    return str(mitre_value).split(" - ", 1)[0].strip()


def get_mitre_context(mitre_value=None, incident_type=None):
    technique_id = _extract_technique_id(mitre_value)

    if technique_id in MITRE_TECHNIQUES:
        return MITRE_TECHNIQUES[technique_id]

    incident_lookup = {
        "Brute Force": "T1110",
        "Brute Force Attempt": "T1110",
        "Password Spray": "T1110.003",
        "Impossible Travel": "T1078",
        "Potential Account Takeover": "T1078",
        "Port Scan": "T1046",
        "VPN Brute Force": "T1133",
        "C2 Beaconing": "T1071",
    }

    fallback_id = incident_lookup.get(incident_type)

    if fallback_id:
        return MITRE_TECHNIQUES[fallback_id]

    return {
        "technique_id": technique_id or "Unknown",
        "name": "Unmapped Technique",
        "tactic": "Unmapped",
        "description": "No ATT&CK context is currently mapped to this incident.",
        "recommended_actions": [
            "Review the evidence and determine the appropriate response based on the activity observed."
        ],
    }
