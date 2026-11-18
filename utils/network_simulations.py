"""
AEGIS network attack and traffic simulations.

Writes Zeek/NetFlow-style firewall, VPN and flow events into the
network_events table. All internal addresses use the fictional
10.10.0.0/16 lab network.
"""

import random
from datetime import datetime, timedelta

from db import get_connection


INTERNAL_HOSTS = [f"10.10.20.{n}" for n in range(20, 60)] + [
    f"10.10.30.{n}" for n in range(20, 60)
]

SERVERS = {
    "10.10.5.10": "File Server",
    "10.10.5.11": "Domain Controller",
    "10.10.5.12": "Web Server",
    "10.10.5.13": "Database Server",
}

# (external IP, country) — documentation/test ranges where possible
EXTERNAL_SOURCES = [
    ("185.220.101.12", "Germany"),
    ("45.155.205.233", "Netherlands"),
    ("103.27.202.11", "India"),
    ("91.198.174.192", "Ukraine"),
    ("179.43.159.20", "Brazil"),
    ("203.0.113.45", "Unknown"),
    ("198.51.100.77", "United States"),
]

# Legitimate destinations for background traffic
NORMAL_DESTINATIONS = [
    ("142.250.190.78", 443),   # web
    ("52.96.165.2", 443),      # mail / SaaS
    ("13.107.42.14", 443),
    ("151.101.1.69", 443),
    ("8.8.8.8", 53),           # DNS
    ("1.1.1.1", 53),
]

C2_DESTINATIONS = [
    ("203.0.113.66", 443),
    ("198.51.100.23", 8443),
    ("192.0.2.150", 80),
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 5985, 8080, 8443, 9200,
]

VPN_USERS = [
    "jdoe", "asmith", "contractor01", "helpdesk01",
    "finance.user", "vpn.user", "sysadmin",
]


def _insert_events(events):
    if not events:
        return

    conn = get_connection()
    cursor = conn.cursor()

    cursor.executemany(
        """
        INSERT INTO network_events (
            event_time, event_source, action, src_ip, src_port,
            dst_ip, dst_port, protocol, bytes_out, username,
            geo_country, device_name
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        [
            (
                e["event_time"].strftime("%Y-%m-%d %H:%M:%S"),
                e["event_source"],
                e["action"],
                e["src_ip"],
                e.get("src_port"),
                e.get("dst_ip"),
                e.get("dst_port"),
                e.get("protocol", "TCP"),
                e.get("bytes_out", 0),
                e.get("username"),
                e.get("geo_country"),
                e.get("device_name"),
            )
            for e in events
        ],
    )

    conn.commit()
    cursor.close()
    conn.close()


def _ephemeral_port():
    return random.randint(49152, 65535)


# =========================================================
# BACKGROUND TRAFFIC
# =========================================================

def simulate_normal_traffic(count=150):
    """Legitimate outbound flows and allowed firewall traffic."""
    now = datetime.now()
    events = []

    for _ in range(count):
        src = random.choice(INTERNAL_HOSTS)
        dst, port = random.choice(NORMAL_DESTINATIONS)
        events.append({
            "event_time": now - timedelta(seconds=random.randint(0, 900)),
            "event_source": "flow",
            "action": "allow",
            "src_ip": src,
            "src_port": _ephemeral_port(),
            "dst_ip": dst,
            "dst_port": port,
            "protocol": "UDP" if port == 53 else "TCP",
            "bytes_out": random.randint(800, 2_500_000),
            "device_name": "FW-EDGE-01",
        })

    # A few legitimate VPN logins
    for user in random.sample(VPN_USERS, 3):
        events.append({
            "event_time": now - timedelta(seconds=random.randint(0, 900)),
            "event_source": "vpn",
            "action": "success",
            "src_ip": f"73.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "username": user,
            "geo_country": "United States",
            "device_name": "VPN-GW-01",
        })

    _insert_events(events)
    return len(events)


# =========================================================
# PORT SCAN (T1046)
# =========================================================

def simulate_port_scan():
    src, country = random.choice(EXTERNAL_SOURCES)
    target = random.choice(list(SERVERS))
    now = datetime.now()
    events = []

    ports = random.sample(COMMON_PORTS, len(COMMON_PORTS))

    for offset, port in enumerate(ports):
        open_port = port in (80, 443)
        events.append({
            "event_time": now - timedelta(seconds=len(ports) - offset),
            "event_source": "firewall",
            "action": "allow" if open_port else "deny",
            "src_ip": src,
            "src_port": _ephemeral_port(),
            "dst_ip": target,
            "dst_port": port,
            "protocol": "TCP",
            "bytes_out": 60,
            "geo_country": country,
            "device_name": "FW-EDGE-01",
        })

    _insert_events(events)
    return src, target, SERVERS[target], len(ports)


# =========================================================
# VPN BRUTE FORCE (T1133)
# =========================================================

def simulate_vpn_brute_force(succeed=False):
    src, country = random.choice(EXTERNAL_SOURCES)
    user = random.choice(VPN_USERS)
    now = datetime.now()
    attempts = random.randint(8, 14)
    events = []

    for i in range(attempts):
        events.append({
            "event_time": now - timedelta(seconds=(attempts - i) * 4),
            "event_source": "vpn",
            "action": "failed",
            "src_ip": src,
            "username": user,
            "geo_country": country,
            "device_name": "VPN-GW-01",
        })

    if succeed:
        events.append({
            "event_time": now,
            "event_source": "vpn",
            "action": "success",
            "src_ip": src,
            "username": user,
            "geo_country": country,
            "device_name": "VPN-GW-01",
        })

    _insert_events(events)
    return src, user, country, attempts


# =========================================================
# BEACONING / C2 (T1071)
# =========================================================

def simulate_beaconing():
    src = random.choice(INTERNAL_HOSTS)
    dst, port = random.choice(C2_DESTINATIONS)
    interval = random.choice([30, 45, 60])
    beacons = 12
    now = datetime.now()
    events = []

    # Backdated so the full pattern sits inside the detection window
    for i in range(beacons):
        jitter = random.uniform(-2, 2)
        events.append({
            "event_time": now - timedelta(seconds=(beacons - i) * interval + jitter),
            "event_source": "flow",
            "action": "allow",
            "src_ip": src,
            "src_port": _ephemeral_port(),
            "dst_ip": dst,
            "dst_port": port,
            "protocol": "TCP",
            "bytes_out": random.randint(200, 600),
            "device_name": "FW-EDGE-01",
        })

    _insert_events(events)
    return src, dst, port, interval


# =========================================================
# DEVICE HEALTH
# =========================================================

def refresh_device_telemetry():
    """Randomly vary CPU and bandwidth on devices that are up."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT device_name, capacity_mbps FROM network_devices WHERE status != 'Down'"
    )

    for device_name, capacity in cursor.fetchall():
        cursor.execute(
            """
            UPDATE network_devices
            SET cpu_percent = %s,
                bandwidth_mbps = %s,
                last_seen = %s
            WHERE device_name = %s
            """,
            (
                random.randint(8, 55),
                int(capacity * random.uniform(0.1, 0.7)),
                datetime.now(),
                device_name,
            ),
        )

    conn.commit()
    cursor.close()
    conn.close()


def simulate_device_outage():
    """Take a random access switch down."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT device_name FROM network_devices "
        "WHERE device_type = 'Access Switch' AND status = 'Up'"
    )
    candidates = [row[0] for row in cursor.fetchall()]

    if not candidates:
        cursor.close()
        conn.close()
        return None

    device = random.choice(candidates)

    cursor.execute(
        """
        UPDATE network_devices
        SET status = 'Down', bandwidth_mbps = 0, cpu_percent = 0,
            interface_errors = interface_errors + %s
        WHERE device_name = %s
        """,
        (random.randint(40, 200), device),
    )

    conn.commit()
    cursor.close()
    conn.close()
    return device


def restore_all_devices():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE network_devices
        SET status = 'Up', interface_errors = 0, last_seen = %s
        """,
        (datetime.now(),),
    )

    conn.commit()
    cursor.close()
    conn.close()

    refresh_device_telemetry()
