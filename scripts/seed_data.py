"""
Seed the AEGIS database with a realistic day of activity.

Generates 24 hours of normal authentication and network traffic, then a
recent burst of attacks so every detection has something to find.

Run from the project root, after sql/schema.sql:

    python -m scripts.seed_data

Reads database credentials from .streamlit/secrets.toml (or AEGIS_DB_*
environment variables), the same as the app.
"""

import random
import warnings
from datetime import datetime, timedelta

warnings.filterwarnings("ignore")

from db import get_connection
from utils import simulations, network_simulations as net


HOURS = 24
HOME_COUNTRY = "US"

# Each normal user logs in from one home city, so ordinary activity
# never looks like impossible travel.
USER_HOMES = {
    "jdoe": (30.4213, -87.2169),          # Pensacola, FL
    "asmith": (30.4213, -87.2169),        # Pensacola, FL
    "helpdesk01": (30.4518, -86.6372),    # Fort Walton Beach, FL
    "finance.user": (30.6954, -88.0399),  # Mobile, AL
    "vpn.user": (30.4383, -84.2807),      # Tallahassee, FL
    "sysadmin": (30.4213, -87.2169),      # Pensacola, FL
}
NORMAL_USERS = list(USER_HOMES)


def seed_normal_authentication(count=500):
    """Mostly successful logins from the US, with occasional typos."""
    now = datetime.now()
    rows = []

    for _ in range(count):
        when = now - timedelta(seconds=random.randint(1800, HOURS * 3600))
        user = random.choice(NORMAL_USERS)
        failed = random.random() < 0.06
        home_lat, home_lon = USER_HOMES[user]
        lat = home_lat + random.uniform(-0.05, 0.05)
        lon = home_lon + random.uniform(-0.05, 0.05)

        rows.append((
            when.strftime("%Y-%m-%d %H:%M:%S"),
            f"73.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
            user,
            "login_failed" if failed else "login_success",
            "failed" if failed else "success",
            HOME_COUNTRY,
            random.choice(["Windows", "MacOS", "Web Portal"]),
            lat,
            lon,
        ))

    conn = get_connection()
    cursor = conn.cursor()
    cursor.executemany(
        """
        INSERT INTO events (
            event_time, source_ip, username, event_type, status,
            geo_country, device_type, latitude, longitude
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        rows,
    )
    conn.commit()
    cursor.close()
    conn.close()

    return len(rows)


def seed_normal_network(count=1500):
    """A day of legitimate outbound flows and VPN logins."""
    now = datetime.now()
    events = []

    for _ in range(count):
        dst, port = random.choice(net.NORMAL_DESTINATIONS)
        events.append({
            "event_time": now - timedelta(seconds=random.randint(1800, HOURS * 3600)),
            "event_source": "flow",
            "action": "allow",
            "src_ip": random.choice(net.INTERNAL_HOSTS),
            "src_port": random.randint(49152, 65535),
            "dst_ip": dst,
            "dst_port": port,
            "protocol": "UDP" if port == 53 else "TCP",
            "bytes_out": random.randint(800, 2_500_000),
            "device_name": "FW-EDGE-01",
        })

    for _ in range(60):
        events.append({
            "event_time": now - timedelta(seconds=random.randint(1800, HOURS * 3600)),
            "event_source": "vpn",
            "action": "success",
            "src_ip": f"73.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "username": random.choice(net.VPN_USERS),
            "geo_country": "United States",
            "device_name": "VPN-GW-01",
        })

    net._insert_events(events)
    return len(events)


def seed_recent_attacks():
    """One of each attack, timestamped now, so detections fire."""
    simulations.simulate_brute_force()
    simulations.simulate_password_spray()
    simulations.simulate_impossible_travel()
    simulations.simulate_compromised_account()

    net.simulate_normal_traffic()
    net.simulate_port_scan()
    net.simulate_vpn_brute_force(succeed=True)
    net.simulate_beaconing()
    net.refresh_device_telemetry()


def main():
    print("Seeding AEGIS with 24 hours of activity...")
    print(f"  {seed_normal_authentication()} normal authentication events")
    print(f"  {seed_normal_network()} normal network events")
    seed_recent_attacks()
    print("  1 of each identity and network attack (last 15 minutes)")
    print("\nDone. Start the app with: streamlit run app.py")


if __name__ == "__main__":
    main()
