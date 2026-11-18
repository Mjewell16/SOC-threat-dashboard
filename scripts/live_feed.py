"""
AEGIS live feed: keeps the dashboard running like a real SOC.

Continuously writes normal authentication and network traffic, launches a
random attack every few minutes, occasionally takes a switch offline (and
brings it back), polls device health, and deletes old telemetry so the
database doesn't grow forever.

Run from the project root in its own Terminal window, while the app runs
in another:

    python -m scripts.live_feed

Options:
    --attack-every 5     minutes between attacks (default 5)
    --noise-every 10     seconds between batches of normal traffic (default 10)
    --retention-days 3   delete events older than this (default 3, 0 = never)
    --no-outages         never take switches offline

Press Ctrl+C to stop.
"""

import argparse
import random
import time
import warnings
from datetime import datetime, timedelta

warnings.filterwarnings("ignore")

from db import get_connection
from scripts.seed_data import USER_HOMES
from utils import simulations, network_simulations as net


# =========================================================
# LOGGING
# =========================================================

COLORS = {
    "info": "\033[36m",     # cyan
    "attack": "\033[91m",   # red
    "ok": "\033[92m",       # green
    "warn": "\033[93m",     # yellow
    "reset": "\033[0m",
}


def log(message, kind="info"):
    stamp = datetime.now().strftime("%H:%M:%S")
    print(f"{COLORS[kind]}[{stamp}] {message}{COLORS['reset']}", flush=True)


# =========================================================
# NORMAL TRAFFIC
# =========================================================

def write_normal_authentication(count):
    """A few ordinary logins from each user's home city."""
    now = datetime.now()
    rows = []

    for _ in range(count):
        user = random.choice(list(USER_HOMES))
        failed = random.random() < 0.06
        home_lat, home_lon = USER_HOMES[user]

        rows.append((
            (now - timedelta(seconds=random.randint(0, 5))).strftime("%Y-%m-%d %H:%M:%S"),
            f"73.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
            user,
            "login_failed" if failed else "login_success",
            "failed" if failed else "success",
            "US",
            random.choice(["Windows", "MacOS", "Web Portal"]),
            home_lat + random.uniform(-0.05, 0.05),
            home_lon + random.uniform(-0.05, 0.05),
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


def write_normal_network(count):
    """Ordinary outbound web/DNS flows timestamped right now."""
    now = datetime.now()
    events = []

    for _ in range(count):
        dst, port = random.choice(net.NORMAL_DESTINATIONS)
        events.append({
            "event_time": now - timedelta(seconds=random.randint(0, 5)),
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

    if random.random() < 0.3:
        events.append({
            "event_time": now,
            "event_source": "vpn",
            "action": "success",
            "src_ip": f"73.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "username": random.choice(net.VPN_USERS),
            "geo_country": "United States",
            "device_name": "VPN-GW-01",
        })

    net._insert_events(events)


# =========================================================
# ATTACKS
# =========================================================

def attack_brute_force():
    ip, user, country = simulations.simulate_brute_force()
    return f"Brute force: {ip} ({country}) → {user}"


def attack_password_spray():
    ip, users, country = simulations.simulate_password_spray()
    return f"Password spray: {ip} ({country}) → {len(users)} accounts"


def attack_impossible_travel():
    user, _, c1, _, c2 = simulations.simulate_impossible_travel()
    return f"Impossible travel: {user} {c1} → {c2}"


def attack_account_takeover():
    ip, user, country = simulations.simulate_compromised_account()
    return f"Account takeover: {ip} ({country}) → {user}"


def attack_port_scan():
    ip, target, role, ports = net.simulate_port_scan()
    return f"Port scan: {ip} → {target} ({role}), {ports} ports"


def attack_vpn_brute_force():
    succeed = random.random() < 0.3
    ip, user, country, attempts = net.simulate_vpn_brute_force(succeed=succeed)
    result = " — SESSION ESTABLISHED" if succeed else ""
    return f"VPN brute force: {ip} ({country}) → {user}, {attempts} attempts{result}"


def attack_beaconing():
    src, dst, port, interval = net.simulate_beaconing()
    return f"C2 beaconing: {src} → {dst}:{port} every ~{interval}s"


# (function, relative weight) — common attacks happen more often
ATTACKS = [
    (attack_brute_force, 3),
    (attack_password_spray, 2),
    (attack_port_scan, 3),
    (attack_vpn_brute_force, 2),
    (attack_impossible_travel, 1),
    (attack_account_takeover, 1),
    (attack_beaconing, 1),
]


def launch_random_attack():
    functions, weights = zip(*ATTACKS)
    attack = random.choices(functions, weights=weights, k=1)[0]
    return attack()


# =========================================================
# CLEANUP
# =========================================================

def delete_old_telemetry(retention_days):
    """Remove events older than the retention period."""
    conn = get_connection()
    cursor = conn.cursor()
    removed = 0

    for table in ("events", "network_events"):
        cursor.execute(
            f"DELETE FROM {table} WHERE event_time < NOW() - INTERVAL %s DAY",
            (retention_days,),
        )
        removed += cursor.rowcount

    conn.commit()
    cursor.close()
    conn.close()
    return removed


# =========================================================
# MAIN LOOP
# =========================================================

def main():
    parser = argparse.ArgumentParser(description="AEGIS live telemetry feed")
    parser.add_argument("--attack-every", type=float, default=5,
                        help="minutes between attacks (default 5)")
    parser.add_argument("--noise-every", type=float, default=10,
                        help="seconds between normal traffic batches (default 10)")
    parser.add_argument("--retention-days", type=int, default=3,
                        help="delete events older than this many days (0 = never)")
    parser.add_argument("--no-outages", action="store_true",
                        help="never take switches offline")
    args = parser.parse_args()

    attack_interval = args.attack_every * 60
    noise_interval = args.noise_every
    device_poll_interval = 60
    cleanup_interval = 3600
    outage_chance_per_hour = 0.5
    outage_duration = 4 * 60

    log("AEGIS live feed started. Press Ctrl+C to stop.", "ok")
    log(f"Normal traffic every {noise_interval:g}s, an attack every ~{args.attack_every:g} min")
    if args.retention_days:
        log(f"Keeping {args.retention_days} days of telemetry")

    now = time.monotonic()
    # First attack lands in ~30 seconds so you see something quickly
    next_attack = now + 30
    next_noise = now
    next_poll = now
    next_cleanup = now + 60
    outage_restore_at = None
    noise_batches = 0

    while True:
        now = time.monotonic()

        try:
            if now >= next_noise:
                write_normal_authentication(random.randint(1, 3))
                write_normal_network(random.randint(5, 15))
                noise_batches += 1
                if noise_batches % 30 == 0:
                    log(f"{noise_batches} batches of normal traffic written")
                next_noise = now + noise_interval

            if now >= next_attack:
                log(launch_random_attack(), "attack")
                # ±30% so attacks don't arrive on an obvious timer
                next_attack = now + attack_interval * random.uniform(0.7, 1.3)

            if now >= next_poll:
                net.refresh_device_telemetry()

                if outage_restore_at and now >= outage_restore_at:
                    net.restore_all_devices()
                    log("All network devices restored", "ok")
                    outage_restore_at = None

                elif (
                    not args.no_outages
                    and not outage_restore_at
                    and random.random() < outage_chance_per_hour * device_poll_interval / 3600
                ):
                    device = net.simulate_device_outage()
                    if device:
                        log(f"Switch outage: {device} is down", "warn")
                        outage_restore_at = now + outage_duration

                next_poll = now + device_poll_interval

            if args.retention_days and now >= next_cleanup:
                try:
                    removed = delete_old_telemetry(args.retention_days)
                    if removed:
                        log(f"Cleanup: removed {removed} events older than "
                            f"{args.retention_days} days")
                except Exception as error:
                    if "DELETE command denied" in str(error):
                        log("Cleanup skipped: aegis_app has no DELETE permission. "
                            "Run sql/grant_cleanup.sql as root to enable it.", "warn")
                    else:
                        raise
                next_cleanup = now + cleanup_interval

        except KeyboardInterrupt:
            raise
        except Exception as error:
            log(f"Error: {error}. Retrying in 10 seconds.", "warn")
            time.sleep(10)
            continue

        time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("Live feed stopped.", "ok")
