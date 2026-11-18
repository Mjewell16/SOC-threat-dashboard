# utils/simulations.py

import random
from datetime import datetime

from db import get_connection


location_lookup = {
    "US": (37.0902, -95.7129, 15),
    "Russia": (61.5240, 105.3188, 18),
    "China": (35.8617, 104.1954, 12),
    "Germany": (51.1657, 10.4515, 4),
    "India": (20.5937, 78.9629, 10),
    "Brazil": (-14.2350, -51.9253, 14),
    "North Korea": (40.3399, 127.5101, 3),
    "Iran": (32.4279, 53.6880, 6),
    "Ukraine": (48.3794, 31.1656, 5),
    "United Kingdom": (55.3781, -3.4360, 3),
    "Canada": (56.1304, -106.3468, 16),
    "France": (46.2276, 2.2137, 4),
    "Japan": (36.2048, 138.2529, 4),
    "South Korea": (35.9078, 127.7669, 3),
    "Australia": (-25.2744, 133.7751, 14),
    "Mexico": (23.6345, -102.5528, 8),
    "Netherlands": (52.1326, 5.2913, 2),
    "Turkey": (38.9637, 35.2433, 7),
    "South Africa": (-30.5595, 22.9375, 10),
    "Singapore": (1.3521, 103.8198, 1),
    "Italy": (41.8719, 12.5674, 4),
    "Spain": (40.4637, -3.7492, 5),
    "Sweden": (60.1282, 18.6435, 6),
    "Norway": (60.4720, 8.4689, 7),
    "Argentina": (-38.4161, -63.6167, 10),
}


attack_sources = [
    ("185.220.101.12", "Russia"),
    ("45.155.205.233", "Germany"),
    ("36.110.10.88", "China"),
    ("103.27.202.11", "India"),
    ("91.198.174.192", "Ukraine"),
    ("179.43.159.20", "Brazil"),
    ("102.129.145.88", "Iran"),
    ("37.120.193.219", "United Kingdom"),
    ("175.45.176.15", "North Korea"),
    ("198.51.100.77", "US"),
    ("24.48.0.1", "Canada"),
    ("51.158.68.133", "France"),
    ("133.242.0.1", "Japan"),
    ("211.234.10.20", "South Korea"),
    ("1.120.0.1", "Australia"),
    ("189.203.240.1", "Mexico"),
    ("145.100.0.1", "Netherlands"),
    ("88.255.0.1", "Turkey"),
    ("41.76.0.1", "South Africa"),
    ("139.59.0.1", "Singapore"),
]


target_users = [
    "admin",
    "sysadmin",
    "jdoe",
    "asmith",
    "contractor01",
    "guest.user",
    "service.account",
    "helpdesk01",
    "finance.user",
    "vpn.user",
]


def get_coordinates(country):
    base_lat, base_lon, spread = location_lookup[country]

    lat = base_lat + random.uniform(-spread, spread)
    lon = base_lon + random.uniform(-spread, spread)

    return lat, lon


def append_login_event(
    username,
    password,
    source_ip,
    country,
):
    correct_password = "Start26"

    status = (
        "success"
        if password == correct_password
        else "failed"
    )

    event_type = (
        "login_success"
        if status == "success"
        else "login_failed"
    )

    lat, lon = get_coordinates(country)

    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO events (
            event_time,
            source_ip,
            username,
            event_type,
            status,
            geo_country,
            device_type,
            latitude,
            longitude
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    values = (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        source_ip,
        username,
        event_type,
        status,
        country,
        "Web Portal",
        lat,
        lon,
    )

    cursor.execute(query, values)
    conn.commit()

    cursor.close()
    conn.close()

    return status


def simulate_brute_force():
    source_ip, country = random.choice(attack_sources)
    username = random.choice(target_users)

    for _ in range(10):
        append_login_event(
            username=username,
            password="wrongpassword",
            source_ip=source_ip,
            country=country,
        )

    return source_ip, username, country


def simulate_password_spray():
    source_ip, country = random.choice(attack_sources)

    sprayed_users = random.sample(
        target_users,
        min(8, len(target_users)),
    )

    for username in sprayed_users:
        append_login_event(
            username=username,
            password="Summer2026!",
            source_ip=source_ip,
            country=country,
        )

    return source_ip, sprayed_users, country


def simulate_impossible_travel():
    username = random.choice(target_users)

    travel_pairs = [
        (
            ("198.51.100.77", "US"),
            ("133.242.0.1", "Japan"),
        ),
        (
            ("37.120.193.219", "United Kingdom"),
            ("1.120.0.1", "Australia"),
        ),
        (
            ("24.48.0.1", "Canada"),
            ("139.59.0.1", "Singapore"),
        ),
        (
            ("45.155.205.233", "Germany"),
            ("181.0.0.1", "Argentina"),
        ),
    ]

    source_one, source_two = random.choice(travel_pairs)

    source_ip_1, country_1 = source_one
    source_ip_2, country_2 = source_two

    append_login_event(
        username=username,
        password="Start26",
        source_ip=source_ip_1,
        country=country_1,
    )

    append_login_event(
        username=username,
        password="Start26",
        source_ip=source_ip_2,
        country=country_2,
    )

    return (
        username,
        source_ip_1,
        country_1,
        source_ip_2,
        country_2,
    )


def simulate_compromised_account():
    source_ip, country = random.choice(attack_sources)
    username = random.choice(target_users)

    for _ in range(7):
        append_login_event(
            username=username,
            password="wrongpassword",
            source_ip=source_ip,
            country=country,
        )

    append_login_event(
        username=username,
        password="Start26",
        source_ip=source_ip,
        country=country,
    )

    return source_ip, username, country