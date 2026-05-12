import csv
import random
import time
from datetime import datetime
from pathlib import Path

CSV_PATH = Path("../data/security_events.csv")

ATTACK_IPS = [
    ("185.220.101.12", "Russia", 61.5240, 105.3188),
    ("45.155.205.233", "Germany", 51.1657, 10.4515),
    ("172.16.0.88", "China", 35.8617, 104.1954),
    ("103.27.202.11", "India", 20.5937, 78.9629),
]

TARGET_USERS = [
    "admin",
    "teacher1",
    "student23",
    "principal",
    "itadmin",
    "mjewell"
]

DEVICE_TYPES = [
    "Windows",
    "Linux",
    "MacOS",
    "Unknown"
]

def get_next_event_id():
    with open(CSV_PATH, "r", newline="") as file:
        reader = list(csv.DictReader(file))
        if not reader:
            return 1
        return max(int(row["event_id"]) for row in reader) + 1

def append_event():
    event_id = get_next_event_id()
    source_ip, country, lat, lon = random.choice(ATTACK_IPS)
    username = random.choice(TARGET_USERS)
    device = random.choice(DEVICE_TYPES)

    event = {
        "event_id": event_id,
        "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": source_ip,
        "username": username,
        "event_type": "login_failed",
        "status": "failed",
        "geo_country": country,
        "device_type": device,
        "latitude": lat,
        "longitude": lon
    }

    with open(CSV_PATH, "a", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=event.keys())
        writer.writerow(event)

    print(
        f"[SIMULATED ATTACK] {event['event_time']} | "
        f"IP {source_ip} | User {username} | Country {country}"
    )

print("Starting simulated brute-force activity...")
print("Press Control + C to stop.\n")

while True:
    append_event()
    time.sleep(random.randint(2, 5))