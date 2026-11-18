# AEGIS — SOC Threat Detection Dashboard

AEGIS is a Security Operations Center (SOC) dashboard that detects identity and network attacks, maps each one to MITRE ATT&CK, and tracks it through an incident response workflow. It runs on simulated authentication, firewall, VPN, and flow telemetry stored in MySQL, with a built-in attack simulator for generating realistic threats on demand.

Built with Python, Streamlit, pandas, and MySQL.

![Command Center](screenshots/command_center.png)

---

## Features

- **Command Center**: live alert feed, threat level, attack origin map, authentication timeline, and open incidents
- **Network Operations**: infrastructure health (device status, CPU, link utilization, interface errors), top talkers, firewall denies by port, traffic timeline, and network threat detections
- **Incident Queue**: incidents are created automatically from detections, de-duplicated, and triaged by status, assignment, and severity
- **Incident Details**: correlated evidence timeline, ATT&CK context, recommended response actions, and analyst notes
- **User Investigation**: per-user risk score, authentication history, and detection findings
- **Threat Intelligence**: source IP lookup across observed activity
- **Detection Rules**: every rule's logic, thresholds, and ATT&CK mapping, generated from the same file the detections run on
- **Attack Simulation**: one-click identity attacks, network attacks, background traffic, and switch outages

## Detection Coverage

All thresholds, rule IDs, and ATT&CK mappings live in one file, [`utils/detection_rules.py`](utils/detection_rules.py). Every page and detection reads from it, so changing a threshold changes it everywhere.

| Rule | Detection | Logic | ATT&CK | Tactic |
|---|---|---|---|---|
| AEGIS-001 | Brute Force | 5+ failed logins, same user and source IP, within 15 min | T1110 Brute Force | Credential Access |
| AEGIS-002 | Password Spray | One source IP fails against 5+ accounts within 15 min | T1110.003 Password Spraying | Credential Access |
| AEGIS-003 | Account Takeover | 5+ failures followed by a success, same user and IP | T1078 Valid Accounts | Initial Access / Persistence |
| AEGIS-004 | Impossible Travel | Consecutive logins 500+ km apart that would require more than 900 km/h travel (haversine distance) | T1078 Valid Accounts | Initial Access / Persistence |
| AEGIS-005 | Port Scan | One source hits 15+ ports or 10+ hosts through the firewall within 15 min | T1046 Network Service Discovery | Discovery |
| AEGIS-006 | VPN Brute Force | 5+ failed VPN logins, same user and source; Critical if a session is then established | T1133 External Remote Services | Initial Access / Persistence |
| AEGIS-007 | C2 Beaconing | 8+ outbound connections from one internal host to the same external IP:port with ≤15% interval variation | T1071 Application Layer Protocol | Command and Control |

### How beaconing detection works

Malware usually "phones home" on a timer, while people browse at irregular intervals. For each internal-to-external connection pair, AEGIS measures the time between connections and calculates the **coefficient of variation** (standard deviation ÷ mean). Traffic that repeats at a near-constant interval, for example every 60 seconds ±2, gets flagged, while normal web traffic does not.

### How impossible travel works

Instead of flagging any change of country, AEGIS calculates the great-circle distance between consecutive successful logins and the speed needed to cover it. A login from Detroit followed by one from Windsor, Canada ten minutes later is ignored. A login from the US followed by one from Japan a minute later is flagged.

## Screenshots

| Network Operations | Incident Queue |
|---|---|
| ![Network Operations](screenshots/network_operations.png) | ![Incident Queue](screenshots/incident_queue.png) |

| Incident Details | Attack Simulation |
|---|---|
| ![Incident Details](screenshots/incident_details.png) | ![Attack Simulation](screenshots/attack_simulation.png) |

## Architecture

```
 Attack Simulation page  ──writes──►  MySQL (soc_dashboard)
 scripts/seed_data.py                  ├── events            (authentication)
                                       ├── network_events    (firewall / VPN / flow)
                                       ├── network_devices   (infrastructure health)
                                       ├── incidents
                                       └── incident_notes
                                              │
                                    utils/data_loader.py
                                              │
              ┌───────────────────────────────┼───────────────────────────────┐
     utils/detections.py              utils/analytics.py            utils/network_detections.py
     (AEGIS-001/002/003)              (AEGIS-004)                   (AEGIS-005/006/007)
              └──────────────── utils/detection_rules.py (thresholds + ATT&CK) ┘
                                              │
                              utils/incidents.py  →  Streamlit pages
```

## Setup

**Requirements:** Python 3.11+ and MySQL 8+

1. **Clone and install**
   ```bash
   git clone https://github.com/Mjewell16/SOC-threat-dashboard.git
   cd SOC-threat-dashboard
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Create the database** (as MySQL root)
   ```bash
   mysql -u root -p < sql/schema.sql
   ```

3. **Create a least-privilege app account.** Edit the password in `sql/create_app_user.sql`, then run:
   ```bash
   mysql -u root -p < sql/create_app_user.sql
   ```
   The dashboard connects as `aegis_app`, which can only `SELECT`, `INSERT`, and `UPDATE`. It cannot drop tables or change schema.

4. **Add your credentials**
   ```bash
   cp .streamlit/secrets.toml.example .streamlit/secrets.toml
   ```
   Put the `aegis_app` password in `secrets.toml`. This file is in `.gitignore` and is never committed. Environment variables (`AEGIS_DB_PASSWORD`, `AEGIS_DB_USER`, etc.) also work.

5. **Load sample data** (24 hours of normal activity plus one of each attack)
   ```bash
   python -m scripts.seed_data
   ```

6. **Run**
   ```bash
   streamlit run app.py
   ```
   Open http://localhost:8501 and sign in with the demo account `analyst` / `Aegis2026!`.

## Demo Walkthrough

1. **Attack Simulation**: click **Generate Normal Traffic** a few times so there is background noise
2. Run **Simulate Port Scan**, **Simulate VPN Brute Force** (tick "Attacker gets in"), and **Simulate Beaconing**
3. **Network Operations**: each attack appears under Network Threat Detections; normal traffic does not
4. **Simulate Switch Outage** → the device turns red on Network Operations
5. **Incident Queue**: the detections have become incidents; assign one and change its status
6. **Incident Details**: review the correlated timeline, ATT&CK context, and response steps, then add an analyst note

## Live Mode

To keep the dashboard running like a real SOC, start the live feed in a second terminal while the app runs:

```bash
python -m scripts.live_feed
```

It writes normal authentication and network traffic every 10 seconds, launches a random attack every ~5 minutes (with ±30% jitter so attacks don't arrive on an obvious schedule), polls device health every minute, occasionally takes an access switch offline and restores it, and deletes telemetry older than 3 days.

```bash
python -m scripts.live_feed --attack-every 2 --retention-days 7 --no-outages
```

Cleanup needs `DELETE` on the two telemetry tables only. Run `sql/grant_cleanup.sql` as root to allow it; incidents, notes, and device inventory stay protected.

The Attack Simulation buttons still work with the feed running, for hands-on demos.

## Project Structure

```
app.py                       Navigation and authentication gate
db.py                        MySQL connection (credentials from secrets/env, never code)
pages/
  0_command_center.py        Identity overview and alert feed
  2_incident_queue.py        Incident creation and triage
  3_threat_intelligence.py   Source IP lookup
  4_user_investigation.py    Per-user risk and history
  5_detection_rules.py       Rule catalog (generated from detection_rules.py)
  6_incident_details.py      Evidence correlation and analyst notes
  7_attack_simulation.py     Identity and network attack generators
  8_network_operations.py    Infrastructure health and network detections
utils/
  detection_rules.py         Single source of truth for all rules
  detections.py              Brute force, password spray, account takeover
  analytics.py               Impossible travel (haversine distance and speed)
  network_detections.py      Port scan, VPN brute force, beaconing
  simulations.py             Identity attack generators
  network_simulations.py     Firewall/VPN/flow and device health generators
  incidents.py               Incident persistence and notes
  mitre.py                   ATT&CK technique context and response guidance
sql/
  schema.sql                 Full database schema and device inventory
  create_app_user.sql        Least-privilege MySQL account
  grant_cleanup.sql          Optional DELETE on telemetry tables for live feed cleanup
scripts/
  seed_data.py               Sample data loader
  live_feed.py               Continuous traffic and attack generator
```

## Security Notes

- **No credentials in source code.** Database credentials load from `.streamlit/secrets.toml` or environment variables.
- **Least privilege.** The app's MySQL account has no `DROP`, `ALTER`, or `GRANT` rights.
- **Parameterized queries throughout.** No SQL is built from user input.
- **Demo authentication only.** The analyst login is hard-coded for demonstration and is not intended for production use.
- **Simulated data only.** All IPs, users, and devices are fictional. Internal addressing uses RFC 1918 space, and simulated attacker infrastructure uses documentation ranges where possible.

## Roadmap

- Ingest real log formats (Zeek `conn.log`, pfSense filterlog, Windows Event IDs 4624/4625)
- DNS tunneling and lateral movement (T1021) detections
- Threat intelligence enrichment from AbuseIPDB
- Docker Compose for one-command setup

---

**Mason Jewell**: B.S. Computer Science, M.S. Cybersecurity (University of West Florida)
