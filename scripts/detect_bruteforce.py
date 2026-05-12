import pandas as pd

# Load security logs
df = pd.read_csv('../data/security_events.csv')

# Find failed logins
failed_logins = df[df['status'] == 'failed']

# Count failed logins by source IP
suspicious_ips = (
    failed_logins.groupby('source_ip')
    .size()
    .reset_index(name='failed_attempts')
)

# Alert threshold
alerts = suspicious_ips[suspicious_ips['failed_attempts'] >= 5]

print("=== Suspicious IP Alerts ===")
print(alerts)