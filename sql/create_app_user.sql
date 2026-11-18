-- Run once as root in MySQL to create a limited account for the dashboard.
-- Replace the password, then put the same password in .streamlit/secrets.toml.

CREATE USER IF NOT EXISTS 'aegis_app'@'localhost' IDENTIFIED BY 'CHANGE_ME';
GRANT SELECT, INSERT, UPDATE ON soc_dashboard.* TO 'aegis_app'@'localhost';
FLUSH PRIVILEGES;
