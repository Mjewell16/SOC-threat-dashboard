-- Optional: lets the live feed delete old telemetry.
-- Grants DELETE on the two telemetry tables only, so the app still
-- cannot delete incidents, notes, or device inventory.
-- Run once as root.

GRANT DELETE ON soc_dashboard.events TO 'aegis_app'@'localhost';
GRANT DELETE ON soc_dashboard.network_events TO 'aegis_app'@'localhost';
