-- =========================================================
-- AEGIS SOC Dashboard — database schema
--
-- Creates the soc_dashboard database and all tables from scratch.
-- Safe to re-run: existing tables and data are left untouched.
--
-- Run as root:
--   mysql -u root -p < sql/schema.sql
-- or open it in MySQL Workbench and click the lightning bolt.
-- =========================================================

CREATE DATABASE IF NOT EXISTS soc_dashboard
    DEFAULT CHARACTER SET utf8mb4
    COLLATE utf8mb4_0900_ai_ci;

USE soc_dashboard;


-- ---------------------------------------------------------
-- Authentication telemetry (web portal logins)
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    event_id     INT           NOT NULL AUTO_INCREMENT,
    event_time   DATETIME      NOT NULL,
    source_ip    VARCHAR(50)   DEFAULT NULL,
    username     VARCHAR(100)  DEFAULT NULL,
    event_type   VARCHAR(100)  DEFAULT NULL,   -- login_success | login_failed
    status       VARCHAR(20)   DEFAULT NULL,   -- success | failed
    geo_country  VARCHAR(100)  DEFAULT NULL,
    device_type  VARCHAR(100)  DEFAULT NULL,
    latitude     DECIMAL(9,6)  DEFAULT NULL,
    longitude    DECIMAL(9,6)  DEFAULT NULL,
    PRIMARY KEY (event_id),
    KEY idx_events_time (event_time),
    KEY idx_events_user (username),
    KEY idx_events_ip (source_ip)
) ENGINE=InnoDB;


-- ---------------------------------------------------------
-- Persistent incidents (case management)
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id               INT           NOT NULL AUTO_INCREMENT,
    incident_id      VARCHAR(20)   DEFAULT NULL,   -- INC-1001, set after insert
    created_at       DATETIME      DEFAULT CURRENT_TIMESTAMP,
    severity         VARCHAR(20)   NOT NULL,
    incident_type    VARCHAR(100)  NOT NULL,
    source_ip        VARCHAR(45)   DEFAULT NULL,
    username         VARCHAR(100)  DEFAULT NULL,
    failed_attempts  INT           DEFAULT 0,
    status           VARCHAR(30)   DEFAULT 'Open', -- Open | Investigating | Contained | Closed
    assigned_to      VARCHAR(100)  DEFAULT 'Unassigned',
    mitre_technique  VARCHAR(100)  DEFAULT NULL,
    updated_at       DATETIME      DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY incident_id (incident_id)
) ENGINE=InnoDB;


-- ---------------------------------------------------------
-- Analyst notes on incidents
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident_notes (
    id           INT           NOT NULL AUTO_INCREMENT,
    incident_id  VARCHAR(50)   NOT NULL,
    analyst      VARCHAR(255)  NOT NULL,
    note         TEXT          NOT NULL,
    created_at   DATETIME      DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_incident_notes_incident_id (incident_id)
) ENGINE=InnoDB;


-- ---------------------------------------------------------
-- Network telemetry: firewall, VPN and flow events
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS network_events (
    id            INT           NOT NULL AUTO_INCREMENT,
    event_time    DATETIME      NOT NULL,
    event_source  VARCHAR(20)   NOT NULL,   -- firewall | vpn | flow
    action        VARCHAR(20)   NOT NULL,   -- allow | deny | success | failed
    src_ip        VARCHAR(45)   NOT NULL,
    src_port      INT           DEFAULT NULL,
    dst_ip        VARCHAR(45)   DEFAULT NULL,
    dst_port      INT           DEFAULT NULL,
    protocol      VARCHAR(10)   DEFAULT NULL,   -- TCP | UDP | ICMP
    bytes_out     BIGINT        NOT NULL DEFAULT 0,
    username      VARCHAR(100)  DEFAULT NULL,   -- VPN events only
    geo_country   VARCHAR(100)  DEFAULT NULL,
    device_name   VARCHAR(50)   DEFAULT NULL,   -- device that logged the event
    PRIMARY KEY (id),
    KEY idx_net_time (event_time),
    KEY idx_net_src (src_ip),
    KEY idx_net_source (event_source)
) ENGINE=InnoDB;


-- ---------------------------------------------------------
-- Network infrastructure inventory and health
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS network_devices (
    device_name       VARCHAR(50)   NOT NULL,
    device_type       VARCHAR(30)   NOT NULL,
    mgmt_ip           VARCHAR(45)   NOT NULL,
    location          VARCHAR(100)  NOT NULL,
    status            VARCHAR(10)   NOT NULL DEFAULT 'Up',  -- Up | Down | Degraded
    cpu_percent       INT           NOT NULL DEFAULT 0,
    bandwidth_mbps    INT           NOT NULL DEFAULT 0,
    capacity_mbps     INT           NOT NULL DEFAULT 1000,
    interface_errors  INT           NOT NULL DEFAULT 0,
    last_seen         DATETIME      NOT NULL,
    PRIMARY KEY (device_name)
) ENGINE=InnoDB;


-- Fictional lab network inventory (RFC 1918 addressing)
INSERT INTO network_devices
    (device_name, device_type, mgmt_ip, location, status, cpu_percent,
     bandwidth_mbps, capacity_mbps, interface_errors, last_seen)
VALUES
    ('FW-EDGE-01',   'Firewall',            '10.10.0.1',   'Data Center', 'Up', 34,  620,  1000, 0, NOW()),
    ('RTR-WAN-01',   'Router',              '10.10.0.2',   'Data Center', 'Up', 22,  580,  1000, 0, NOW()),
    ('VPN-GW-01',    'VPN Gateway',         '10.10.0.5',   'Data Center', 'Up', 41,  210,   500, 0, NOW()),
    ('CORE-SW-01',   'Core Switch',         '10.10.1.1',   'Data Center', 'Up', 18, 2400, 10000, 0, NOW()),
    ('CORE-SW-02',   'Core Switch',         '10.10.1.2',   'Data Center', 'Up', 16, 2100, 10000, 0, NOW()),
    ('ACC-SW-B1-01', 'Access Switch',       '10.10.20.11', 'Building 1',  'Up', 12,  310,  1000, 2, NOW()),
    ('ACC-SW-B2-01', 'Access Switch',       '10.10.30.11', 'Building 2',  'Up', 14,  280,  1000, 0, NOW()),
    ('ACC-SW-B3-01', 'Access Switch',       '10.10.40.11', 'Building 3',  'Up', 11,  190,  1000, 0, NOW()),
    ('WLC-01',       'Wireless Controller', '10.10.1.10',  'Data Center', 'Up', 27,  450,  1000, 0, NOW())
ON DUPLICATE KEY UPDATE device_name = device_name;
