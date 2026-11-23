-- NIDPS Database Schema Initialization
-- PostgreSQL 12+

-- Ensure clean setup (uncomment DROP statements if resetting schema)
-- DROP TABLE IF EXISTS blocked_ips CASCADE;
-- DROP TABLE IF EXISTS alerts CASCADE;

-- 1. Alerts Table: Stores parsed Snort intrusion alerts
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    alert_message TEXT NOT NULL,
    severity INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 4),
    status VARCHAR(20) DEFAULT 'unresolved' NOT NULL CHECK (status IN ('unresolved', 'investigating', 'blocked', 'resolved', 'false_positive'))
);

-- Indexes for alerts table performance
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts (source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);

-- 2. Blocked IPs Table: Stores actively and historically blocked IP addresses
CREATE TABLE IF NOT EXISTS blocked_ips (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    block_reason TEXT NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    unblocked_at TIMESTAMPTZ NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL
);

-- Indexes for blocked_ips table
CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips (is_active);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_address ON blocked_ips (ip_address);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_timestamp ON blocked_ips (timestamp DESC);

-- Seed initial sample data (uncomment if you want demonstration baseline data)
-- INSERT INTO alerts (timestamp, source_ip, dest_ip, protocol, alert_message, severity, status)
-- VALUES 
--     (NOW() - INTERVAL '35 minutes', '198.51.100.23', '10.0.0.5', 'TCP', 'ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)', 1, 'blocked');
-- INSERT INTO blocked_ips (ip_address, block_reason, timestamp, unblocked_at, is_active)
-- VALUES
--     ('198.51.100.23', 'Automatic mitigation: High severity alert ET EXPLOIT Apache Log4j RCE Attempt', NOW() - INTERVAL '35 minutes', NULL, TRUE);
