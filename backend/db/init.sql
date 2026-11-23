-- NIDPS database schema (PostgreSQL 12+).
-- Safe to run repeatedly: every statement is idempotent. The backend runs this
-- automatically on start-up, so existing databases are upgraded in place.

-- 1. Alerts parsed from Snort
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    alert_message TEXT NOT NULL,
    severity INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 4),
    status VARCHAR(20) DEFAULT 'unresolved' NOT NULL
        CHECK (status IN ('unresolved', 'investigating', 'blocked', 'resolved', 'false_positive'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts (source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);

-- 2. Firewall blocks (active and historical)
CREATE TABLE IF NOT EXISTS blocked_ips (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    block_reason TEXT NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    unblocked_at TIMESTAMPTZ NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL
);
ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NULL;
ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS created_by VARCHAR(64) NOT NULL DEFAULT 'system';
CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips (is_active);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_address ON blocked_ips (ip_address);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_timestamp ON blocked_ips (timestamp DESC);

-- 3. Audit log: who did what, when, and why
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    actor VARCHAR(64) NOT NULL,
    action VARCHAR(32) NOT NULL,
    target VARCHAR(64) NULL,
    detail TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp DESC);
