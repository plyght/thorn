use rusqlite::Connection;
use thorn_core::ThornResult;

pub fn run_migrations(conn: &Connection) -> ThornResult<()> {
    conn.execute_batch(SCHEMA_V1)
        .map_err(|e| thorn_core::ThornError::Database(e.to_string()))?;
    Ok(())
}

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS scan_results (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    score REAL NOT NULL,
    classification TEXT NOT NULL,
    signals_json TEXT NOT NULL,
    scanned_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS wallets (
    address TEXT PRIMARY KEY,
    chain TEXT NOT NULL,
    balance_usdc REAL NOT NULL DEFAULT 0.0,
    transaction_count INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT,
    last_seen TEXT,
    funded_by TEXT,
    status TEXT NOT NULL DEFAULT 'Unknown',
    total_spent REAL NOT NULL DEFAULT 0.0,
    total_earned REAL NOT NULL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS wallet_children (
    parent_address TEXT NOT NULL,
    child_address TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    PRIMARY KEY (parent_address, child_address)
);

CREATE TABLE IF NOT EXISTS honeypot_hits (
    id TEXT PRIMARY KEY,
    source_ip TEXT NOT NULL,
    wallet_address TEXT,
    endpoint TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    headers_json TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    signals_json TEXT NOT NULL,
    prompt_injection_triggered INTEGER NOT NULL DEFAULT 0,
    payment_amount REAL
);

CREATE TABLE IF NOT EXISTS domains (
    domain TEXT PRIMARY KEY,
    registrar TEXT,
    registered_at TEXT,
    wallet_address TEXT,
    bot_score REAL,
    classification TEXT,
    content_hash INTEGER,
    infra_json TEXT NOT NULL DEFAULT '{}',
    last_scanned TEXT
);

CREATE TABLE IF NOT EXISTS discovered_targets (
    url TEXT PRIMARY KEY,
    source_kind TEXT NOT NULL,
    source_detail TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    priority REAL NOT NULL DEFAULT 0.5,
    scanned INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS canary_tokens (
    token TEXT PRIMARY KEY,
    generated_at TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    triggered INTEGER NOT NULL DEFAULT 0,
    triggered_at TEXT,
    found_at TEXT
);

CREATE TABLE IF NOT EXISTS x402_transactions (
    tx_hash TEXT PRIMARY KEY,
    from_wallet TEXT NOT NULL,
    to_wallet TEXT NOT NULL,
    amount_usdc REAL NOT NULL,
    service_url TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL,
    chain TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS capture_strategies (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    target_wallet TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    total_captured REAL NOT NULL DEFAULT 0.0,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_domain ON scan_results(domain);
CREATE INDEX IF NOT EXISTS idx_scan_score ON scan_results(score);
CREATE INDEX IF NOT EXISTS idx_hits_ip ON honeypot_hits(source_ip);
CREATE INDEX IF NOT EXISTS idx_hits_wallet ON honeypot_hits(wallet_address);
CREATE INDEX IF NOT EXISTS idx_hits_ts ON honeypot_hits(timestamp);
CREATE INDEX IF NOT EXISTS idx_wallets_status ON wallets(status);
CREATE INDEX IF NOT EXISTS idx_discovered_scanned ON discovered_targets(scanned);
CREATE INDEX IF NOT EXISTS idx_discovered_priority ON discovered_targets(priority DESC);
CREATE INDEX IF NOT EXISTS idx_x402_from ON x402_transactions(from_wallet);
CREATE INDEX IF NOT EXISTS idx_x402_to ON x402_transactions(to_wallet);
CREATE INDEX IF NOT EXISTS idx_capture_wallet ON capture_strategies(target_wallet);
"#;
