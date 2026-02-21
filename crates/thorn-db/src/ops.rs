use chrono::Utc;
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};
use thorn_core::{HoneypotHit, ScanRecord, ThornError, ThornResult, X402Transaction};

pub struct ThornDb {
    conn: Arc<Mutex<Connection>>,
}

impl ThornDb {
    pub fn open(path: &str) -> ThornResult<Self> {
        let conn = Connection::open(path).map_err(|e| ThornError::Database(e.to_string()))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;",
        )
        .map_err(|e| ThornError::Database(e.to_string()))?;
        crate::schema::run_migrations(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn clone_handle(&self) -> Self {
        Self {
            conn: self.conn.clone(),
        }
    }

    fn with_conn<F, T>(&self, f: F) -> ThornResult<T>
    where
        F: FnOnce(&Connection) -> Result<T, rusqlite::Error>,
    {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ThornError::Database(e.to_string()))?;
        f(&conn).map_err(|e| ThornError::Database(e.to_string()))
    }

    pub fn insert_scan_result(&self, rec: &ScanRecord) -> ThornResult<()> {
        let signals_json =
            serde_json::to_string(&rec.signals).map_err(|e| ThornError::Database(e.to_string()))?;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO scan_results (id, url, domain, score, classification, signals_json, scanned_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![rec.id, rec.url, rec.domain, rec.score, rec.classification, signals_json, rec.scanned_at.to_rfc3339()],
            )?;
            Ok(())
        })
    }

    pub fn get_scan_results(&self, limit: usize) -> ThornResult<Vec<ScanRecord>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, url, domain, score, classification, signals_json, scanned_at FROM scan_results ORDER BY scanned_at DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], |row| {
                let signals_str: String = row.get(5)?;
                let scanned_str: String = row.get(6)?;
                Ok(ScanRecord {
                    id: row.get(0)?,
                    url: row.get(1)?,
                    domain: row.get(2)?,
                    score: row.get(3)?,
                    classification: row.get(4)?,
                    signals: serde_json::from_str(&signals_str).unwrap_or_default(),
                    scanned_at: chrono::DateTime::parse_from_rfc3339(&scanned_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
            })?;
            rows.collect()
        })
    }

    pub fn get_scans_by_domain(&self, domain: &str) -> ThornResult<Vec<ScanRecord>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, url, domain, score, classification, signals_json, scanned_at FROM scan_results WHERE domain = ?1 ORDER BY scanned_at DESC",
            )?;
            let rows = stmt.query_map(params![domain], |row| {
                let signals_str: String = row.get(5)?;
                let scanned_str: String = row.get(6)?;
                Ok(ScanRecord {
                    id: row.get(0)?,
                    url: row.get(1)?,
                    domain: row.get(2)?,
                    score: row.get(3)?,
                    classification: row.get(4)?,
                    signals: serde_json::from_str(&signals_str).unwrap_or_default(),
                    scanned_at: chrono::DateTime::parse_from_rfc3339(&scanned_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
            })?;
            rows.collect()
        })
    }

    pub fn insert_honeypot_hit(&self, hit: &HoneypotHit) -> ThornResult<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let headers_json =
            serde_json::to_string(&hit.headers).map_err(|e| ThornError::Database(e.to_string()))?;
        let signals_json =
            serde_json::to_string(&hit.signals).map_err(|e| ThornError::Database(e.to_string()))?;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO honeypot_hits (id, source_ip, wallet_address, endpoint, user_agent, headers_json, timestamp, signals_json, prompt_injection_triggered, payment_amount) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    id,
                    hit.source_ip,
                    hit.wallet_address,
                    hit.endpoint,
                    hit.user_agent,
                    headers_json,
                    hit.timestamp.to_rfc3339(),
                    signals_json,
                    hit.prompt_injection_triggered as i32,
                    hit.payment_amount,
                ],
            )?;
            Ok(id)
        })
    }

    pub fn get_honeypot_hits(&self, limit: usize) -> ThornResult<Vec<HoneypotHit>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT source_ip, wallet_address, endpoint, user_agent, headers_json, timestamp, signals_json, prompt_injection_triggered, payment_amount FROM honeypot_hits ORDER BY timestamp DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], |row| {
                let headers_str: String = row.get(4)?;
                let ts_str: String = row.get(5)?;
                let signals_str: String = row.get(6)?;
                let pit: i32 = row.get(7)?;
                Ok(HoneypotHit {
                    source_ip: row.get(0)?,
                    wallet_address: row.get(1)?,
                    endpoint: row.get(2)?,
                    user_agent: row.get(3)?,
                    headers: serde_json::from_str(&headers_str).unwrap_or_default(),
                    timestamp: chrono::DateTime::parse_from_rfc3339(&ts_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    signals: serde_json::from_str(&signals_str).unwrap_or_default(),
                    prompt_injection_triggered: pit != 0,
                    payment_amount: row.get(8)?,
                })
            })?;
            rows.collect()
        })
    }

    pub fn upsert_wallet(
        &self,
        address: &str,
        chain: &str,
        balance: f64,
        tx_count: u64,
        status: &str,
        funded_by: Option<&str>,
        spent: f64,
        earned: f64,
    ) -> ThornResult<()> {
        let now = Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO wallets (address, chain, balance_usdc, transaction_count, first_seen, last_seen, funded_by, status, total_spent, total_earned)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(address) DO UPDATE SET
                   balance_usdc = excluded.balance_usdc,
                   transaction_count = excluded.transaction_count,
                   last_seen = excluded.last_seen,
                   status = excluded.status,
                   total_spent = excluded.total_spent,
                   total_earned = excluded.total_earned",
                params![address, chain, balance, tx_count as i64, now, now, funded_by, status, spent, earned],
            )?;
            Ok(())
        })
    }

    pub fn get_wallet_addresses(&self) -> ThornResult<Vec<String>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT address FROM wallets")?;
            let rows = stmt.query_map([], |row| row.get(0))?;
            rows.collect()
        })
    }

    pub fn insert_wallet_child(&self, parent: &str, child: &str) -> ThornResult<()> {
        let now = Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO wallet_children (parent_address, child_address, discovered_at) VALUES (?1, ?2, ?3)",
                params![parent, child, now],
            )?;
            Ok(())
        })
    }

    pub fn insert_discovered_target(
        &self,
        url: &str,
        source_kind: &str,
        source_detail: &str,
        priority: f64,
    ) -> ThornResult<()> {
        let now = Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO discovered_targets (url, source_kind, source_detail, discovered_at, priority, scanned) VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                params![url, source_kind, source_detail, now, priority],
            )?;
            Ok(())
        })
    }

    pub fn get_unscanned_targets(&self, limit: usize) -> ThornResult<Vec<(String, f64)>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT url, priority FROM discovered_targets WHERE scanned = 0 ORDER BY priority DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;
            rows.collect()
        })
    }

    pub fn mark_target_scanned(&self, url: &str) -> ThornResult<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE discovered_targets SET scanned = 1 WHERE url = ?1",
                params![url],
            )?;
            Ok(())
        })
    }

    pub fn insert_canary_token(&self, token: &str, endpoint: &str) -> ThornResult<()> {
        let now = Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO canary_tokens (token, generated_at, endpoint) VALUES (?1, ?2, ?3)",
                params![token, now, endpoint],
            )?;
            Ok(())
        })
    }

    pub fn trigger_canary(&self, token: &str, found_at: &str) -> ThornResult<bool> {
        let now = Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            let changed = conn.execute(
                "UPDATE canary_tokens SET triggered = 1, triggered_at = ?1, found_at = ?2 WHERE token = ?3 AND triggered = 0",
                params![now, found_at, token],
            )?;
            Ok(changed > 0)
        })
    }

    pub fn insert_x402_transaction(&self, tx: &X402Transaction) -> ThornResult<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO x402_transactions (tx_hash, from_wallet, to_wallet, amount_usdc, service_url, timestamp, chain) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    tx.tx_hash,
                    tx.from_wallet,
                    tx.to_wallet,
                    tx.amount_usdc,
                    tx.service_url,
                    tx.timestamp.to_rfc3339(),
                    format!("{:?}", tx.chain),
                ],
            )?;
            Ok(())
        })
    }

    pub fn upsert_domain(
        &self,
        domain: &str,
        wallet: Option<&str>,
        bot_score: Option<f64>,
        classification: Option<&str>,
        infra_json: &str,
    ) -> ThornResult<()> {
        let now = Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO domains (domain, wallet_address, bot_score, classification, infra_json, last_scanned)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(domain) DO UPDATE SET
                   wallet_address = COALESCE(excluded.wallet_address, domains.wallet_address),
                   bot_score = COALESCE(excluded.bot_score, domains.bot_score),
                   classification = COALESCE(excluded.classification, domains.classification),
                   infra_json = excluded.infra_json,
                   last_scanned = excluded.last_scanned",
                params![domain, wallet, bot_score, classification, infra_json, now],
            )?;
            Ok(())
        })
    }

    pub fn upsert_capture_strategy(
        &self,
        id: &str,
        kind: &str,
        target_wallet: &str,
        active: bool,
        total_captured: f64,
        config_json: &str,
    ) -> ThornResult<()> {
        let now = Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO capture_strategies (id, kind, target_wallet, active, total_captured, config_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(id) DO UPDATE SET
                   active = excluded.active,
                   total_captured = excluded.total_captured,
                   config_json = excluded.config_json,
                   updated_at = excluded.updated_at",
                params![id, kind, target_wallet, active as i32, total_captured, config_json, now, now],
            )?;
            Ok(())
        })
    }

    pub fn get_active_capture_strategies(
        &self,
    ) -> ThornResult<Vec<(String, String, String, f64, String)>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, kind, target_wallet, total_captured, config_json FROM capture_strategies WHERE active = 1",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
            })?;
            rows.collect()
        })
    }

    pub fn get_wallets_discovered_from_honeypot(&self) -> ThornResult<Vec<String>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT wallet_address FROM honeypot_hits WHERE wallet_address IS NOT NULL AND wallet_address != ''",
            )?;
            let rows = stmt.query_map([], |row| row.get(0))?;
            rows.collect()
        })
    }

    pub fn get_wallets(&self, limit: usize) -> ThornResult<Vec<WalletRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT address, chain, balance_usdc, transaction_count, first_seen, last_seen, funded_by, status, total_spent, total_earned FROM wallets ORDER BY last_seen DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], |row| {
                Ok(WalletRow {
                    address: row.get(0)?,
                    chain: row.get(1)?,
                    balance_usdc: row.get(2)?,
                    transaction_count: row.get(3)?,
                    first_seen: row.get(4)?,
                    last_seen: row.get(5)?,
                    funded_by: row.get(6)?,
                    status: row.get(7)?,
                    total_spent: row.get(8)?,
                    total_earned: row.get(9)?,
                })
            })?;
            rows.collect()
        })
    }

    pub fn get_discovered_targets(&self, limit: usize) -> ThornResult<Vec<TargetRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT url, source_kind, source_detail, discovered_at, priority, scanned FROM discovered_targets ORDER BY discovered_at DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], |row| {
                let scanned_int: i32 = row.get(5)?;
                Ok(TargetRow {
                    url: row.get(0)?,
                    source_kind: row.get(1)?,
                    source_detail: row.get(2)?,
                    discovered_at: row.get(3)?,
                    priority: row.get(4)?,
                    scanned: scanned_int != 0,
                })
            })?;
            rows.collect()
        })
    }

    pub fn get_domain_urls_for_crawl(&self) -> ThornResult<Vec<String>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT domain FROM domains WHERE domain IS NOT NULL AND domain != '' ORDER BY last_scanned ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                let d: String = row.get(0)?;
                Ok(format!("https://{}", d))
            })?;
            rows.collect()
        })
    }

    pub fn stats(&self) -> ThornResult<DbStats> {
        self.with_conn(|conn| {
            let scans: i64 =
                conn.query_row("SELECT COUNT(*) FROM scan_results", [], |r| r.get(0))?;
            let hits: i64 =
                conn.query_row("SELECT COUNT(*) FROM honeypot_hits", [], |r| r.get(0))?;
            let wallets: i64 = conn.query_row("SELECT COUNT(*) FROM wallets", [], |r| r.get(0))?;
            let domains: i64 = conn.query_row("SELECT COUNT(*) FROM domains", [], |r| r.get(0))?;
            let targets: i64 =
                conn.query_row("SELECT COUNT(*) FROM discovered_targets", [], |r| r.get(0))?;
            let unscanned: i64 = conn.query_row(
                "SELECT COUNT(*) FROM discovered_targets WHERE scanned = 0",
                [],
                |r| r.get(0),
            )?;
            let canaries: i64 =
                conn.query_row("SELECT COUNT(*) FROM canary_tokens", [], |r| r.get(0))?;
            let triggered: i64 = conn.query_row(
                "SELECT COUNT(*) FROM canary_tokens WHERE triggered = 1",
                [],
                |r| r.get(0),
            )?;
            let captures: i64 = conn.query_row(
                "SELECT COUNT(*) FROM capture_strategies WHERE active = 1",
                [],
                |r| r.get(0),
            )?;
            Ok(DbStats {
                scan_results: scans as u64,
                honeypot_hits: hits as u64,
                wallets: wallets as u64,
                domains: domains as u64,
                discovered_targets: targets as u64,
                unscanned_targets: unscanned as u64,
                canary_tokens: canaries as u64,
                canaries_triggered: triggered as u64,
                active_captures: captures as u64,
            })
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DbStats {
    pub scan_results: u64,
    pub honeypot_hits: u64,
    pub wallets: u64,
    pub domains: u64,
    pub discovered_targets: u64,
    pub unscanned_targets: u64,
    pub canary_tokens: u64,
    pub canaries_triggered: u64,
    pub active_captures: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WalletRow {
    pub address: String,
    pub chain: String,
    pub balance_usdc: f64,
    pub transaction_count: i64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub funded_by: Option<String>,
    pub status: String,
    pub total_spent: f64,
    pub total_earned: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TargetRow {
    pub url: String,
    pub source_kind: String,
    pub source_detail: String,
    pub discovered_at: String,
    pub priority: f64,
    pub scanned: bool,
}
