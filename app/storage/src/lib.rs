use analyzer::Alert;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use collector::FlowEvent;
use ring::aead::{self, Aad, LessSafeKey, UnboundKey};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

const AAD_CONTEXT: &[u8] = b"nets-local-monitor";

pub struct Storage {
    conn: Connection,
    key: LessSafeKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFlow {
    pub id: i64,
    pub ts_first: DateTime<Utc>,
    pub ts_last: DateTime<Utc>,
    pub proto: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub bytes: u64,
}

impl Storage {
    pub fn open<P: AsRef<Path>>(path: P, key_bytes: &[u8]) -> Result<Self> {
        let conn = Connection::open(path)?;
        if key_bytes.len() != 32 {
            return Err(anyhow!("AES-256-GCM key must be 32 bytes"));
        }
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key_bytes)
            .map_err(|_| anyhow!("failed to initialize encryption key"))?;
        let key = LessSafeKey::new(unbound_key);
        let storage = Self { conn, key };
        storage.migrate()?;
        Ok(storage)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_first TEXT NOT NULL,
                ts_last TEXT NOT NULL,
                proto TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                bytes INTEGER NOT NULL,
                ciphertext BLOB
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                summary TEXT NOT NULL,
                rationale TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    pub fn put_flow(&self, flow: &FlowEvent) -> Result<i64> {
        let serialized = serde_json::to_vec(flow)?;
        let nonce = aead::Nonce::assume_unique_for_key([0u8; 12]);
        let mut in_out = serialized.clone();
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(AAD_CONTEXT), &mut in_out)
            .map_err(|_| anyhow!("failed to encrypt flow"))?;
        in_out.extend_from_slice(tag.as_ref());
        self.conn.execute(
            "INSERT INTO flows (ts_first, ts_last, proto, src_ip, dst_ip, src_port, dst_port, bytes, ciphertext) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                flow.ts_first.to_rfc3339(),
                flow.ts_last.to_rfc3339(),
                flow.proto,
                flow.src_ip,
                flow.dst_ip,
                flow.src_port,
                flow.dst_port,
                flow.bytes,
                in_out,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn put_alert(&self, alert: &Alert) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO alerts (id, ts, severity, rule_id, summary, rationale) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                alert.id,
                alert.ts.to_rfc3339(),
                format!("{:?}", alert.severity),
                alert.rule_id,
                alert.summary,
                alert.rationale,
            ],
        )?;
        Ok(())
    }

    pub fn query_flows(&self, limit: usize) -> Result<Vec<StoredFlow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts_first, ts_last, proto, src_ip, dst_ip, src_port, dst_port, bytes FROM flows ORDER BY ts_first DESC LIMIT ?1",
        )?;
        let flows = stmt
            .query_map(params![limit as i64], |row| {
                Ok(StoredFlow {
                    id: row.get(0)?,
                    ts_first: DateTime::parse_from_rfc3339(row.get::<_, String>(1)?.as_str())
                        .unwrap()
                        .with_timezone(&Utc),
                    ts_last: DateTime::parse_from_rfc3339(row.get::<_, String>(2)?.as_str())
                        .unwrap()
                        .with_timezone(&Utc),
                    proto: row.get(3)?,
                    src_ip: row.get(4)?,
                    dst_ip: row.get(5)?,
                    src_port: row.get(6)?,
                    dst_port: row.get(7)?,
                    bytes: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(flows)
    }
}
