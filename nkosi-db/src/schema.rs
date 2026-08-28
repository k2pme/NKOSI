use crate::repositories::*;
use nkosi_common::types::*;
use rusqlite::{Connection, Result};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn new(db_path: &Path) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.initialize()?;
        Ok(db)
    }

    pub fn connection(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap()
    }

    pub fn get_recent(&self, limit: i32) -> Result<Vec<Event>> {
        let repo = EventRepository::new(self);
        repo.get_recent(limit)
    }

    pub fn get_active(&self) -> Result<Vec<QuarantineItem>> {
        let repo = QuarantineRepository::new(self);
        repo.get_active()
    }

    fn initialize(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_module TEXT NOT NULL,
                pid INTEGER,
                ppid INTEGER,
                user TEXT,
                file_path TEXT,
                file_hash TEXT,
                remote_ip TEXT,
                remote_port INTEGER,
                domain TEXT,
                incident_id TEXT,
                severity TEXT NOT NULL,
                score INTEGER,
                action TEXT,
                result TEXT,
                agent_id TEXT DEFAULT '',
                agent_host TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS threat_indicators (
                id TEXT PRIMARY KEY,
                indicator_type TEXT NOT NULL,
                value TEXT NOT NULL UNIQUE,
                malware_family TEXT,
                confidence REAL NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                tags TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                status TEXT NOT NULL,
                global_score INTEGER NOT NULL,
                summary TEXT
            );

            CREATE TABLE IF NOT EXISTS detections (
                id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                incident_id TEXT,
                detection_engine TEXT NOT NULL,
                rule_id TEXT,
                rule_name TEXT,
                confidence REAL NOT NULL,
                score_contribution INTEGER NOT NULL,
                details TEXT,
                FOREIGN KEY (event_id) REFERENCES events(id),
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            );

            CREATE TABLE IF NOT EXISTS quarantine_items (
                id TEXT PRIMARY KEY,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                reason TEXT NOT NULL,
                score INTEGER NOT NULL,
                quarantined_at TEXT NOT NULL,
                restored_at TEXT,
                deleted_at TEXT,
                status TEXT NOT NULL,
                agent_id TEXT DEFAULT '',
                agent_host TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                files_scanned INTEGER NOT NULL DEFAULT 0,
                threats_found INTEGER NOT NULL DEFAULT 0,
                suspicious_found INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
            CREATE INDEX IF NOT EXISTS idx_events_incident_id ON events(incident_id);
            CREATE INDEX IF NOT EXISTS idx_detections_incident_id ON detections(incident_id);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
            CREATE INDEX IF NOT EXISTS idx_threat_indicators_value ON threat_indicators(value);
            CREATE INDEX IF NOT EXISTS idx_threat_indicators_type ON threat_indicators(indicator_type);
            CREATE INDEX IF NOT EXISTS idx_detections_event_id ON detections(event_id);
            CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_items(status);

            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                os_version TEXT NOT NULL,
                nkosi_version TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Online',
                last_seen TEXT NOT NULL,
                registered_at TEXT NOT NULL,
                events_count INTEGER NOT NULL DEFAULT 0,
                threats_count INTEGER NOT NULL DEFAULT 0,
                score INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_agents_hostname ON agents(hostname);
            CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
            ",
        )?;

        // F2.11: add agent columns to pre-existing databases (no-op on fresh ones)
        for stmt in [
            "ALTER TABLE events ADD COLUMN agent_id TEXT DEFAULT ''",
            "ALTER TABLE events ADD COLUMN agent_host TEXT DEFAULT ''",
            "ALTER TABLE quarantine_items ADD COLUMN agent_id TEXT DEFAULT ''",
            "ALTER TABLE quarantine_items ADD COLUMN agent_host TEXT DEFAULT ''",
        ] {
            match conn.execute(stmt, []) {
                Ok(_) => {}
                Err(e) if e.to_string().contains("duplicate column name") => {}
                Err(e) => return Err(e),
            }
        }

        // The agent_id indexes must be created AFTER the column migrations,
        // otherwise they fail on pre-existing databases that lack the column.
        for stmt in [
            "CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events(agent_id)",
            "CREATE INDEX IF NOT EXISTS idx_quarantine_agent_id ON quarantine_items(agent_id)",
        ] {
            conn.execute(stmt, [])?;
        }
        Ok(())
    }
}
