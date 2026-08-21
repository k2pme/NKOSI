use crate::schema::Database;
use chrono::{DateTime, Utc};
use nkosi_common::types::*;
use rusqlite::params;
use uuid::Uuid;

pub struct EventRepository<'a> {
    db: &'a Database,
}

impl<'a> EventRepository<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn insert(&self, event: &Event) -> Result<(), rusqlite::Error> {
        let conn = self.db.connection();
        conn.execute(
            "INSERT INTO events (
                id, timestamp, event_type, source_module, pid, ppid, user,
                file_path, file_hash, remote_ip, remote_port, domain,
                severity, score, action, result
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                event.id.to_string(),
                event.timestamp.to_rfc3339(),
                serde_json::to_string(&event.event_type).unwrap(),
                event.source_module,
                event.pid,
                event.ppid,
                event.user,
                event.file_path,
                event.file_hash,
                event.remote_ip,
                event.remote_port,
                event.domain,
                serde_json::to_string(&event.severity).unwrap(),
                event.score,
                event.action.as_ref().map(|a| serde_json::to_string(a).unwrap()),
                event.result,
            ],
        )?;
        Ok(())
    }

    pub fn get_by_id(&self, id: &Uuid) -> Result<Option<Event>, rusqlite::Error> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, event_type, source_module, pid, ppid, user,
                    file_path, file_hash, remote_ip, remote_port, domain,
                    severity, score, action, result
             FROM events WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map(params![id.to_string()], |row| {
            Ok(Event {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap(),
                timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                    .unwrap()
                    .with_timezone(&Utc),
                event_type: serde_json::from_str(&row.get::<_, String>(2)?).unwrap(),
                source_module: row.get(3)?,
                pid: row.get(4)?,
                ppid: row.get(5)?,
                user: row.get(6)?,
                file_path: row.get(7)?,
                file_hash: row.get(8)?,
                remote_ip: row.get(9)?,
                remote_port: row.get(10)?,
                domain: row.get(11)?,
                severity: serde_json::from_str(&row.get::<_, String>(12)?).unwrap(),
                score: row.get(13)?,
                action: row.get::<_, Option<String>>(14)?
                    .map(|a| serde_json::from_str(&a).unwrap()),
                result: row.get(15)?,
            })
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    pub fn get_recent(&self, limit: i32) -> Result<Vec<Event>, rusqlite::Error> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, event_type, source_module, pid, ppid, user,
                    file_path, file_hash, remote_ip, remote_port, domain,
                    severity, score, action, result
             FROM events ORDER BY timestamp DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit], |row| {
            Ok(Event {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap(),
                timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                    .unwrap()
                    .with_timezone(&Utc),
                event_type: serde_json::from_str(&row.get::<_, String>(2)?).unwrap(),
                source_module: row.get(3)?,
                pid: row.get(4)?,
                ppid: row.get(5)?,
                user: row.get(6)?,
                file_path: row.get(7)?,
                file_hash: row.get(8)?,
                remote_ip: row.get(9)?,
                remote_port: row.get(10)?,
                domain: row.get(11)?,
                severity: serde_json::from_str(&row.get::<_, String>(12)?).unwrap(),
                score: row.get(13)?,
                action: row.get::<_, Option<String>>(14)?
                    .map(|a| serde_json::from_str(&a).unwrap()),
                result: row.get(15)?,
            })
        })?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }
}

pub struct ThreatIndicatorRepository<'a> {
    db: &'a Database,
}

impl<'a> ThreatIndicatorRepository<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn insert(&self, indicator: &ThreatIndicator) -> Result<(), rusqlite::Error> {
        let conn = self.db.connection();
        conn.execute(
            "INSERT OR REPLACE INTO threat_indicators (
                id, indicator_type, value, malware_family, confidence, severity,
                source, first_seen, last_seen, tags, enabled
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                indicator.id.to_string(),
                serde_json::to_string(&indicator.indicator_type).unwrap(),
                indicator.value,
                indicator.malware_family,
                indicator.confidence,
                serde_json::to_string(&indicator.severity).unwrap(),
                indicator.source,
                indicator.first_seen.to_rfc3339(),
                indicator.last_seen.to_rfc3339(),
                serde_json::to_string(&indicator.tags).unwrap(),
                indicator.enabled as i32,
            ],
        )?;
        Ok(())
    }

    pub fn find_by_value(&self, value: &str) -> Result<Option<ThreatIndicator>, rusqlite::Error> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT id, indicator_type, value, malware_family, confidence, severity,
                    source, first_seen, last_seen, tags, enabled
             FROM threat_indicators WHERE value = ?1 AND enabled = 1",
        )?;

        let mut rows = stmt.query_map(params![value], |row| {
            Ok(ThreatIndicator {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap(),
                indicator_type: serde_json::from_str(&row.get::<_, String>(1)?).unwrap(),
                value: row.get(2)?,
                malware_family: row.get(3)?,
                confidence: row.get(4)?,
                severity: serde_json::from_str(&row.get::<_, String>(5)?).unwrap(),
                source: row.get(6)?,
                first_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                    .unwrap()
                    .with_timezone(&Utc),
                last_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .unwrap()
                    .with_timezone(&Utc),
                tags: serde_json::from_str(&row.get::<_, String>(9)?).unwrap(),
                enabled: row.get::<_, i32>(10)? != 0,
            })
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    pub fn count(&self) -> Result<i64, rusqlite::Error> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT COUNT(*) FROM threat_indicators WHERE enabled = 1",
        )?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count)
    }
}

pub struct QuarantineRepository<'a> {
    db: &'a Database,
}

impl<'a> QuarantineRepository<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn insert(&self, item: &QuarantineItem) -> Result<(), rusqlite::Error> {
        let conn = self.db.connection();
        conn.execute(
            "INSERT INTO quarantine_items (
                id, original_path, quarantine_path, sha256, reason, score,
                quarantined_at, restored_at, deleted_at, status
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                item.id.to_string(),
                item.original_path,
                item.quarantine_path,
                item.sha256,
                item.reason,
                item.score,
                item.quarantined_at.to_rfc3339(),
                item.restored_at.map(|t| t.to_rfc3339()),
                item.deleted_at.map(|t| t.to_rfc3339()),
                serde_json::to_string(&item.status).unwrap(),
            ],
        )?;
        Ok(())
    }

    pub fn get_active(&self) -> Result<Vec<QuarantineItem>, rusqlite::Error> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT id, original_path, quarantine_path, sha256, reason, score,
                    quarantined_at, restored_at, deleted_at, status
             FROM quarantine_items WHERE status = '\"Quarantined\"'
             ORDER BY quarantined_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(QuarantineItem {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap(),
                original_path: row.get(1)?,
                quarantine_path: row.get(2)?,
                sha256: row.get(3)?,
                reason: row.get(4)?,
                score: row.get(5)?,
                quarantined_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                    .unwrap()
                    .with_timezone(&Utc),
                restored_at: row.get::<_, Option<String>>(7)?
                    .map(|t| DateTime::parse_from_rfc3339(&t).unwrap().with_timezone(&Utc)),
                deleted_at: row.get::<_, Option<String>>(8)?
                    .map(|t| DateTime::parse_from_rfc3339(&t).unwrap().with_timezone(&Utc)),
                status: serde_json::from_str(&row.get::<_, String>(9)?).unwrap(),
            })
        })?;

        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    pub fn get_by_id(&self, id: &Uuid) -> Result<Option<QuarantineItem>, rusqlite::Error> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT id, original_path, quarantine_path, sha256, reason, score,
                    quarantined_at, restored_at, deleted_at, status
             FROM quarantine_items WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map(params![id.to_string()], |row| {
            Ok(QuarantineItem {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap(),
                original_path: row.get(1)?,
                quarantine_path: row.get(2)?,
                sha256: row.get(3)?,
                reason: row.get(4)?,
                score: row.get(5)?,
                quarantined_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                    .unwrap()
                    .with_timezone(&Utc),
                restored_at: row.get::<_, Option<String>>(7)?
                    .map(|t| DateTime::parse_from_rfc3339(&t).unwrap().with_timezone(&Utc)),
                deleted_at: row.get::<_, Option<String>>(8)?
                    .map(|t| DateTime::parse_from_rfc3339(&t).unwrap().with_timezone(&Utc)),
                status: serde_json::from_str(&row.get::<_, String>(9)?).unwrap(),
            })
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    pub fn update_status(
        &self,
        id: &Uuid,
        status: QuarantineStatus,
    ) -> Result<(), rusqlite::Error> {
        let now = Utc::now().to_rfc3339();
        let conn = self.db.connection();
        match status {
            QuarantineStatus::Restored => {
                conn.execute(
                    "UPDATE quarantine_items SET status = ?1, restored_at = ?2 WHERE id = ?3",
                    params![serde_json::to_string(&status).unwrap(), now, id.to_string()],
                )?;
            }
            QuarantineStatus::Deleted => {
                conn.execute(
                    "UPDATE quarantine_items SET status = ?1, deleted_at = ?2 WHERE id = ?3",
                    params![serde_json::to_string(&status).unwrap(), now, id.to_string()],
                )?;
            }
            _ => {}
        }
        Ok(())
    }
}

pub struct ScanRepository<'a> {
    db: &'a Database,
}

impl<'a> ScanRepository<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn insert(&self, scan: &Scan) -> Result<(), rusqlite::Error> {
        let conn = self.db.connection();
        conn.execute(
            "INSERT INTO scans (
                id, scan_type, target, started_at, completed_at,
                files_scanned, threats_found, suspicious_found, status
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                scan.id.to_string(),
                serde_json::to_string(&scan.scan_type).unwrap(),
                scan.target,
                scan.started_at.to_rfc3339(),
                scan.completed_at.map(|t| t.to_rfc3339()),
                scan.files_scanned,
                scan.threats_found,
                scan.suspicious_found,
                serde_json::to_string(&scan.status).unwrap(),
            ],
        )?;
        Ok(())
    }

    pub fn update(&self, scan: &Scan) -> Result<(), rusqlite::Error> {
        let conn = self.db.connection();
        conn.execute(
            "UPDATE scans SET
                completed_at = ?1,
                files_scanned = ?2,
                threats_found = ?3,
                suspicious_found = ?4,
                status = ?5
            WHERE id = ?6",
            params![
                scan.completed_at.map(|t| t.to_rfc3339()),
                scan.files_scanned,
                scan.threats_found,
                scan.suspicious_found,
                serde_json::to_string(&scan.status).unwrap(),
                scan.id.to_string(),
            ],
        )?;
        Ok(())
    }
}
