use crate::schema::Database;
use chrono::{DateTime, Utc};
use nkosi_common::types::*;
use rusqlite::{params, types::ToSql};
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
                file_path, file_hash, remote_ip, remote_port, domain, incident_id,
                severity, score, action, result, agent_id, agent_host
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
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
                event.incident_id.as_ref().map(|id| id.to_string()),
                serde_json::to_string(&event.severity).unwrap(),
                event.score,
                event.action.as_ref().map(|a| serde_json::to_string(a).unwrap()),
                event.result,
                event.agent_id,
                event.agent_host,
            ],
        )?;
        Ok(())
    }

    pub fn get_by_id(&self, id: &Uuid) -> Result<Option<Event>, rusqlite::Error> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, event_type, source_module, pid, ppid, user,
                    file_path, file_hash, remote_ip, remote_port, domain, incident_id,
                    severity, score, action, result, agent_id, agent_host
             FROM events WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map(params![id.to_string()], |row| {
            Ok(Event {
                id: Uuid::parse_str(&row.get::<_, String>(0)?)
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
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
                incident_id: row
                    .get::<_, Option<String>>(12)?
                    .and_then(|s| Uuid::parse_str(&s).ok()),
                severity: serde_json::from_str(&row.get::<_, String>(13)?).unwrap(),
                score: row.get(14)?,
                action: row
                    .get::<_, Option<String>>(15)?
                    .map(|a| serde_json::from_str(&a).unwrap()),
                result: row.get(16)?,
                agent_id: row.get(17)?,
                agent_host: row.get(18)?,
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
                    file_path, file_hash, remote_ip, remote_port, domain, incident_id,
                    severity, score, action, result, agent_id, agent_host
             FROM events ORDER BY timestamp DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit], |row| {
            Ok(Event {
                id: Uuid::parse_str(&row.get::<_, String>(0)?)
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
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
                incident_id: row
                    .get::<_, Option<String>>(12)?
                    .and_then(|s| Uuid::parse_str(&s).ok()),
                severity: serde_json::from_str(&row.get::<_, String>(13)?).unwrap(),
                score: row.get(14)?,
                action: row
                    .get::<_, Option<String>>(15)?
                    .map(|a| serde_json::from_str(&a).unwrap()),
                result: row.get(16)?,
                agent_id: row.get(17)?,
                agent_host: row.get(18)?,
            })
        })?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    pub fn get_by_incident(&self, incident_id: &Uuid) -> Result<Vec<Event>, rusqlite::Error> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, event_type, source_module, pid, ppid, user,
                    file_path, file_hash, remote_ip, remote_port, domain, incident_id,
                    severity, score, action, result, agent_id, agent_host
             FROM events WHERE incident_id = ?1 ORDER BY timestamp ASC",
        )?;

        let rows = stmt.query_map(params![incident_id.to_string()], |row| {
            Ok(Event {
                id: Uuid::parse_str(&row.get::<_, String>(0)?)
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
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
                incident_id: row
                    .get::<_, Option<String>>(12)?
                    .and_then(|s| Uuid::parse_str(&s).ok()),
                severity: serde_json::from_str(&row.get::<_, String>(13)?).unwrap(),
                score: row.get(14)?,
                action: row
                    .get::<_, Option<String>>(15)?
                    .map(|a| serde_json::from_str(&a).unwrap()),
                result: row.get(16)?,
                agent_id: row.get(17)?,
                agent_host: row.get(18)?,
            })
        })?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    pub fn link_to_incident(
        &self,
        event_id: &Uuid,
        incident_id: &Uuid,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.db.connection();
        conn.execute(
            "UPDATE events SET incident_id = ?1 WHERE id = ?2",
            params![incident_id.to_string(), event_id.to_string()],
        )?;
        Ok(())
    }
}

pub struct DetectionRepository<'a> {
    db: &'a Database,
}

impl<'a> DetectionRepository<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn insert(&self, detection: &Detection) -> Result<(), rusqlite::Error> {
        let conn = self.db.connection();
        conn.execute(
            "INSERT INTO detections (
                id, event_id, incident_id, detection_engine, rule_id, rule_name,
                confidence, score_contribution, details
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                detection.id.to_string(),
                detection.event_id.to_string(),
                detection.incident_id.as_ref().map(|id| id.to_string()),
                serde_json::to_string(&detection.detection_engine).unwrap(),
                detection.rule_id,
                detection.rule_name,
                detection.confidence,
                detection.score_contribution as i32,
                detection.details,
            ],
        )?;
        Ok(())
    }

    pub fn get_by_incident(&self, incident_id: &Uuid) -> Result<Vec<Detection>, rusqlite::Error> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT id, event_id, incident_id, detection_engine, rule_id, rule_name,
                    confidence, score_contribution, details
             FROM detections WHERE incident_id = ?1",
        )?;

        let rows = stmt.query_map(params![incident_id.to_string()], |row| {
            Ok(Detection {
                id: Uuid::parse_str(&row.get::<_, String>(0)?)
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                event_id: Uuid::parse_str(&row.get::<_, String>(1)?)
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                incident_id: row
                    .get::<_, Option<String>>(2)?
                    .and_then(|s| Uuid::parse_str(&s).ok()),
                detection_engine: serde_json::from_str(&row.get::<_, String>(3)?).unwrap(),
                rule_id: row.get(4)?,
                rule_name: row.get(5)?,
                confidence: row.get(6)?,
                score_contribution: row.get::<_, i32>(7)? as u32,
                details: row.get(8)?,
            })
        })?;

        let mut detections = Vec::new();
        for row in rows {
            detections.push(row?);
        }
        Ok(detections)
    }

    pub fn link_to_incident(
        &self,
        detection_id: &Uuid,
        incident_id: &Uuid,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.db.connection();
        conn.execute(
            "UPDATE detections SET incident_id = ?1 WHERE id = ?2",
            params![incident_id.to_string(), detection_id.to_string()],
        )?;
        Ok(())
    }
}

pub struct IncidentRepository<'a> {
    db: &'a Database,
}

impl<'a> IncidentRepository<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn insert(&self, incident: &Incident) -> Result<(), rusqlite::Error> {
        let conn = self.db.connection();
        conn.execute(
            "INSERT INTO incidents (
                id, created_at, updated_at, status, global_score, summary
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                incident.id.to_string(),
                incident.created_at.to_rfc3339(),
                incident.updated_at.to_rfc3339(),
                serde_json::to_string(&incident.status).unwrap(),
                incident.global_score as i32,
                incident.summary,
            ],
        )?;
        Ok(())
    }

    pub fn get_by_id(&self, id: &Uuid) -> Result<Option<Incident>, rusqlite::Error> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT id, created_at, updated_at, status, global_score, summary
             FROM incidents WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map(params![id.to_string()], |row| {
            Ok(Incident {
                id: Uuid::parse_str(&row.get::<_, String>(0)?)
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(2)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                status: serde_json::from_str(&row.get::<_, String>(3)?).unwrap(),
                global_score: row.get::<_, i32>(4)? as u32,
                summary: row.get(5)?,
            })
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    pub fn get_recent(&self, limit: i32) -> Result<Vec<Incident>, rusqlite::Error> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT id, created_at, updated_at, status, global_score, summary
             FROM incidents ORDER BY created_at DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit], |row| {
            Ok(Incident {
                id: Uuid::parse_str(&row.get::<_, String>(0)?)
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(2)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                status: serde_json::from_str(&row.get::<_, String>(3)?).unwrap(),
                global_score: row.get::<_, i32>(4)? as u32,
                summary: row.get(5)?,
            })
        })?;

        let mut incidents = Vec::new();
        for row in rows {
            incidents.push(row?);
        }
        Ok(incidents)
    }

    pub fn update_status(&self, id: &Uuid, status: IncidentStatus) -> Result<(), rusqlite::Error> {
        let now = Utc::now().to_rfc3339();
        let conn = self.db.connection();
        conn.execute(
            "UPDATE incidents SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![serde_json::to_string(&status).unwrap(), now, id.to_string()],
        )?;
        Ok(())
    }

    pub fn update_score(&self, id: &Uuid, score: u32) -> Result<(), rusqlite::Error> {
        let conn = self.db.connection();
        conn.execute(
            "UPDATE incidents SET global_score = ?1, updated_at = ?2 WHERE id = ?3",
            params![score as i32, Utc::now().to_rfc3339(), id.to_string()],
        )?;
        Ok(())
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
                id: Uuid::parse_str(&row.get::<_, String>(0)?)
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                indicator_type: serde_json::from_str(&row.get::<_, String>(1)?).unwrap(),
                value: row.get(2)?,
                malware_family: row.get(3)?,
                confidence: row.get(4)?,
                severity: serde_json::from_str(&row.get::<_, String>(5)?).unwrap(),
                source: row.get(6)?,
                first_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                last_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
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
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM threat_indicators WHERE enabled = 1")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count)
    }

    /// Returns enabled SHA-256 indicators for the in-memory file hash engine.
    pub fn get_enabled_sha256_values(&self) -> Result<Vec<String>, rusqlite::Error> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT value FROM threat_indicators WHERE indicator_type = ?1 AND enabled = 1",
        )?;
        stmt.query_map(
            params![serde_json::to_string(&IndicatorType::Sha256).unwrap()],
            |row| row.get(0),
        )?
        .collect()
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
                id: Uuid::parse_str(&row.get::<_, String>(0)?)
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                original_path: row.get(1)?,
                quarantine_path: row.get(2)?,
                sha256: row.get(3)?,
                reason: row.get(4)?,
                score: row.get(5)?,
                quarantined_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                restored_at: row.get::<_, Option<String>>(7)?.map(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .unwrap()
                        .with_timezone(&Utc)
                }),
                deleted_at: row.get::<_, Option<String>>(8)?.map(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .unwrap()
                        .with_timezone(&Utc)
                }),
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
                id: Uuid::parse_str(&row.get::<_, String>(0)?)
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                original_path: row.get(1)?,
                quarantine_path: row.get(2)?,
                sha256: row.get(3)?,
                reason: row.get(4)?,
                score: row.get(5)?,
                quarantined_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                restored_at: row.get::<_, Option<String>>(7)?.map(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .unwrap()
                        .with_timezone(&Utc)
                }),
                deleted_at: row.get::<_, Option<String>>(8)?.map(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .unwrap()
                        .with_timezone(&Utc)
                }),
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

pub struct AgentRepository<'a> {
    db: &'a Database,
}

impl<'a> AgentRepository<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn upsert(&self, agent: &Agent) -> Result<(), rusqlite::Error> {
        let conn = self.db.connection();
        conn.execute(
            "INSERT OR REPLACE INTO agents (
                id, hostname, ip_address, os_version, nkosi_version, agent_name,
                status, last_seen, registered_at, events_count, threats_count, score
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                agent.id,
                agent.hostname,
                agent.ip_address,
                agent.os_version,
                agent.nkosi_version,
                agent.agent_name,
                match agent.status {
                    AgentStatus::Online => "Online",
                    AgentStatus::Offline => "Offline",
                    AgentStatus::Degraded => "Degraded",
                }
                .to_string(),
                agent.last_seen.to_rfc3339(),
                agent.registered_at.to_rfc3339(),
                agent.events_count,
                agent.threats_count,
                agent.score,
            ],
        )?;
        Ok(())
    }

    pub fn get_all(&self) -> Result<Vec<Agent>, rusqlite::Error> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT id, hostname, ip_address, os_version, nkosi_version, agent_name,
                    status, last_seen, registered_at, events_count, threats_count, score
             FROM agents ORDER BY last_seen DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(Agent {
                id: row.get(0)?,
                hostname: row.get(1)?,
                ip_address: row.get(2)?,
                os_version: row.get(3)?,
                nkosi_version: row.get(4)?,
                agent_name: row.get(5)?,
                status: match row.get::<_, String>(6)?.as_str() {
                    "Offline" => AgentStatus::Offline,
                    "Degraded" => AgentStatus::Degraded,
                    _ => AgentStatus::Online,
                },
                last_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                registered_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                events_count: row.get(9)?,
                threats_count: row.get(10)?,
                score: row.get(11)?,
            })
        })?;

        let mut agents = Vec::new();
        for row in rows {
            agents.push(row?);
        }
        Ok(agents)
    }

    pub fn get_by_id(&self, id: &str) -> Result<Option<Agent>, rusqlite::Error> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT id, hostname, ip_address, os_version, nkosi_version, agent_name,
                    status, last_seen, registered_at, events_count, threats_count, score
             FROM agents WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map(params![id], |row| {
            Ok(Agent {
                id: row.get(0)?,
                hostname: row.get(1)?,
                ip_address: row.get(2)?,
                os_version: row.get(3)?,
                nkosi_version: row.get(4)?,
                agent_name: row.get(5)?,
                status: match row.get::<_, String>(6)?.as_str() {
                    "Offline" => AgentStatus::Offline,
                    "Degraded" => AgentStatus::Degraded,
                    _ => AgentStatus::Online,
                },
                last_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                registered_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                events_count: row.get(9)?,
                threats_count: row.get(10)?,
                score: row.get(11)?,
            })
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    pub fn update_heartbeat(
        &self,
        id: &str,
        score: u32,
        events: u32,
        threats: u32,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.db.connection();
        conn.execute(
            "UPDATE agents SET last_seen = ?1, score = ?2, events_count = ?3, threats_count = ?4, status = 'Online' WHERE id = ?5",
            params![Utc::now().to_rfc3339(), score, events, threats, id],
        )?;
        Ok(())
    }

    pub fn mark_offline_stale(&self, stale_seconds: i64) -> Result<u32, rusqlite::Error> {
        let conn = self.db.connection();
        let cutoff = (Utc::now() - chrono::Duration::seconds(stale_seconds)).to_rfc3339();
        let affected = conn.execute(
            "UPDATE agents SET status = 'Offline' WHERE status != 'Offline' AND last_seen < ?1",
            params![cutoff],
        )?;
        Ok(affected as u32)
    }

    pub fn get_events_filtered(
        &self,
        agent_id: Option<&str>,
        host: Option<&str>,
        severity: Option<&str>,
        limit: i32,
    ) -> Result<Vec<Event>, rusqlite::Error> {
        let conn = self.db.connection();
        let mut sql = "SELECT id, timestamp, event_type, source_module, pid, ppid, user,
                file_path, file_hash, remote_ip, remote_port, domain, incident_id,
                severity, score, action, result, agent_id, agent_host
         FROM events WHERE 1=1"
            .to_string();

        let mut params_vec: Vec<Box<dyn ToSql>> = Vec::new();
        let mut param_idx = 1;

        if let Some(aid) = agent_id
            && !aid.is_empty()
        {
            sql.push_str(&format!(" AND agent_id = ?{param_idx}"));
            params_vec.push(Box::new(aid.to_string()));
            param_idx += 1;
        }
        if let Some(h) = host
            && !h.is_empty()
        {
            sql.push_str(&format!(" AND agent_host = ?{param_idx}"));
            params_vec.push(Box::new(h.to_string()));
            param_idx += 1;
        }
        if let Some(s) = severity
            && !s.is_empty()
        {
            // Severity is stored as JSON ("Critical"), so compare with JSON-encoded value
            let json_severity = serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s));
            sql.push_str(&format!(" AND severity = ?{param_idx}"));
            params_vec.push(Box::new(json_severity));
            param_idx += 1;
        }
        sql.push_str(&format!(" ORDER BY timestamp DESC LIMIT ?{param_idx}"));
        params_vec.push(Box::new(limit));

        let param_refs: Vec<&dyn ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(param_refs.as_slice(), |row| {
            Ok(Event {
                id: Uuid::parse_str(&row.get::<_, String>(0)?)
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
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
                incident_id: row
                    .get::<_, Option<String>>(12)?
                    .and_then(|s| Uuid::parse_str(&s).ok()),
                severity: serde_json::from_str(&row.get::<_, String>(13)?).unwrap(),
                score: row.get(14)?,
                action: row
                    .get::<_, Option<String>>(15)?
                    .map(|a| serde_json::from_str(&a).unwrap()),
                result: row.get(16)?,
                agent_id: row.get(17)?,
                agent_host: row.get(18)?,
            })
        })?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    pub fn get_consolidated_stats(&self) -> Result<ConsolidatedStats, rusqlite::Error> {
        let conn = self.db.connection();

        let total_agents: u32 =
            conn.query_row("SELECT COUNT(*) FROM agents", [], |row| row.get(0))?;
        let online_agents: u32 = conn.query_row(
            "SELECT COUNT(*) FROM agents WHERE status = 'Online'",
            [],
            |row| row.get(0),
        )?;
        let total_events: u64 =
            conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        let total_threats: u64 = conn.query_row(
            "SELECT COUNT(*) FROM events WHERE event_type LIKE '%Detection%'",
            [],
            |row| row.get(0),
        )?;
        let total_quarantine: u64 = conn.query_row(
            "SELECT COUNT(*) FROM quarantine_items WHERE status = '\"Quarantined\"'",
            [],
            |row| row.get(0),
        )?;

        Ok(ConsolidatedStats {
            total_agents,
            online_agents,
            offline_agents: total_agents - online_agents,
            total_events: total_events as u32,
            total_threats: total_threats as u32,
            total_quarantine: total_quarantine as u32,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConsolidatedStats {
    pub total_agents: u32,
    pub online_agents: u32,
    pub offline_agents: u32,
    pub total_events: u32,
    pub total_threats: u32,
    pub total_quarantine: u32,
}
