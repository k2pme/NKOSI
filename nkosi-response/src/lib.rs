use nkosi_common::types::*;
use nkosi_db::Database;
use nkosi_scanner::FirewallManager;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

pub struct ResponseEngine {
    quarantine_path: PathBuf,
    db: Option<Database>,
}

impl ResponseEngine {
    pub fn new(quarantine_path: PathBuf, db: Option<Database>) -> Self {
        Self {
            quarantine_path,
            db,
        }
    }

    pub async fn execute_action(
        &self,
        action: &ResponseAction,
        file_path: Option<&str>,
        pid: Option<u32>,
        ip: Option<&str>,
        score: u32,
        reason: &str,
    ) -> anyhow::Result<()> {
        match action {
            ResponseAction::Allow => {
                info!("Action: ALLOW");
                Ok(())
            }
            ResponseAction::Alert => {
                info!("Action: ALERT - {}", reason);
                Ok(())
            }
            ResponseAction::Kill => {
                if let Some(pid) = pid {
                    self.kill_process(pid).await?;
                }
                Ok(())
            }
            ResponseAction::Block => {
                if let Some(ip) = ip {
                    self.block_ip(ip, reason).await?;
                }
                Ok(())
            }
            ResponseAction::Quarantine => {
                if let Some(path) = file_path {
                    self.quarantine_file(path, score, reason).await?;
                }
                Ok(())
            }
            ResponseAction::Restore => {
                if let Some(path) = file_path {
                    self.restore_file(path).await?;
                }
                Ok(())
            }
            ResponseAction::Delete => {
                if let Some(path) = file_path {
                    self.delete_from_quarantine(path).await?;
                }
                Ok(())
            }
        }
    }

    async fn block_ip(&self, ip: &str, reason: &str) -> anyhow::Result<()> {
        let mgr = FirewallManager::new();
        match mgr.block_ip(ip, Some(reason), false) {
            Ok(()) => {
                info!("Blocked IP {} via iptables (reason: {})", ip, reason);
                Ok(())
            }
            Err(e) => {
                warn!("Failed to block IP {} via iptables: {}", ip, e);
                Err(e)
            }
        }
    }

    async fn kill_process(&self, pid: u32) -> anyhow::Result<()> {
        info!("Killing process PID: {}", pid);

        #[cfg(unix)]
        {
            unsafe {
                let result = libc::kill(pid as i32, libc::SIGKILL);
                if result == 0 {
                    info!("Successfully killed process {}", pid);
                } else {
                    let err = std::io::Error::last_os_error();
                    warn!("Failed to kill process {}: {}", pid, err);
                    return Err(err.into());
                }
            }
        }

        Ok(())
    }

    async fn quarantine_file(
        &self,
        file_path: &str,
        score: u32,
        reason: &str,
    ) -> anyhow::Result<()> {
        let source = Path::new(file_path);

        if !source.exists() {
            warn!("File not found for quarantine: {}", file_path);
            return Ok(());
        }

        // Create quarantine directory if needed
        std::fs::create_dir_all(&self.quarantine_path)?;

        // Generate quarantine filename
        let id = uuid::Uuid::new_v4();
        let filename = format!(
            "{}_{}",
            id,
            source.file_name().unwrap_or_default().to_string_lossy()
        );
        let dest = self.quarantine_path.join(&filename);

        // Compute hash before moving
        let hash = self.compute_hash(source).unwrap_or_default();

        // Rename is atomic when both paths are on the same filesystem. Fall back
        // to copy+remove only after the destination has been fully written.
        if let Err(rename_error) = std::fs::rename(source, &dest) {
            warn!(
                "Atomic quarantine move unavailable: {}; falling back to copy",
                rename_error
            );
            std::fs::copy(source, &dest)?;
            std::fs::File::open(&dest)?.sync_all()?;
            std::fs::remove_file(source)?;
        }

        // Remove permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o000);
            std::fs::set_permissions(&dest, perms)?;
        }

        info!(
            "Quarantined: {} -> {} (score: {}, reason: {})",
            file_path,
            dest.display(),
            score,
            reason
        );

        // Save to database if available
        if let Some(ref db) = self.db {
            let item = QuarantineItem {
                id,
                original_path: file_path.to_string(),
                quarantine_path: dest.to_string_lossy().to_string(),
                sha256: hash,
                reason: reason.to_string(),
                score,
                quarantined_at: chrono::Utc::now(),
                restored_at: None,
                deleted_at: None,
                status: QuarantineStatus::Quarantined,
            };

            let repo = nkosi_db::QuarantineRepository::new(db);
            if let Err(e) = repo.insert(&item) {
                error!("Failed to save quarantine item to database: {}", e);
            }
        }

        Ok(())
    }

    async fn restore_file(&self, quarantine_path: &str) -> anyhow::Result<()> {
        let source = Path::new(quarantine_path);

        if !source.exists() {
            warn!("Quarantine file not found: {}", quarantine_path);
            return Ok(());
        }

        let item = self
            .db
            .as_ref()
            .and_then(|db| nkosi_db::QuarantineRepository::new(db).get_active().ok())
            .and_then(|items| {
                items
                    .into_iter()
                    .find(|item| item.quarantine_path == quarantine_path)
            })
            .ok_or_else(|| {
                anyhow::anyhow!("Quarantine metadata not found; refusing unsafe restore")
            })?;
        let dest = PathBuf::from(&item.original_path);

        // Warn about restoring potentially dangerous file
        warn!(
            "WARNING: Restoring potentially dangerous file {} to {}",
            quarantine_path,
            dest.display()
        );

        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(source, &dest)?;

        // Restore permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o644);
            std::fs::set_permissions(&dest, perms)?;
        }

        // Remove from quarantine
        std::fs::remove_file(source)?;
        if let Some(ref db) = self.db {
            nkosi_db::QuarantineRepository::new(db)
                .update_status(&item.id, QuarantineStatus::Restored)?;
        }

        info!("Restored: {} -> {}", quarantine_path, dest.display());

        Ok(())
    }

    async fn delete_from_quarantine(&self, quarantine_path: &str) -> anyhow::Result<()> {
        let source = Path::new(quarantine_path);

        if !source.exists() {
            warn!("Quarantine file not found: {}", quarantine_path);
            return Ok(());
        }

        // Permanently delete
        std::fs::remove_file(source)?;
        if let Some(ref db) = self.db
            && let Some(item) = nkosi_db::QuarantineRepository::new(db)
                .get_active()?
                .into_iter()
                .find(|item| item.quarantine_path == quarantine_path)
        {
            nkosi_db::QuarantineRepository::new(db)
                .update_status(&item.id, QuarantineStatus::Deleted)?;
        }

        info!("Permanently deleted from quarantine: {}", quarantine_path);

        Ok(())
    }

    fn compute_hash(&self, path: &Path) -> Option<String> {
        use sha2::{Digest, Sha256};
        use std::io::Read;

        let mut file = std::fs::File::open(path).ok()?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer).ok()?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Some(format!("{:x}", hasher.finalize()))
    }

    pub fn get_quarantine_items(&self) -> Vec<QuarantineItem> {
        if let Some(ref db) = self.db {
            let repo = nkosi_db::QuarantineRepository::new(db);
            repo.get_active().unwrap_or_default()
        } else {
            Vec::new()
        }
    }
}
