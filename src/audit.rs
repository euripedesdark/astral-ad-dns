use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use std::collections::VecDeque;
use chrono::Utc;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: String,
    pub operator: String,
    pub client_ip: Option<String>,
    pub action: String,
    pub target: String,
    pub dry_run: bool,
    pub success: bool,
    pub details: String,
}

#[derive(Debug)]
pub struct AuditTrail {
    events: RwLock<VecDeque<AuditEvent>>,
    max_entries: usize,
}

impl AuditTrail {
    pub fn new(max_entries: usize) -> Self {
        Self {
            events: RwLock::new(VecDeque::with_capacity(max_entries)),
            max_entries,
        }
    }

    pub fn record(
        &self,
        operator: &str,
        client_ip: Option<&str>,
        action: &str,
        target: &str,
        dry_run: bool,
        success: bool,
        details: &str,
    ) -> String {
        let ts = Utc::now();
        let rand_val = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() & 0xFFFF) as u16;
        let id = format!("evt_{}_{:04x}", ts.timestamp_millis(), rand_val);

        let event = AuditEvent {
            id: id.clone(),
            timestamp: ts.to_rfc3339(),
            operator: operator.to_string(),
            client_ip: client_ip.map(|s| s.to_string()),
            action: action.to_string(),
            target: target.to_string(),
            dry_run,
            success,
            details: details.to_string(),
        };

        if let Ok(mut lock) = self.events.write() {
            if lock.len() >= self.max_entries {
                lock.pop_front();
            }
            lock.push_back(event);
        }

        id
    }

    pub fn list(&self, limit: usize) -> Vec<AuditEvent> {
        if let Ok(lock) = self.events.read() {
            lock.iter().rev().take(limit).cloned().collect()
        } else {
            Vec::new()
        }
    }

    pub fn clear(&self) {
        if let Ok(mut lock) = self.events.write() {
            lock.clear();
        }
    }

    pub fn count(&self) -> usize {
        self.events.read().map(|l| l.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_recording_and_limiting() {
        let trail = AuditTrail::new(3);
        trail.record("admin", Some("127.0.0.1"), "USER_CREATE", "user:maria", false, true, "Created user maria");
        trail.record("admin", Some("127.0.0.1"), "USER_DELETE", "user:carlos", true, true, "[SIMULATION] Delete user carlos");
        trail.record("operator", None, "DNS_ADD", "record:web.lan", false, true, "Added A record");

        let list = trail.list(10);
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].action, "DNS_ADD"); // mais recente primeiro
        assert_eq!(list[1].action, "USER_DELETE");
        assert!(list[1].dry_run);

        // Ultrapassa capacidade máxima 3
        trail.record("admin", None, "BACKUP", "backup:daily", false, true, "Backup created");
        let list_after = trail.list(10);
        assert_eq!(list_after.len(), 3);
        assert_eq!(list_after[0].action, "BACKUP");
        // O primeiro evento ("USER_CREATE") foi descartado pelo buffer circular
        assert!(!list_after.iter().any(|e| e.action == "USER_CREATE"));
    }
}
