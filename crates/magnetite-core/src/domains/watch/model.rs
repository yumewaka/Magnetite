//! Watch (monitoring) domain data (07_data_watch): monitored hosts, alert-
//! generating rules, host groups, maintenance windows and metric samples. The
//! alerts themselves live in the shared `Alert` structure.

use crate::models::common::Severity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A monitored host (07_data_watch §1). `status`/`last_seen` are updated by the
/// monitoring engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredHost {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub name: String,
    pub ip_address: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// `server` etc.
    pub host_type: String,
    /// `online` / `offline` / `warning` / `unknown`.
    pub status: String,
    #[serde(default)]
    pub os_type: Option<String>,
    #[serde(default)]
    pub agent_version: Option<String>,
    pub snmp_enabled: bool,
    #[serde(default)]
    pub last_seen: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
}

/// A monitor rule that generates alerts on threshold breach (07_data_watch §2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorRule {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub name: String,
    /// Target host name; `None` = all hosts.
    #[serde(default)]
    pub target_host: Option<String>,
    /// `cpu_percent` / `memory_percent` / `disk_percent` / `net_rx` / `net_tx`
    /// / `process_missing` / `port_down` / `command_failed`.
    pub metric: String,
    #[serde(default)]
    pub warning_threshold: Option<f64>,
    #[serde(default)]
    pub critical_threshold: Option<f64>,
    pub severity: Severity,
    pub eval_interval_secs: u32,
    pub enabled: bool,
}

/// A logical group of hosts (07_data_watch §3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostGroup {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Member host names.
    pub members: Vec<String>,
}

/// A planned maintenance window that suppresses alerts (07_data_watch §4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceWindow {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub name: String,
    #[serde(default)]
    pub target_host: Option<String>,
    #[serde(default)]
    pub target_group: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
}

/// Derived maintenance status (S-WATCH-05 W5-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceStatus {
    Scheduled,
    Active,
    Ended,
}

impl MaintenanceWindow {
    /// Status at `now`.
    pub fn status_at(&self, now: DateTime<Utc>) -> MaintenanceStatus {
        if now < self.starts_at {
            MaintenanceStatus::Scheduled
        } else if now <= self.ends_at {
            MaintenanceStatus::Active
        } else {
            MaintenanceStatus::Ended
        }
    }
}

/// A metric time-series sample (07_data_watch §5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub id: String,
    pub host_ref: String,
    pub name: String,
    pub value: f64,
    pub timestamp: DateTime<Utc>,
}
