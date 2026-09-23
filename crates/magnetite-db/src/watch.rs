//! Watch (monitoring) domain repository (07_data_watch / screen_watch): hosts,
//! rules, groups, maintenance windows and metrics. Alerts are generated into the
//! shared Alert structure (evaluation engine added with the alerting feature).

use crate::error::{DbError, DbResult};
use crate::records::{parse_rfc3339, record_key, to_rfc3339};
use crate::store::Db;
use chrono::Utc;
use magnetite_core::domains::watch::model::{
    HostGroup, MaintenanceWindow, Metric, MonitorRule, MonitoredHost,
};
use magnetite_core::models::common::Severity;
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, SurrealValue};

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::Warning => "warning",
        Severity::Info => "info",
    }
}
fn severity_from(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "info" => Severity::Info,
        _ => Severity::Warning,
    }
}

fn json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "[]".into())
}
fn from_json<T: serde::de::DeserializeOwned + Default>(s: &str) -> T {
    serde_json::from_str(s).unwrap_or_default()
}

// ---- Records --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct HostRecord {
    id: Option<RecordId>,
    name: String,
    ip_address: String,
    hostname: Option<String>,
    description: Option<String>,
    host_type: String,
    status: String,
    os_type: Option<String>,
    agent_version: Option<String>,
    snmp_enabled: bool,
    last_seen: Option<String>,
    tags: String,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl HostRecord {
    fn into_model(self) -> MonitoredHost {
        MonitoredHost {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            name: self.name,
            ip_address: self.ip_address,
            hostname: self.hostname,
            description: self.description,
            host_type: self.host_type,
            status: self.status,
            os_type: self.os_type,
            agent_version: self.agent_version,
            snmp_enabled: self.snmp_enabled,
            last_seen: self.last_seen.as_deref().map(parse_rfc3339),
            tags: from_json(&self.tags),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct RuleRecord {
    id: Option<RecordId>,
    name: String,
    target_host: Option<String>,
    metric: String,
    warning_threshold: Option<f64>,
    critical_threshold: Option<f64>,
    severity: String,
    eval_interval_secs: u32,
    enabled: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl RuleRecord {
    fn into_model(self) -> MonitorRule {
        MonitorRule {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            name: self.name,
            target_host: self.target_host,
            metric: self.metric,
            warning_threshold: self.warning_threshold,
            critical_threshold: self.critical_threshold,
            severity: severity_from(&self.severity),
            eval_interval_secs: self.eval_interval_secs,
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct GroupRecord {
    id: Option<RecordId>,
    name: String,
    description: Option<String>,
    members: String,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl GroupRecord {
    fn members_vec(&self) -> Vec<String> {
        from_json(&self.members)
    }

    fn into_model(self) -> HostGroup {
        let members = self.members_vec();
        HostGroup {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            name: self.name,
            description: self.description,
            members,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct MaintRecord {
    id: Option<RecordId>,
    name: String,
    target_host: Option<String>,
    target_group: Option<String>,
    reason: Option<String>,
    starts_at: String,
    ends_at: String,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl MaintRecord {
    fn into_model(self) -> MaintenanceWindow {
        MaintenanceWindow {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            name: self.name,
            target_host: self.target_host,
            target_group: self.target_group,
            reason: self.reason,
            starts_at: parse_rfc3339(&self.starts_at),
            ends_at: parse_rfc3339(&self.ends_at),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct MetricRecord {
    id: Option<RecordId>,
    host_ref: String,
    name: String,
    value: f64,
    timestamp: String,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl MetricRecord {
    fn into_model(self) -> Metric {
        Metric {
            id: record_key(&self.id),
            host_ref: self.host_ref,
            name: self.name,
            value: self.value,
            timestamp: parse_rfc3339(&self.timestamp),
        }
    }
}

impl Db {
    // ---- Hosts ------------------------------------------------------------

    pub async fn list_watch_hosts(&self) -> DbResult<Vec<MonitoredHost>> {
        let recs: Vec<HostRecord> = self
            .inner
            .query("SELECT * FROM watch_host ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(HostRecord::into_model).collect())
    }

    async fn find_watch_host(&self, name: &str) -> DbResult<Option<HostRecord>> {
        let recs: Vec<HostRecord> = self
            .inner
            .query("SELECT * FROM watch_host WHERE name = $n LIMIT 1")
            .bind(("n", name.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next())
    }

    pub async fn save_watch_host(&self, host: &MonitoredHost) -> DbResult<MonitoredHost> {
        let now = to_rfc3339(Utc::now());
        if host.id.is_empty() {
            if self.find_watch_host(&host.name).await?.is_some() {
                return Err(DbError::Constraint("同じ名称が既に存在します。".into()));
            }
            let rec = HostRecord {
                id: None,
                name: host.name.clone(),
                ip_address: host.ip_address.clone(),
                hostname: host.hostname.clone(),
                description: host.description.clone(),
                host_type: host.host_type.clone(),
                status: "unknown".into(),
                os_type: host.os_type.clone(),
                agent_version: host.agent_version.clone(),
                snmp_enabled: host.snmp_enabled,
                last_seen: None,
                tags: json(&host.tags),
                created_at: now.clone(),
                updated_at: now,
                created_by: host.created_by.clone(),
            };
            let created: Option<HostRecord> = self.inner.create("watch_host").content(rec).await?;
            created
                .map(HostRecord::into_model)
                .ok_or_else(|| DbError::Constraint("host creation failed".into()))
        } else {
            let updated: Vec<HostRecord> = self
                .inner
                .query("UPDATE type::record('watch_host', $id) SET ip_address = $ip, hostname = $hn, description = $d, host_type = $ht, os_type = $os, agent_version = $av, snmp_enabled = $sn, tags = $tg, updated_at = $t")
                .bind(("id", host.id.clone()))
                .bind(("ip", host.ip_address.clone()))
                .bind(("hn", host.hostname.clone()))
                .bind(("d", host.description.clone()))
                .bind(("ht", host.host_type.clone()))
                .bind(("os", host.os_type.clone()))
                .bind(("av", host.agent_version.clone()))
                .bind(("sn", host.snmp_enabled))
                .bind(("tg", json(&host.tags)))
                .bind(("t", now))
                .await?
                .take(0)?;
            updated
                .into_iter()
                .next()
                .map(HostRecord::into_model)
                .ok_or(DbError::NotFound)
        }
    }

    /// Update a monitored host's live status (and `last_seen` when reachable),
    /// used by the embedded Watch collector. Matches by name.
    pub async fn update_watch_host_status(
        &self,
        name: &str,
        status: &str,
        reachable: bool,
    ) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        if reachable {
            self.inner
                .query(
                    "UPDATE watch_host SET status = $s, last_seen = $ls, updated_at = $t \
                     WHERE name = $n",
                )
                .bind(("s", status.to_string()))
                .bind(("ls", now.clone()))
                .bind(("t", now))
                .bind(("n", name.to_string()))
                .await?;
        } else {
            self.inner
                .query("UPDATE watch_host SET status = $s, updated_at = $t WHERE name = $n")
                .bind(("s", status.to_string()))
                .bind(("t", now))
                .bind(("n", name.to_string()))
                .await?;
        }
        Ok(())
    }

    /// Delete a host and detach it from groups/rules/maintenance references.
    pub async fn delete_watch_host(&self, id: &str, name: &str) -> DbResult<()> {
        // Remove from group members.
        for mut group in self.list_watch_group_records().await? {
            let mut members = group.members_vec();
            let before = members.len();
            members.retain(|m| m != name);
            if members.len() != before {
                group.members = json(&members);
                self.inner
                    .query("UPDATE type::record('watch_group', $id) SET members = $m")
                    .bind(("id", record_key(&group.id)))
                    .bind(("m", group.members.clone()))
                    .await?;
            }
        }
        // Null out rule / maintenance target references.
        self.inner
            .query("UPDATE watch_rule SET target_host = NONE WHERE target_host = $n")
            .bind(("n", name.to_string()))
            .await?;
        self.inner
            .query("UPDATE watch_maintenance SET target_host = NONE WHERE target_host = $n")
            .bind(("n", name.to_string()))
            .await?;
        let _: Option<HostRecord> = self.inner.delete(("watch_host", id)).await?;
        Ok(())
    }

    // ---- Rules ------------------------------------------------------------

    pub async fn list_watch_rules(&self) -> DbResult<Vec<MonitorRule>> {
        let recs: Vec<RuleRecord> = self
            .inner
            .query("SELECT * FROM watch_rule ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(RuleRecord::into_model).collect())
    }

    pub async fn save_watch_rule(&self, rule: &MonitorRule) -> DbResult<MonitorRule> {
        let now = to_rfc3339(Utc::now());
        if rule.id.is_empty() {
            let rec = RuleRecord {
                id: None,
                name: rule.name.clone(),
                target_host: rule.target_host.clone(),
                metric: rule.metric.clone(),
                warning_threshold: rule.warning_threshold,
                critical_threshold: rule.critical_threshold,
                severity: severity_str(rule.severity).into(),
                eval_interval_secs: rule.eval_interval_secs,
                enabled: rule.enabled,
                created_at: now.clone(),
                updated_at: now,
                created_by: rule.created_by.clone(),
            };
            let created: Option<RuleRecord> = self.inner.create("watch_rule").content(rec).await?;
            created
                .map(RuleRecord::into_model)
                .ok_or_else(|| DbError::Constraint("rule creation failed".into()))
        } else {
            let updated: Vec<RuleRecord> = self
                .inner
                .query("UPDATE type::record('watch_rule', $id) SET name = $n, target_host = $th, metric = $m, warning_threshold = $w, critical_threshold = $c, severity = $s, eval_interval_secs = $ei, enabled = $en, updated_at = $t")
                .bind(("id", rule.id.clone()))
                .bind(("n", rule.name.clone()))
                .bind(("th", rule.target_host.clone()))
                .bind(("m", rule.metric.clone()))
                .bind(("w", rule.warning_threshold))
                .bind(("c", rule.critical_threshold))
                .bind(("s", severity_str(rule.severity).to_string()))
                .bind(("ei", rule.eval_interval_secs))
                .bind(("en", rule.enabled))
                .bind(("t", now))
                .await?
                .take(0)?;
            updated
                .into_iter()
                .next()
                .map(RuleRecord::into_model)
                .ok_or(DbError::NotFound)
        }
    }

    pub async fn set_watch_rule_enabled(&self, id: &str, enabled: bool) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('watch_rule', $id) SET enabled = $v, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("v", enabled))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    pub async fn delete_watch_rule(&self, id: &str) -> DbResult<()> {
        let _: Option<RuleRecord> = self.inner.delete(("watch_rule", id)).await?;
        Ok(())
    }

    // ---- Groups -----------------------------------------------------------

    async fn list_watch_group_records(&self) -> DbResult<Vec<GroupRecord>> {
        Ok(self
            .inner
            .query("SELECT * FROM watch_group ORDER BY name ASC")
            .await?
            .take(0)?)
    }

    pub async fn list_watch_groups(&self) -> DbResult<Vec<HostGroup>> {
        Ok(self
            .list_watch_group_records()
            .await?
            .into_iter()
            .map(GroupRecord::into_model)
            .collect())
    }

    pub async fn save_watch_group(&self, group: &HostGroup) -> DbResult<HostGroup> {
        let now = to_rfc3339(Utc::now());
        if group.id.is_empty() {
            let recs: Vec<GroupRecord> = self
                .inner
                .query("SELECT * FROM watch_group WHERE name = $n LIMIT 1")
                .bind(("n", group.name.clone()))
                .await?
                .take(0)?;
            if !recs.is_empty() {
                return Err(DbError::Constraint("同じ名称が既に存在します。".into()));
            }
            let rec = GroupRecord {
                id: None,
                name: group.name.clone(),
                description: group.description.clone(),
                members: json(&group.members),
                created_at: now.clone(),
                updated_at: now,
                created_by: group.created_by.clone(),
            };
            let created: Option<GroupRecord> =
                self.inner.create("watch_group").content(rec).await?;
            created
                .map(GroupRecord::into_model)
                .ok_or_else(|| DbError::Constraint("group creation failed".into()))
        } else {
            let updated: Vec<GroupRecord> = self
                .inner
                .query("UPDATE type::record('watch_group', $id) SET description = $d, members = $m, updated_at = $t")
                .bind(("id", group.id.clone()))
                .bind(("d", group.description.clone()))
                .bind(("m", json(&group.members)))
                .bind(("t", now))
                .await?
                .take(0)?;
            updated
                .into_iter()
                .next()
                .map(GroupRecord::into_model)
                .ok_or(DbError::NotFound)
        }
    }

    pub async fn delete_watch_group(&self, id: &str, name: &str) -> DbResult<()> {
        self.inner
            .query("UPDATE watch_maintenance SET target_group = NONE WHERE target_group = $n")
            .bind(("n", name.to_string()))
            .await?;
        let _: Option<GroupRecord> = self.inner.delete(("watch_group", id)).await?;
        Ok(())
    }

    // ---- Maintenance windows ----------------------------------------------

    pub async fn list_watch_maintenance(&self) -> DbResult<Vec<MaintenanceWindow>> {
        let recs: Vec<MaintRecord> = self
            .inner
            .query("SELECT * FROM watch_maintenance ORDER BY starts_at DESC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(MaintRecord::into_model).collect())
    }

    pub async fn create_watch_maintenance(
        &self,
        window: &MaintenanceWindow,
    ) -> DbResult<MaintenanceWindow> {
        let now = to_rfc3339(Utc::now());
        let rec = MaintRecord {
            id: None,
            name: window.name.clone(),
            target_host: window.target_host.clone(),
            target_group: window.target_group.clone(),
            reason: window.reason.clone(),
            starts_at: to_rfc3339(window.starts_at),
            ends_at: to_rfc3339(window.ends_at),
            created_at: now.clone(),
            updated_at: now,
            created_by: window.created_by.clone(),
        };
        let created: Option<MaintRecord> =
            self.inner.create("watch_maintenance").content(rec).await?;
        created
            .map(MaintRecord::into_model)
            .ok_or_else(|| DbError::Constraint("maintenance creation failed".into()))
    }

    pub async fn delete_watch_maintenance(&self, id: &str) -> DbResult<()> {
        let _: Option<MaintRecord> = self.inner.delete(("watch_maintenance", id)).await?;
        Ok(())
    }

    /// Host names currently under an active maintenance window (AC-20), directly
    /// or via a targeted group's members.
    pub async fn hosts_under_maintenance(&self) -> DbResult<Vec<String>> {
        let now = Utc::now();
        let windows = self.list_watch_maintenance().await?;
        let groups = self.list_watch_groups().await?;
        let mut hosts = std::collections::BTreeSet::new();
        for w in windows
            .into_iter()
            .filter(|w| w.starts_at <= now && now <= w.ends_at)
        {
            if let Some(h) = w.target_host {
                hosts.insert(h);
            }
            if let Some(g) = w.target_group {
                if let Some(group) = groups.iter().find(|gr| gr.name == g) {
                    hosts.extend(group.members.iter().cloned());
                }
            }
        }
        Ok(hosts.into_iter().collect())
    }

    // ---- Metrics ----------------------------------------------------------

    pub async fn list_host_metrics(&self, host_name: &str) -> DbResult<Vec<Metric>> {
        let recs: Vec<MetricRecord> = self
            .inner
            .query("SELECT * FROM watch_metric WHERE host_ref = $h ORDER BY timestamp ASC")
            .bind(("h", host_name.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(MetricRecord::into_model).collect())
    }

    /// Delete metric samples older than `cutoff` (RFC3339). Returns how many were removed.
    /// Called periodically so `watch_metric` (one row per sample) does not grow unbounded.
    pub async fn prune_watch_metrics_before(&self, cutoff: &str) -> DbResult<usize> {
        let removed: Vec<MetricRecord> = self
            .inner
            .query("DELETE FROM watch_metric WHERE timestamp < $c RETURN BEFORE")
            .bind(("c", cutoff.to_string()))
            .await?
            .take(0)?;
        Ok(removed.len())
    }

    /// Record a metric sample (used by the collector / tests).
    pub async fn record_metric(&self, host: &str, name: &str, value: f64) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        let rec = MetricRecord {
            id: None,
            host_ref: host.to_string(),
            name: name.to_string(),
            value,
            timestamp: now.clone(),
            created_at: now.clone(),
            updated_at: now,
            created_by: "system".into(),
        };
        let _: Option<MetricRecord> = self.inner.create("watch_metric").content(rec).await?;
        Ok(())
    }

    /// Metrics: total / online / offline / warning host counts + rule count.
    pub async fn watch_metrics(&self) -> DbResult<(usize, usize, usize, usize, usize)> {
        let hosts = self.list_watch_hosts().await?;
        let online = hosts.iter().filter(|h| h.status == "online").count();
        let offline = hosts.iter().filter(|h| h.status == "offline").count();
        let warning = hosts.iter().filter(|h| h.status == "warning").count();
        let rules = self.list_watch_rules().await?.len();
        Ok((hosts.len(), online, offline, warning, rules))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    fn host(name: &str) -> MonitoredHost {
        MonitoredHost {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            name: name.into(),
            ip_address: "10.0.0.1".into(),
            hostname: None,
            description: None,
            host_type: "server".into(),
            status: "unknown".into(),
            os_type: None,
            agent_version: None,
            snmp_enabled: false,
            last_seen: None,
            tags: vec!["prod".into()],
        }
    }

    #[tokio::test]
    async fn host_crud_and_group_cleanup() {
        let (db, _dir) = test_db().await;
        let h = db.save_watch_host(&host("web1")).await.unwrap();
        assert!(db.save_watch_host(&host("web1")).await.is_err());
        let group = HostGroup {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            name: "prod".into(),
            description: None,
            members: vec!["web1".into()],
        };
        db.save_watch_group(&group).await.unwrap();
        db.delete_watch_host(&h.id, "web1").await.unwrap();
        // Group membership is cleaned up.
        assert!(db.list_watch_groups().await.unwrap()[0].members.is_empty());
    }

    #[tokio::test]
    async fn maintenance_marks_hosts() {
        let (db, _dir) = test_db().await;
        db.save_watch_host(&host("db1")).await.unwrap();
        let now = Utc::now();
        let window = MaintenanceWindow {
            id: String::new(),
            created_at: now,
            updated_at: now,
            created_by: "admin".into(),
            name: "urgent".into(),
            target_host: Some("db1".into()),
            target_group: None,
            reason: None,
            starts_at: now - chrono::Duration::minutes(10),
            ends_at: now + chrono::Duration::hours(1),
        };
        db.create_watch_maintenance(&window).await.unwrap();
        assert_eq!(
            db.hosts_under_maintenance().await.unwrap(),
            vec!["db1".to_string()]
        );
    }

    #[tokio::test]
    async fn rule_toggle() {
        let (db, _dir) = test_db().await;
        let rule = MonitorRule {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            name: "cpu".into(),
            target_host: None,
            metric: "cpu_percent".into(),
            warning_threshold: Some(80.0),
            critical_threshold: Some(95.0),
            severity: Severity::Warning,
            eval_interval_secs: 60,
            enabled: true,
        };
        let saved = db.save_watch_rule(&rule).await.unwrap();
        db.set_watch_rule_enabled(&saved.id, false).await.unwrap();
        assert!(!db.list_watch_rules().await.unwrap()[0].enabled);
    }
}
