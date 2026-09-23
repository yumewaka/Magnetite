//! One collector pass: probe reachability, record metrics, refresh status, and
//! evaluate monitor rules into alerts. Factored out of the periodic loop so it
//! can be driven deterministically in tests.

use chrono::Utc;
use magnetite_core::domain::DomainKey;
use magnetite_core::domains::watch::model::{MonitorRule, MonitoredHost};
use magnetite_core::models::common::{LogKind, LogLevel, Severity};
use magnetite_db::{Db, NewAlert, NewLogEntry};
use std::collections::HashSet;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// Synthetic `rule_ref` for the built-in reachability alert (distinct from any
/// user MonitorRule id, which is a record key).
const REACHABILITY_RULE: &str = "reachability";

/// Probe a host's TCP reachability, returning latency in milliseconds on a
/// successful connect within [`PROBE_TIMEOUT`].
pub(crate) async fn tcp_probe(ip: &str, port: u16) -> Option<f64> {
    let addr = format!("{ip}:{port}");
    let start = tokio::time::Instant::now();
    match timeout(PROBE_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => Some(start.elapsed().as_secs_f64() * 1000.0),
        _ => None,
    }
}

/// Run a single collection pass over all monitored hosts and rules.
pub(crate) async fn collect_once(db: &Db, probe_port: u16, log_events: bool) {
    let hosts = db.list_watch_hosts().await.unwrap_or_default();
    let maintenance: HashSet<String> = db
        .hosts_under_maintenance()
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    let rules = db.list_watch_rules().await.unwrap_or_default();
    // Snapshot of currently-open Watch alerts, for de-duplication across ticks.
    let open = db
        .list_alerts(Some("open"), None, Some(DomainKey::Watch.as_str()))
        .await
        .unwrap_or_default();
    let is_open = |source: &str, rule: &str| -> bool {
        open.iter()
            .any(|a| a.source_ref.as_deref() == Some(source) && a.rule_ref.as_deref() == Some(rule))
    };

    for host in &hosts {
        let latency = tcp_probe(&host.ip_address, probe_port).await;
        let reachable = latency.is_some();
        let _ = db
            .record_metric(&host.name, "reachable", if reachable { 1.0 } else { 0.0 })
            .await;
        if let Some(ms) = latency {
            let _ = db.record_metric(&host.name, "latency_ms", ms).await;
        }

        let status = if reachable { "online" } else { "offline" };
        let _ = db
            .update_watch_host_status(&host.name, status, reachable)
            .await;

        // Reachability alert: raised once while the host stays down (dedup by the
        // open snapshot), suppressed under maintenance.
        if !reachable
            && !maintenance.contains(&host.name)
            && !is_open(&host.name, REACHABILITY_RULE)
        {
            let _ = db
                .raise_alert(NewAlert {
                    domain: DomainKey::Watch,
                    severity: Severity::Critical,
                    summary: format!("ホスト {} が到達不能です。", host.name),
                    source_ref: Some(host.name.clone()),
                    rule_ref: Some(REACHABILITY_RULE.to_string()),
                    suppressed: false,
                })
                .await;
        }

        log(
            db,
            log_events,
            LogLevel::Info,
            format!(
                "probe host={} reachable={} latency_ms={}",
                host.name,
                reachable,
                latency
                    .map(|m| format!("{m:.1}"))
                    .unwrap_or_else(|| "-".into())
            ),
        )
        .await;
    }

    evaluate_rules(db, &hosts, &rules, &maintenance, &is_open).await;
}

/// Evaluate each enabled rule against the latest recorded value of its metric on
/// each target host, raising an alert on a threshold breach.
async fn evaluate_rules(
    db: &Db,
    hosts: &[MonitoredHost],
    rules: &[MonitorRule],
    maintenance: &HashSet<String>,
    is_open: &impl Fn(&str, &str) -> bool,
) {
    for rule in rules.iter().filter(|r| r.enabled) {
        let targets = hosts
            .iter()
            .filter(|h| rule.target_host.as_deref().is_none_or(|t| t == h.name));
        for host in targets {
            let Some(value) = latest_metric(db, &host.name, &rule.metric).await else {
                continue;
            };
            let Some(severity) = breach(rule, value) else {
                continue;
            };
            if maintenance.contains(&host.name) || is_open(&host.name, &rule.id) {
                continue;
            }
            let _ = db
                .raise_alert(NewAlert {
                    domain: DomainKey::Watch,
                    severity,
                    summary: format!(
                        "{}: {} = {:.1} が閾値を超過しました（{}）。",
                        rule.name, rule.metric, value, host.name
                    ),
                    source_ref: Some(host.name.clone()),
                    rule_ref: Some(rule.id.clone()),
                    suppressed: false,
                })
                .await;
        }
    }
}

/// The most recent recorded value of `metric` for `host` (metrics are stored
/// oldest-first, so the last matching sample is newest).
async fn latest_metric(db: &Db, host: &str, metric: &str) -> Option<f64> {
    let metrics = db.list_host_metrics(host).await.ok()?;
    metrics
        .iter()
        .rfind(|m| m.name.eq_ignore_ascii_case(metric))
        .map(|m| m.value)
}

/// Higher-is-worse threshold check: `Critical` at/above the critical threshold,
/// else `Warning` at/above the warning threshold, else no breach.
fn breach(rule: &MonitorRule, value: f64) -> Option<Severity> {
    if let Some(c) = rule.critical_threshold {
        if value >= c {
            return Some(Severity::Critical);
        }
    }
    if let Some(w) = rule.warning_threshold {
        if value >= w {
            return Some(Severity::Warning);
        }
    }
    None
}

async fn log(db: &Db, enabled: bool, level: LogLevel, message: String) {
    if !enabled {
        return;
    }
    let _ = db
        .append_log(NewLogEntry {
            domain: DomainKey::Watch,
            log_kind: LogKind::Query,
            level,
            message,
            at: Utc::now(),
            meta: None,
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetite_core::models::alert::Alert;
    use tokio::net::TcpListener;

    fn rule(name: &str, metric: &str, warn: f64, crit: f64, target: Option<&str>) -> MonitorRule {
        MonitorRule {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            name: name.into(),
            target_host: target.map(String::from),
            metric: metric.into(),
            warning_threshold: Some(warn),
            critical_threshold: Some(crit),
            severity: Severity::Warning,
            eval_interval_secs: 60,
            enabled: true,
        }
    }

    fn host(name: &str, ip: &str) -> MonitoredHost {
        MonitoredHost {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            name: name.into(),
            ip_address: ip.into(),
            hostname: None,
            description: None,
            host_type: "server".into(),
            status: "unknown".into(),
            os_type: None,
            agent_version: None,
            snmp_enabled: false,
            last_seen: None,
            tags: vec![],
        }
    }

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    async fn free_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    }

    async fn open_watch_alerts(db: &Db) -> Vec<Alert> {
        db.list_alerts(Some("open"), None, Some("watch"))
            .await
            .unwrap()
    }

    #[test]
    fn breach_prefers_critical_then_warning() {
        let r = rule("cpu", "cpu_percent", 80.0, 90.0, None);
        assert!(matches!(breach(&r, 95.0), Some(Severity::Critical)));
        assert!(matches!(breach(&r, 85.0), Some(Severity::Warning)));
        assert!(breach(&r, 50.0).is_none());
    }

    #[tokio::test]
    async fn reachable_host_is_online_without_alert() {
        let (db, _dir) = test_db().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        db.save_watch_host(&host("web", "127.0.0.1")).await.unwrap();

        collect_once(&db, port, false).await;

        let reachable = db
            .list_host_metrics("web")
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.name == "reachable")
            .unwrap();
        assert_eq!(reachable.value, 1.0);
        assert_eq!(db.list_watch_hosts().await.unwrap()[0].status, "online");
        assert!(open_watch_alerts(&db).await.is_empty());
        drop(listener);
    }

    #[tokio::test]
    async fn unreachable_host_alerts_once() {
        let (db, _dir) = test_db().await;
        let dead = free_port().await; // nothing is listening here
        db.save_watch_host(&host("db1", "127.0.0.1")).await.unwrap();

        collect_once(&db, dead, false).await;
        assert_eq!(db.list_watch_hosts().await.unwrap()[0].status, "offline");
        let reachable = db
            .list_host_metrics("db1")
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.name == "reachable")
            .unwrap();
        assert_eq!(reachable.value, 0.0);
        let alerts = open_watch_alerts(&db).await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].source_ref.as_deref(), Some("db1"));

        // A second pass while still down must not duplicate the alert.
        collect_once(&db, dead, false).await;
        assert_eq!(open_watch_alerts(&db).await.len(), 1);
    }

    #[tokio::test]
    async fn rule_breach_raises_alert() {
        let (db, _dir) = test_db().await;
        let port = free_port().await;
        db.save_watch_host(&host("app", "127.0.0.1")).await.unwrap();
        // A high CPU sample arrives out-of-band; the rule should fire.
        db.record_metric("app", "cpu_percent", 95.0).await.unwrap();
        db.save_watch_rule(&rule("cpu high", "cpu_percent", 80.0, 90.0, Some("app")))
            .await
            .unwrap();

        collect_once(&db, port, false).await;

        let alerts = open_watch_alerts(&db).await;
        let cpu = alerts
            .iter()
            .find(|a| {
                a.rule_ref
                    .as_deref()
                    .is_some_and(|r| r != REACHABILITY_RULE)
            })
            .expect("cpu rule alert raised");
        assert!(matches!(cpu.severity, Severity::Critical));
        assert_eq!(cpu.source_ref.as_deref(), Some("app"));
    }
}
