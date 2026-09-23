//! The automatic-failover decision logic (P3), kept as a pure function so it can be
//! reasoned about and unit-tested without any I/O.
//!
//! The center is the single arbiter. Per cluster the operator designates one server's
//! `intent` as `primary` and one or more as `standby`, and arms `auto_failover` with a
//! `failure_threshold` N. Each poll updates a per-server consecutive-failure counter; this
//! evaluator turns a cluster snapshot into the actions to take:
//!
//! - **auto-promote**: when the active primary has missed ≥ N consecutive polls, promote a
//!   healthy standby and record it as the new active primary.
//! - **fence-on-return**: a former primary that was failed away from is marked *fenced*;
//!   when it comes back it is demoted to a secondary rather than allowed to act as a second
//!   primary (the practical stand-in for STONITH when we have no power control).
//! - **split-brain guard**: any reachable server acting as primary that is not the recorded
//!   active primary is demoted, so a cluster never keeps two primaries.
//!
//! Failback is intentionally *not* automatic (it would risk flapping): after a failover the
//! standby stays primary until an operator moves it back.

use serde::{Deserialize, Serialize};

/// A server's designated baseline role within its cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RoleIntent {
    /// The designated primary for the cluster.
    Primary,
    /// A promotion candidate held in reserve.
    Standby,
    /// No role in automatic failover (never auto-promoted or demoted).
    #[default]
    Unset,
}

impl RoleIntent {
    pub fn as_str(self) -> &'static str {
        match self {
            RoleIntent::Primary => "primary",
            RoleIntent::Standby => "standby",
            RoleIntent::Unset => "unset",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "primary" => Some(RoleIntent::Primary),
            "standby" => Some(RoleIntent::Standby),
            "" | "unset" | "none" => Some(RoleIntent::Unset),
            _ => None,
        }
    }
}

/// One control action the poller should carry out against a server's `/mgmt/*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Promote(String),
    Demote(String),
}

/// A server as the evaluator sees it (already-polled state).
#[derive(Debug, Clone)]
pub struct ServerView {
    pub sid: String,
    pub intent: RoleIntent,
    /// Reachable at the last poll.
    pub healthy: bool,
    /// Consecutive failed polls (0 when healthy).
    pub consecutive_failures: u32,
    /// Marked fenced after being failed away from.
    pub fenced: bool,
    /// Live role: this node currently acts as a primary for ≥1 managed domain.
    pub acts_primary: bool,
}

/// A cluster snapshot handed to [`evaluate`].
#[derive(Debug, Clone)]
pub struct ClusterView {
    pub auto_failover: bool,
    pub failure_threshold: u32,
    /// The sid the center currently regards as the active primary (if any).
    pub active_primary: Option<String>,
    pub servers: Vec<ServerView>,
}

/// The outcome of evaluating one cluster: the control actions to issue, the new active
/// primary to persist (if it changed), fencing bookkeeping, and human-readable log lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decision {
    pub actions: Vec<Action>,
    /// `Some(sid)` when the active primary should be updated; `None` leaves it unchanged.
    pub new_active_primary: Option<String>,
    pub fence: Vec<String>,
    pub unfence: Vec<String>,
    pub log: Vec<String>,
}

impl Decision {
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
            && self.new_active_primary.is_none()
            && self.fence.is_empty()
            && self.unfence.is_empty()
    }
}

fn find<'a>(servers: &'a [ServerView], sid: &str) -> Option<&'a ServerView> {
    servers.iter().find(|s| s.sid == sid)
}

/// Decide what to do for one cluster. Pure: no I/O, deterministic given its input.
pub fn evaluate(view: &ClusterView) -> Decision {
    let mut d = Decision::default();
    if !view.auto_failover {
        return d;
    }
    let threshold = view.failure_threshold.max(1);

    // Resolve the effective active primary: the recorded one, or (bootstrap) the healthy
    // designated primary when nothing is recorded yet.
    let mut active: Option<String> = view.active_primary.clone();
    if active.is_none() {
        if let Some(p) = view
            .servers
            .iter()
            .find(|s| s.intent == RoleIntent::Primary && s.healthy)
        {
            active = Some(p.sid.clone());
            d.new_active_primary = Some(p.sid.clone());
        }
    }

    // --- Auto-promote: the active primary has been down for ≥ threshold polls. ---
    let active_down = active
        .as_deref()
        .and_then(|sid| find(&view.servers, sid))
        .map(|s| !s.healthy && s.consecutive_failures >= threshold)
        .unwrap_or(false);

    if active_down {
        // Pick a deterministic healthy, unfenced standby.
        let mut candidates: Vec<&ServerView> = view
            .servers
            .iter()
            .filter(|s| s.intent == RoleIntent::Standby && s.healthy && !s.fenced)
            .collect();
        candidates.sort_by(|a, b| a.sid.cmp(&b.sid));
        if let Some(standby) = candidates.first() {
            let old = active.clone().unwrap_or_default();
            d.actions.push(Action::Promote(standby.sid.clone()));
            d.new_active_primary = Some(standby.sid.clone());
            if !old.is_empty() {
                d.fence.push(old.clone());
            }
            d.log.push(format!(
                "auto-failover: primary {old} down ≥{threshold} polls → promoted standby {}",
                standby.sid
            ));
            active = Some(standby.sid.clone());
        } else {
            d.log.push(
                "auto-failover: active primary down but no healthy standby available".to_string(),
            );
        }
    }

    let active_sid = active.clone().unwrap_or_default();

    // --- Fence-on-return: a fenced server that is healthy again is demoted. ---
    for s in &view.servers {
        if s.fenced && s.healthy && s.sid != active_sid {
            if s.acts_primary {
                d.actions.push(Action::Demote(s.sid.clone()));
            }
            d.unfence.push(s.sid.clone());
            d.log.push(format!(
                "fencing: former primary {} recovered → demoted to secondary",
                s.sid
            ));
        }
    }

    // --- Split-brain guard: a reachable stray primary (not the active one, not fenced
    // — fenced ones are handled above) is demoted so the cluster keeps one primary. ---
    for s in &view.servers {
        if s.healthy && s.acts_primary && s.sid != active_sid && !s.fenced {
            let already = d
                .actions
                .iter()
                .any(|a| matches!(a, Action::Demote(x) if *x == s.sid));
            if !already {
                d.actions.push(Action::Demote(s.sid.clone()));
                d.log.push(format!(
                    "split-brain guard: {} acts as primary but is not the active primary → demoted",
                    s.sid
                ));
            }
        }
    }

    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srv(sid: &str, intent: RoleIntent, healthy: bool, fails: u32) -> ServerView {
        ServerView {
            sid: sid.to_string(),
            intent,
            healthy,
            consecutive_failures: fails,
            fenced: false,
            acts_primary: intent == RoleIntent::Primary && healthy,
        }
    }

    #[test]
    fn disabled_auto_failover_does_nothing() {
        let view = ClusterView {
            auto_failover: false,
            failure_threshold: 3,
            active_primary: Some("p".into()),
            servers: vec![srv("p", RoleIntent::Primary, false, 10)],
        };
        assert!(evaluate(&view).is_empty());
    }

    #[test]
    fn bootstraps_active_primary_from_healthy_designated_primary() {
        let view = ClusterView {
            auto_failover: true,
            failure_threshold: 3,
            active_primary: None,
            servers: vec![
                srv("p", RoleIntent::Primary, true, 0),
                srv("s", RoleIntent::Standby, true, 0),
            ],
        };
        let d = evaluate(&view);
        assert_eq!(d.new_active_primary.as_deref(), Some("p"));
        assert!(d.actions.is_empty());
    }

    #[test]
    fn promotes_standby_when_primary_down_past_threshold() {
        let mut primary = srv("p", RoleIntent::Primary, false, 3);
        primary.acts_primary = false; // it's down
        let view = ClusterView {
            auto_failover: true,
            failure_threshold: 3,
            active_primary: Some("p".into()),
            servers: vec![
                primary,
                srv("s1", RoleIntent::Standby, true, 0),
                srv("s2", RoleIntent::Standby, true, 0),
            ],
        };
        let d = evaluate(&view);
        assert_eq!(d.actions, vec![Action::Promote("s1".into())]); // deterministic pick
        assert_eq!(d.new_active_primary.as_deref(), Some("s1"));
        assert_eq!(d.fence, vec!["p".to_string()]);
    }

    #[test]
    fn does_not_promote_before_threshold() {
        let mut primary = srv("p", RoleIntent::Primary, false, 2);
        primary.acts_primary = false;
        let view = ClusterView {
            auto_failover: true,
            failure_threshold: 3,
            active_primary: Some("p".into()),
            servers: vec![primary, srv("s1", RoleIntent::Standby, true, 0)],
        };
        assert!(evaluate(&view).actions.is_empty());
    }

    #[test]
    fn no_standby_available_logs_but_takes_no_action() {
        let mut primary = srv("p", RoleIntent::Primary, false, 5);
        primary.acts_primary = false;
        let view = ClusterView {
            auto_failover: true,
            failure_threshold: 3,
            active_primary: Some("p".into()),
            servers: vec![primary, srv("s1", RoleIntent::Standby, false, 5)],
        };
        let d = evaluate(&view);
        assert!(d.actions.is_empty());
        assert!(!d.log.is_empty());
    }

    #[test]
    fn fenced_primary_returning_is_demoted() {
        // s1 is the active primary; p (old primary) returns still acting primary + fenced.
        let mut old = srv("p", RoleIntent::Primary, true, 0);
        old.fenced = true;
        old.acts_primary = true;
        let view = ClusterView {
            auto_failover: true,
            failure_threshold: 3,
            active_primary: Some("s1".into()),
            servers: vec![old, srv("s1", RoleIntent::Standby, true, 0)],
        };
        let d = evaluate(&view);
        assert!(d.actions.contains(&Action::Demote("p".into())));
        assert_eq!(d.unfence, vec!["p".to_string()]);
    }

    #[test]
    fn split_brain_stray_primary_is_demoted() {
        // s2 wrongly acts as primary while s1 is the active primary.
        let mut stray = srv("s2", RoleIntent::Standby, true, 0);
        stray.acts_primary = true;
        let view = ClusterView {
            auto_failover: true,
            failure_threshold: 3,
            active_primary: Some("s1".into()),
            servers: vec![srv("s1", RoleIntent::Standby, true, 0), stray],
        };
        let d = evaluate(&view);
        assert_eq!(d.actions, vec![Action::Demote("s2".into())]);
    }
}
