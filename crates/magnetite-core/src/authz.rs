//! Unified authorization engine (08_authz / F-02).
//!
//! The whole platform authorizes through a single, fixed RBAC model: a session
//! carries exactly one ordered [`Role`] (Viewer < Operator < Admin), every
//! operation is classified into an [`ActionClass`], and [`decide`] returns
//! Allow/Deny from the confirmed decision table. `default deny` is the rule —
//! anything without an explicit allow is denied, and unauthenticated callers
//! are rejected before we ever reach here (09 §6.5 handles session validity).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// RBAC role (07 §3.9). Ordered so a higher role subsumes lower ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Read-only across dashboards, lists and logs.
    #[default]
    Viewer,
    /// Everyday create/update/delete plus operational actions.
    Operator,
    /// Full control: destructive bulk ops, settings, accounts, backups, SSO.
    Admin,
}

impl Role {
    /// i18n key for the role label.
    pub fn label_key(self) -> &'static str {
        match self {
            Role::Viewer => "rbac.viewer",
            Role::Operator => "rbac.operator",
            Role::Admin => "rbac.admin",
        }
    }

    /// Stable identifier used in storage and claim mappings.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }

    /// Parse a role from its stable identifier (case-insensitive).
    pub fn from_str(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "viewer" => Some(Role::Viewer),
            "operator" => Some(Role::Operator),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Operation classification (08_authz §3). Each class maps to a minimum role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    /// Lists, detail, logs, audit, dashboard.
    Read,
    /// Ordinary create/update/delete, alert ack/resolve, lease release,
    /// template application.
    Write,
    /// Destructive bulk / cascade operations.
    Destroy,
    /// Service/domain control, settings changes, config reload.
    Control,
    /// Account & session management, backup/restore, SSO provider/client.
    Admin,
}

impl ActionClass {
    /// Minimum role required to perform an action of this class (08_authz §2.1).
    pub fn min_role(self) -> Role {
        match self {
            ActionClass::Read => Role::Viewer,
            ActionClass::Write => Role::Operator,
            ActionClass::Destroy | ActionClass::Control | ActionClass::Admin => Role::Admin,
        }
    }
}

/// Result of an authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    pub fn is_allowed(self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// Core decision: does `role` satisfy the minimum for `action`?
///
/// The decision table (08_authz §2.2) is exactly "role >= action.min_role".
/// Scope (domain vs portal) does not further restrict here — the RBAC model is
/// three fixed tiers; per-domain visibility is governed by domain enablement,
/// not by role (08_authz §5).
pub fn decide(role: Role, action: ActionClass) -> Decision {
    if role >= action.min_role() {
        Decision::Allow
    } else {
        Decision::Deny
    }
}

/// Convenience predicate mirroring [`decide`].
pub fn is_allowed(role: Role, action: ActionClass) -> bool {
    decide(role, action).is_allowed()
}

/// Resolve an effective [`Role`] from OIDC `groups`/`roles` claims via a
/// configured mapping (08_authz §4.2).
///
/// Each claim value is matched *exactly* (case-insensitively) against the
/// mapping keys — substring matching is deliberately avoided so unrelated names
/// (e.g. "non-admin") cannot escalate. When several claims map to roles, the
/// highest wins; when nothing matches, we fall back to the least-privilege
/// [`Role::Viewer`] (never escalate on missing claims).
pub fn role_from_claims(
    groups: Option<&[String]>,
    roles: Option<&[String]>,
    mapping: &HashMap<String, Role>,
) -> Role {
    let normalized: HashMap<String, Role> = mapping
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), *v))
        .collect();

    groups
        .into_iter()
        .flatten()
        .chain(roles.into_iter().flatten())
        .filter_map(|claim| normalized.get(&claim.to_ascii_lowercase()).copied())
        .max()
        .unwrap_or(Role::Viewer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_is_ordered() {
        assert!(Role::Admin > Role::Operator);
        assert!(Role::Operator > Role::Viewer);
        assert_eq!(Role::default(), Role::Viewer);
    }

    #[test]
    fn decision_table_matches_spec() {
        // Viewer
        assert!(is_allowed(Role::Viewer, ActionClass::Read));
        assert!(!is_allowed(Role::Viewer, ActionClass::Write));
        assert!(!is_allowed(Role::Viewer, ActionClass::Destroy));
        assert!(!is_allowed(Role::Viewer, ActionClass::Control));
        assert!(!is_allowed(Role::Viewer, ActionClass::Admin));
        // Operator
        assert!(is_allowed(Role::Operator, ActionClass::Read));
        assert!(is_allowed(Role::Operator, ActionClass::Write));
        assert!(!is_allowed(Role::Operator, ActionClass::Destroy));
        assert!(!is_allowed(Role::Operator, ActionClass::Control));
        assert!(!is_allowed(Role::Operator, ActionClass::Admin));
        // Admin
        for action in [
            ActionClass::Read,
            ActionClass::Write,
            ActionClass::Destroy,
            ActionClass::Control,
            ActionClass::Admin,
        ] {
            assert!(is_allowed(Role::Admin, action));
        }
    }

    fn default_mapping() -> HashMap<String, Role> {
        HashMap::from([
            ("magnetite-admins".to_string(), Role::Admin),
            ("magnetite-operators".to_string(), Role::Operator),
        ])
    }

    #[test]
    fn claims_pick_highest_role() {
        let groups = vec![
            "users".to_string(),
            "magnetite-operators".to_string(),
            "magnetite-admins".to_string(),
        ];
        let role = role_from_claims(Some(&groups), None, &default_mapping());
        assert_eq!(role, Role::Admin);
    }

    #[test]
    fn claims_default_to_viewer() {
        let groups = vec!["developers".to_string(), "non-admin".to_string()];
        let role = role_from_claims(Some(&groups), None, &default_mapping());
        assert_eq!(role, Role::Viewer);
        assert_eq!(
            role_from_claims(None, None, &default_mapping()),
            Role::Viewer
        );
    }

    #[test]
    fn claims_match_is_case_insensitive_and_exact() {
        let roles = vec!["MAGNETITE-ADMINS".to_string()];
        assert_eq!(
            role_from_claims(None, Some(&roles), &default_mapping()),
            Role::Admin
        );
        // Substring must not escalate.
        let sneaky = vec!["not-magnetite-admins-really".to_string()];
        assert_eq!(
            role_from_claims(Some(&sneaky), None, &default_mapping()),
            Role::Viewer
        );
    }
}
