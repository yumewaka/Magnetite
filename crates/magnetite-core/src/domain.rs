//! Domain identity shared across every subsystem.
//!
//! In the integrated redesign each former standalone service becomes an
//! internal domain module. `DomainKey` is the single enum used by audit
//! entries, alerts, templates, backups, notification targets and status —
//! everything that needs to say *which* domain it belongs to (07 §2).

use serde::{Deserialize, Serialize};

/// The eight managed infrastructure domains, plus the cross-cutting `Portal`
/// scope used by audit/authz for platform-wide operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainKey {
    Dns,
    Dhcp,
    Ldap,
    Mail,
    Proxy,
    K8s,
    Sso,
    Watch,
    /// Active Directory domain controller (KDC + SMB/SYSVOL + RPC: SAMR/LSA/
    /// DRSUAPI). A served protocol domain, but not one of the eight control-plane
    /// UI domains, so it is deliberately excluded from [`DomainKey::DOMAINS`].
    Addc,
    /// Cross-cutting platform scope (dashboard, audit, accounts, settings).
    Portal,
}

impl DomainKey {
    /// The eight manageable domains, in the canonical presentation order used
    /// by the sidebar and dashboard (F-11..F-18).
    pub const DOMAINS: [DomainKey; 8] = [
        DomainKey::Dns,
        DomainKey::Dhcp,
        DomainKey::Ldap,
        DomainKey::Mail,
        DomainKey::Proxy,
        DomainKey::K8s,
        DomainKey::Sso,
        DomainKey::Watch,
    ];

    /// Stable lowercase identifier used in config keys, routes and storage.
    pub fn as_str(self) -> &'static str {
        match self {
            DomainKey::Dns => "dns",
            DomainKey::Dhcp => "dhcp",
            DomainKey::Ldap => "ldap",
            DomainKey::Mail => "mail",
            DomainKey::Proxy => "proxy",
            DomainKey::K8s => "k8s",
            DomainKey::Sso => "sso",
            DomainKey::Watch => "watch",
            DomainKey::Addc => "addc",
            DomainKey::Portal => "portal",
        }
    }

    /// Parse a [`DomainKey`] from its stable identifier.
    pub fn from_str(value: &str) -> Option<Self> {
        let key = match value {
            "dns" => DomainKey::Dns,
            "dhcp" => DomainKey::Dhcp,
            "ldap" => DomainKey::Ldap,
            "mail" => DomainKey::Mail,
            "proxy" => DomainKey::Proxy,
            "k8s" => DomainKey::K8s,
            "sso" => DomainKey::Sso,
            "watch" => DomainKey::Watch,
            "addc" => DomainKey::Addc,
            "portal" => DomainKey::Portal,
            _ => return None,
        };
        Some(key)
    }

    /// i18n key for the human-facing domain label.
    pub fn label_key(self) -> &'static str {
        match self {
            DomainKey::Dns => "domain.dns",
            DomainKey::Dhcp => "domain.dhcp",
            DomainKey::Ldap => "domain.ldap",
            DomainKey::Mail => "domain.mail",
            DomainKey::Proxy => "domain.proxy",
            DomainKey::K8s => "domain.k8s",
            DomainKey::Sso => "domain.sso",
            DomainKey::Watch => "domain.watch",
            DomainKey::Addc => "domain.addc",
            DomainKey::Portal => "domain.portal",
        }
    }
}

impl std::fmt::Display for DomainKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_str() {
        for domain in DomainKey::DOMAINS {
            assert_eq!(DomainKey::from_str(domain.as_str()), Some(domain));
        }
        assert_eq!(DomainKey::from_str("portal"), Some(DomainKey::Portal));
        // Addc is served but excluded from DOMAINS; it must still round-trip.
        assert_eq!(
            DomainKey::from_str(DomainKey::Addc.as_str()),
            Some(DomainKey::Addc)
        );
        assert_eq!(DomainKey::from_str("nope"), None);
    }

    #[test]
    fn domains_excludes_portal() {
        assert!(!DomainKey::DOMAINS.contains(&DomainKey::Portal));
        assert_eq!(DomainKey::DOMAINS.len(), 8);
    }
}
