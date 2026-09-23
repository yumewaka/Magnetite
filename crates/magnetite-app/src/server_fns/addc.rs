//! AD DC control-plane server functions (read-only). Surfaces the embedded
//! domain controller's serving status, endpoints, service principals, groups and
//! the AD principals sourced from the shared database.
//!
//! Only non-secret fields are projected to the browser — the NT hash and Kerberos
//! long-term key held in `ad_principal` never leave the server.

use leptos::prelude::*;

/// A single AD principal, safe to send to the browser (no key material).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AdPrincipalRow {
    pub sam_account_name: String,
    pub rid: u32,
}

/// A well-known domain group.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AdGroupRow {
    pub name: String,
    pub rid: u32,
}

/// The embedded AD DC's serving status, endpoints and a summary of what it serves.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AddcStatus {
    /// "healthy" | "warning" | "error" | "unknown" | "disabled".
    pub health: String,
    /// Whether a DC server is registered (configured and started) at all.
    pub serving: bool,
    /// The Kerberos realm the DC is configured for.
    pub realm: String,
    /// Number of AD principals in the directory.
    pub principals: usize,
    /// DRS replication high-water mark (the max object USN a peer replicates up to
    /// — one USN per principal in this tracer-bullet).
    pub high_water_usn: u64,
    /// Configured listen endpoints (host:port).
    pub kdc: String,
    pub smb: String,
    pub rpc: String,
    pub drs: String,
    /// The service principal names (SPNs) the KDC issues tickets for.
    pub spns: Vec<String>,
}

/// List the AD principals from the shared directory (RID-ascending), projecting
/// only the non-secret fields.
#[server(ListAdPrincipals, "/api")]
pub async fn list_ad_principals() -> Result<Vec<AdPrincipalRow>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let mut principals = state
        .db
        .list_ad_principals()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .into_iter()
        .map(|p| AdPrincipalRow {
            sam_account_name: p.sam_account_name,
            rid: p.rid,
        })
        .collect::<Vec<_>>();
    principals.sort_by_key(|p| p.rid);
    Ok(principals)
}

/// List the well-known domain groups the directory serves.
#[server(ListAdGroups, "/api")]
pub async fn list_ad_groups() -> Result<Vec<AdGroupRow>, ServerFnError> {
    use crate::server_fns::auth::require;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    Ok(magnetite_addc::WELL_KNOWN_GROUPS
        .iter()
        .map(|(name, rid)| AdGroupRow {
            name: (*name).to_string(),
            rid: *rid,
        })
        .collect())
}

/// Report the embedded AD DC's serving status, endpoints and a summary.
#[server(GetAddcStatus, "/api")]
pub async fn get_addc_status() -> Result<AddcStatus, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domain::DomainKey;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();

    let addc_cfg = state
        .config
        .domains
        .get(&DomainKey::Addc)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.addc.clone())
        .unwrap_or_default();
    let realm = addc_cfg
        .realm
        .clone()
        .unwrap_or_else(|| magnetite_addc::DEFAULT_REALM.to_string());
    let addrs = magnetite_addc::AddcAddrs::from_config(&addc_cfg);

    let principals = state
        .db
        .list_ad_principals()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .len();

    Ok(AddcStatus {
        health: state.services.health(DomainKey::Addc).as_str().to_string(),
        serving: state.services.is_serving(DomainKey::Addc),
        realm: realm.clone(),
        principals,
        high_water_usn: principals as u64,
        kdc: addrs.kdc.to_string(),
        smb: addrs.smb.to_string(),
        rpc: addrs.rpc.to_string(),
        drs: addrs.drs.to_string(),
        spns: magnetite_addc::service_principals(&realm),
    })
}

// --- Group Policy (GPO) management (F: AD DC Web operations) -------------------

pub use magnetite_core::domains::addc::model::{GpoRegKind, GpoSettingInput, GpoSummary};

/// The AD DC base DN, derived from the configured realm
/// (`EXAMPLE.COM` -> `dc=example,dc=com`).
#[cfg(feature = "ssr")]
fn addc_base_dn() -> String {
    use crate::state::AppState;
    use magnetite_core::domain::DomainKey;
    let state = expect_context::<AppState>();
    let realm = state
        .config
        .domains
        .get(&DomainKey::Addc)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.addc.as_ref())
        .and_then(|a| a.realm.clone())
        .unwrap_or_else(|| magnetite_addc::DEFAULT_REALM.to_string());
    realm
        .split('.')
        .map(|label| format!("dc={}", label.to_lowercase()))
        .collect::<Vec<_>>()
        .join(",")
}

/// This DC's NetBIOS name — the realm's first label, upper-cased (the default the
/// AD DC uses when seeding its own `server`/`nTDSDSA` objects).
#[cfg(feature = "ssr")]
fn addc_netbios() -> String {
    use crate::state::AppState;
    use magnetite_core::domain::DomainKey;
    let state = expect_context::<AppState>();
    let realm = state
        .config
        .domains
        .get(&DomainKey::Addc)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.addc.as_ref())
        .and_then(|a| a.realm.clone())
        .unwrap_or_else(|| magnetite_addc::DEFAULT_REALM.to_string());
    realm
        .split('.')
        .next()
        .unwrap_or("MAGNETITE")
        .to_uppercase()
}

/// Record an audited AD DC control-plane action on `target_kind`/`target_id`.
#[cfg(feature = "ssr")]
async fn audit_addc(
    user: &magnetite_core::models::CurrentUser,
    action: magnetite_core::models::common::ActionKind,
    target_kind: &str,
    target_id: &str,
) {
    use crate::server_fns::auth::client_ip;
    use crate::state::AppState;
    let state = expect_context::<AppState>();
    let _ = state
        .db
        .append_audit(magnetite_core::models::NewAuditEntry {
            actor: user.subject.clone(),
            actor_role: user.role,
            domain: magnetite_core::domain::DomainKey::Addc,
            action,
            target_kind: target_kind.to_string(),
            target_id: target_id.to_string(),
            result: magnetite_core::models::common::OpResult::Success,
            detail: None,
            ip: client_ip().await,
        })
        .await;
}

/// List the domain's Group Policy Objects (GPCs), display-name ordered.
#[server(ListGpos, "/api")]
pub async fn list_gpos() -> Result<Vec<GpoSummary>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_gpos(&addc_base_dn())
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a Group Policy Object with `display_name` + machine registry `settings`,
/// provisioning its GPC (LDAP) and GPT (SYSVOL) halves. Returns the new GPO.
#[server(CreateGpo, "/api")]
pub async fn create_gpo(
    display_name: String,
    settings: Vec<GpoSettingInput>,
) -> Result<GpoSummary, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let display_name = display_name.trim().to_string();
    if display_name.is_empty() {
        return Err(ServerFnError::new("GPO 名を入力してください。"));
    }
    let state = expect_context::<AppState>();
    let gpo = state
        .db
        .create_gpo(&addc_base_dn(), &display_name, &settings)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_addc(&user, ActionKind::Create, "gpo", &gpo.guid).await;
    Ok(gpo)
}

/// Delete a Group Policy Object by GUID (removes its GPC + GPT files).
#[server(DeleteGpo, "/api")]
pub async fn delete_gpo(guid: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_gpo(&addc_base_dn(), &guid)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_addc(&user, ActionKind::Delete, "gpo", &guid).await;
    Ok(())
}

// --- Logon scripts (NETLOGON share) -------------------------------------------

pub use magnetite_core::domains::addc::model::LogonScript;

/// List the domain's logon scripts (served over NETLOGON).
#[server(ListLogonScripts, "/api")]
pub async fn list_logon_scripts() -> Result<Vec<LogonScript>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_logon_scripts(&addc_base_dn())
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create or replace a logon script (`name` + text `content`), stored in the
/// replicated SYSVOL store and served over NETLOGON.
#[server(CreateLogonScript, "/api")]
pub async fn create_logon_script(name: String, content: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err(ServerFnError::new("スクリプト名を入力してください。"));
    }
    let state = expect_context::<AppState>();
    state
        .db
        .create_logon_script(&addc_base_dn(), &name, content.into_bytes())
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_addc(&user, ActionKind::Create, "logon-script", &name).await;
    Ok(())
}

/// Delete a logon script by name.
#[server(DeleteLogonScript, "/api")]
pub async fn delete_logon_script(name: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_logon_script(&addc_base_dn(), &name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_addc(&user, ActionKind::Delete, "logon-script", &name).await;
    Ok(())
}

// --- Domain join / leave (promote this host as a replica DC, or demote it) ------

/// A request to promote this host into an existing AD domain as a replica DC. The
/// admin credentials and endpoints target the **source** DC; nothing here is stored.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct DomainJoinRequest {
    /// Source DC LDAP endpoint, `host:port` (e.g. `dc1.example.com:636`).
    pub source_host: String,
    /// Admin bind DN or UPN (e.g. `Administrator@EXAMPLE.COM`).
    pub bind_dn: String,
    /// Admin bind password.
    pub bind_password: String,
    /// TLS mode for the LDAP bind: `"ldaps"`, `"starttls"` or `"plaintext"`.
    pub tls_mode: String,
    /// This host's short DC name (its server / computer CN, e.g. `MAGNETITE`).
    pub dc_name: String,
    /// The Kerberos realm (e.g. `EXAMPLE.COM`).
    pub realm: String,
    /// Source DC KDC endpoint, `host:port` (e.g. `dc1.example.com:88`).
    pub kdc: String,
    /// Source DC DRSUAPI endpoint, `host:port`.
    pub drs: String,
    /// Admin principal for the Kerberos-sealed DRS bind (short name, no realm).
    pub admin_user: String,
    /// Admin principal password (to derive the AS key).
    pub admin_pass: String,
    /// Source DC service principal, `service/host` (e.g. `ldap/dc1.example.com`).
    pub source_spn: String,
    /// This host's IPv4 address (its host A record).
    pub ip: String,
    /// Skip writing DC-locator DNS (host A, `_msdcs` CNAME, SRV) to the domain.
    pub skip_dns: bool,
    /// Also request a RID allocation pool for the new DC.
    pub request_rid_pool: bool,
}

/// What a domain join created / moved, projected for the browser.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DomainJoinResult {
    pub computer_dn: String,
    pub server_dn: String,
    pub ntds_dn: String,
    pub ntds_guid: String,
    pub connection_dn: String,
    pub dns_nodes: Vec<String>,
    pub rid_pool: Option<String>,
}

/// A request to demote (remove) a DC from the domain, talking LDAP to a surviving DC.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct DomainLeaveRequest {
    /// A **surviving** DC's LDAP endpoint, `host:port`.
    pub source_host: String,
    /// Admin bind DN or UPN.
    pub bind_dn: String,
    /// Admin bind password.
    pub bind_password: String,
    /// TLS mode for the LDAP bind: `"ldaps"`, `"starttls"` or `"plaintext"`.
    pub tls_mode: String,
    /// The leaving DC's short name (its server / computer CN).
    pub dc_name: String,
    /// Skip removing the DC-specific locator DNS (host A + `_msdcs` CNAME).
    pub skip_dns: bool,
}

/// What a domain leave removed, projected for the browser.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DomainLeaveResult {
    /// DNs successfully deleted, in order.
    pub removed: Vec<String>,
    /// `(dn, reason)` for each object that could not be deleted.
    pub errors: Vec<(String, String)>,
}

/// Build a [`JoinTarget`] from the request's endpoint, credentials and TLS mode.
#[cfg(feature = "ssr")]
fn join_target(
    host_port: String,
    bind_dn: String,
    bind_password: String,
    tls_mode: &str,
) -> magnetite_ldap::dc_join::JoinTarget {
    use magnetite_ldap::dc_join::JoinTarget;
    match tls_mode {
        "ldaps" => JoinTarget {
            use_ldaps: true,
            ..JoinTarget::plaintext(host_port, bind_dn, bind_password)
        },
        "starttls" => JoinTarget::starttls(host_port, bind_dn, bind_password, None),
        _ => JoinTarget::plaintext(host_port, bind_dn, bind_password),
    }
}

/// Canonical `xxxxxxxx-…` string for a 16-byte `objectGUID` in DRS wire form.
#[cfg(feature = "ssr")]
fn guid_to_string(g: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}",
        g[3],
        g[2],
        g[1],
        g[0],
        g[5],
        g[4],
        g[7],
        g[6],
        g[8],
        g[9],
        g[10..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

/// Drive a **non-`Send`** future to completion on a dedicated OS thread running its own
/// current-thread runtime, awaiting only the (`Send`) result back over a channel.
///
/// The join / leave orchestration pulls in Kerberos, whose futures hold a
/// `Box<dyn Cipher>` across `await` and so are not `Send` — but a server function's
/// future must be `Send`. This isolates the non-`Send` work off the request task; only
/// the `Send` `Result<T, String>` crosses back.
#[cfg(feature = "ssr")]
async fn run_isolated<T, F, Fut>(f: F) -> Result<T, ServerFnError>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, String>>,
    T: Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = tx.send(Err(format!("ランタイムの初期化に失敗しました: {e}")));
                return;
            }
        };
        let _ = tx.send(rt.block_on(f()));
    });
    rx.await
        .map_err(|_| ServerFnError::new("バックグラウンド処理が異常終了しました。"))?
        .map_err(ServerFnError::new)
}

/// Promote this host into an existing AD domain as a replica DC (runs the full
/// [`magnetite_addc::promote`] orchestration). Admin-only; audited. Long-running.
#[server(JoinDomain, "/api")]
pub async fn join_domain(req: DomainJoinRequest) -> Result<DomainJoinResult, ServerFnError> {
    use crate::server_fns::auth::require;
    use magnetite_addc::promote::{promote, PromoteParams};
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;
    use std::net::{Ipv4Addr, SocketAddr};

    let user = require(ActionClass::Admin).await?;
    let dc_name = req.dc_name.trim().to_string();
    if dc_name.is_empty() {
        return Err(ServerFnError::new("DC 名を入力してください。"));
    }
    let ip: Ipv4Addr = req
        .ip
        .trim()
        .parse()
        .map_err(|_| ServerFnError::new(format!("IP アドレスが不正です: {:?}", req.ip)))?;
    let kdc: SocketAddr =
        req.kdc.trim().parse().map_err(|_| {
            ServerFnError::new(format!("KDC エンドポイントが不正です: {:?}", req.kdc))
        })?;
    let drs: SocketAddr =
        req.drs.trim().parse().map_err(|_| {
            ServerFnError::new(format!("DRS エンドポイントが不正です: {:?}", req.drs))
        })?;

    let params = PromoteParams {
        target: join_target(
            req.source_host.trim().to_string(),
            req.bind_dn.trim().to_string(),
            req.bind_password,
            &req.tls_mode,
        ),
        dc_name: dc_name.clone(),
        realm: req.realm.trim().to_string(),
        kdc,
        drs,
        admin_user: req.admin_user.trim().to_string(),
        admin_pass: req.admin_pass,
        source_spn: req.source_spn.trim().to_string(),
        ip,
        roles: Vec::new(),
        request_rid_pool: req.request_rid_pool,
        skip_dns: req.skip_dns,
        invocation_id: None,
    };
    // `promote` pulls in non-`Send` Kerberos futures — run it off the request task.
    let result = run_isolated(move || async move {
        let outcome = promote(&params)
            .await
            .map_err(|e| format!("参加に失敗しました: {e:#}"))?;
        Ok(DomainJoinResult {
            computer_dn: outcome.computer_dn,
            server_dn: outcome.server_dn,
            ntds_dn: outcome.ntds_dn,
            ntds_guid: guid_to_string(&outcome.ntds_guid),
            connection_dn: outcome.connection_dn,
            dns_nodes: outcome.dns_nodes,
            rid_pool: outcome.rid_pool.map(|e| format!("{e:?}")),
        })
    })
    .await?;
    audit_addc(&user, ActionKind::Control, "domain-join", &dc_name).await;
    Ok(result)
}

/// Demote (remove) a DC from the domain — the reverse of a join. Admin-only; audited.
#[server(LeaveDomain, "/api")]
pub async fn leave_domain(req: DomainLeaveRequest) -> Result<DomainLeaveResult, ServerFnError> {
    use crate::server_fns::auth::require;
    use magnetite_addc::demote::{demote, DemoteParams};
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Admin).await?;
    let dc_name = req.dc_name.trim().to_string();
    if dc_name.is_empty() {
        return Err(ServerFnError::new("DC 名を入力してください。"));
    }
    let params = DemoteParams {
        target: join_target(
            req.source_host.trim().to_string(),
            req.bind_dn.trim().to_string(),
            req.bind_password,
            &req.tls_mode,
        ),
        dc_name: dc_name.clone(),
        skip_dns: req.skip_dns,
    };
    // Isolate off the request task (uniform with join; keeps the fn future `Send`).
    let result = run_isolated(move || async move {
        let outcome = demote(&params)
            .await
            .map_err(|e| format!("離脱に失敗しました: {e:#}"))?;
        Ok(DomainLeaveResult {
            removed: outcome.removed,
            errors: outcome.errors,
        })
    })
    .await?;
    audit_addc(&user, ActionKind::Control, "domain-leave", &dc_name).await;
    Ok(result)
}

// --- FSMO (operations-master) roles -------------------------------------------

pub use magnetite_core::domains::addc::model::FsmoRoleInfo;

/// A stable role key -> (display label, `become<X>Master` seize trigger attribute).
#[cfg(feature = "ssr")]
fn fsmo_role_meta(role: &str) -> Option<(&'static str, &'static str)> {
    match role {
        "schema" => Some(("スキーマ マスター", "becomeschemamaster")),
        "domain_naming" => Some(("ドメイン名前付けマスター", "becomedomainmaster")),
        "rid" => Some(("RID マスター", "becomeridmaster")),
        "infrastructure" => Some((
            "インフラストラクチャ マスター",
            "becomeinfrastructuremaster",
        )),
        "pdc" => Some(("PDC エミュレーター", "becomepdc")),
        _ => None,
    }
}

/// List the five FSMO roles and their current holders (from `fSMORoleOwner`).
#[server(ListFsmoRoles, "/api")]
pub async fn list_fsmo_roles() -> Result<Vec<FsmoRoleInfo>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let base = addc_base_dn();
    let netbios = addc_netbios();
    // The local DC's nTDSDSA DN (normalized, lower-cased) to flag locally-held roles.
    let local_owner = format!(
        "cn=ntds settings,cn={},cn=servers,cn=default-first-site-name,cn=sites,cn=configuration,{}",
        netbios.to_lowercase(),
        base
    );
    let owners = state
        .db
        .fsmo_owners(&base)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(owners
        .into_iter()
        .map(|(role, _dn, owner)| {
            let label = fsmo_role_meta(role).map(|m| m.0).unwrap_or(role);
            let held_locally = owner
                .as_deref()
                .map(|o| o.eq_ignore_ascii_case(&local_owner))
                .unwrap_or(false);
            FsmoRoleInfo {
                role: role.to_string(),
                label: label.to_string(),
                owner,
                held_locally,
            }
        })
        .collect())
}

/// Seize a FSMO role to this magnetite DC (rewrites `fSMORoleOwner`). Admin-only;
/// audited. This is the `samba-tool fsmo seize` / `ntdsutil` equivalent — use it when
/// the current holder is permanently gone.
#[server(SeizeFsmoRole, "/api")]
pub async fn seize_fsmo_role(role: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Admin).await?;
    let Some((_, attr)) = fsmo_role_meta(&role) else {
        return Err(ServerFnError::new("不明な FSMO ロールです。"));
    };
    let state = expect_context::<AppState>();
    state
        .db
        .seize_fsmo_role(&addc_base_dn(), &addc_netbios(), attr)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("ロールの奪取に失敗しました。"))?;
    audit_addc(&user, ActionKind::Control, "fsmo-seize", &role).await;
    Ok(())
}
