//! `magnetite-app` — the Leptos application: shell, standard UI kit, pages and
//! the server-function boundary. Compiled both as the SSR library (linked into
//! `magnetite-server`) and as the WASM hydration bundle.

// The composed shell view (sidebar + header + outlet + toasts) nests deeply
// enough that computing the layout of its `resolve`/`hydrate_async` future
// exceeds rustc's default query-depth limit (128). Raise it for both the SSR
// and WASM builds of this crate.
#![recursion_limit = "256"]

pub mod components;
pub mod pages;
pub mod server_fns;
pub mod shell;
pub mod types;

#[cfg(feature = "ssr")]
pub mod state;

use leptos::prelude::*;
use leptos_meta::{provide_meta_context, MetaTags, Stylesheet, Title};
use leptos_router::components::{ParentRoute, Route, Router, Routes};
use leptos_router::path;
use magnetite_core::i18n::provide_i18n;

use pages::dashboard::DashboardPage;
use pages::login::LoginPage;
use pages::placeholder::PlaceholderPage;
use shell::layout::AuthenticatedShell;

/// WASM entry point invoked by the generated hydration script.
#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook_noop();
    leptos::mount::hydrate_body(App);
}

#[cfg(feature = "hydrate")]
fn console_error_panic_hook_noop() {
    // Placeholder hook slot; a real panic hook can be installed here later.
}

/// Explicit server-function registration (required on Windows MSVC where
/// `inventory` auto-registration does not run).
#[cfg(feature = "ssr")]
pub fn register_server_functions() {
    use server_fns::{auth, shell};
    server_fn::axum::register_explicit::<auth::GetCurrentUser>();
    server_fn::axum::register_explicit::<auth::NeedsSetup>();
    server_fn::axum::register_explicit::<auth::ListLoginProviders>();
    server_fn::axum::register_explicit::<auth::SetupFirstAdmin>();
    server_fn::axum::register_explicit::<auth::LocalLogin>();
    server_fn::axum::register_explicit::<auth::Logout>();
    server_fn::axum::register_explicit::<shell::GetShellInfo>();
    server_fn::axum::register_explicit::<shell::GetDashboardCards>();

    use server_fns::dns;
    server_fn::axum::register_explicit::<dns::GetDnsMetrics>();
    server_fn::axum::register_explicit::<dns::ListZones>();
    server_fn::axum::register_explicit::<dns::GetZone>();
    server_fn::axum::register_explicit::<dns::SaveZone>();
    server_fn::axum::register_explicit::<dns::CountZoneRecords>();
    server_fn::axum::register_explicit::<dns::DeleteZone>();
    server_fn::axum::register_explicit::<dns::ListRecords>();
    server_fn::axum::register_explicit::<dns::SaveRecord>();
    server_fn::axum::register_explicit::<dns::DeleteRecord>();
    server_fn::axum::register_explicit::<dns::ListRpz>();
    server_fn::axum::register_explicit::<dns::SaveRpz>();
    server_fn::axum::register_explicit::<dns::DeleteRpz>();
    server_fn::axum::register_explicit::<dns::DnsQueryTest>();
    server_fn::axum::register_explicit::<dns::SetZoneDnssec>();
    server_fn::axum::register_explicit::<dns::GetDnssecKeyInfo>();
    server_fn::axum::register_explicit::<dns::ListGeoRules>();
    server_fn::axum::register_explicit::<dns::CreateGeoRule>();
    server_fn::axum::register_explicit::<dns::ToggleGeoRule>();
    server_fn::axum::register_explicit::<dns::DeleteGeoRule>();
    server_fn::axum::register_explicit::<dns::SetZoneReplication>();
    server_fn::axum::register_explicit::<dns::ListTsigKeys>();
    server_fn::axum::register_explicit::<dns::CreateTsigKey>();
    server_fn::axum::register_explicit::<dns::DeleteTsigKey>();

    use server_fns::dhcp;
    server_fn::axum::register_explicit::<dhcp::GetDhcpMetrics>();
    server_fn::axum::register_explicit::<dhcp::ListPools>();
    server_fn::axum::register_explicit::<dhcp::GetPool>();
    server_fn::axum::register_explicit::<dhcp::SavePool>();
    server_fn::axum::register_explicit::<dhcp::CountPoolActiveLeases>();
    server_fn::axum::register_explicit::<dhcp::DeletePool>();
    server_fn::axum::register_explicit::<dhcp::ListReservations>();
    server_fn::axum::register_explicit::<dhcp::CreateReservation>();
    server_fn::axum::register_explicit::<dhcp::DeleteReservation>();
    server_fn::axum::register_explicit::<dhcp::ListLeases>();
    server_fn::axum::register_explicit::<dhcp::ReleaseLease>();
    server_fn::axum::register_explicit::<dhcp::GetDhcpConfig>();
    server_fn::axum::register_explicit::<dhcp::SaveDhcpConfig>();

    use server_fns::ldap;
    server_fn::axum::register_explicit::<ldap::GetLdapMetrics>();
    server_fn::axum::register_explicit::<ldap::GetTreeRoot>();
    server_fn::axum::register_explicit::<ldap::GetTreeChildren>();
    server_fn::axum::register_explicit::<ldap::GetEntry>();
    server_fn::axum::register_explicit::<ldap::ListParents>();
    server_fn::axum::register_explicit::<ldap::ListUsers>();
    server_fn::axum::register_explicit::<ldap::CreateUser>();
    server_fn::axum::register_explicit::<ldap::ToggleUser>();
    server_fn::axum::register_explicit::<ldap::ResetPassword>();
    server_fn::axum::register_explicit::<ldap::ListGroups>();
    server_fn::axum::register_explicit::<ldap::CreateGroup>();
    server_fn::axum::register_explicit::<ldap::AddMember>();
    server_fn::axum::register_explicit::<ldap::RemoveMember>();
    server_fn::axum::register_explicit::<ldap::ListOus>();
    server_fn::axum::register_explicit::<ldap::CreateOu>();
    server_fn::axum::register_explicit::<ldap::ListComputers>();
    server_fn::axum::register_explicit::<ldap::CreateComputer>();
    server_fn::axum::register_explicit::<ldap::MoveEntry>();
    server_fn::axum::register_explicit::<ldap::DeleteEntry>();
    server_fn::axum::register_explicit::<ldap::ListLdapAcls>();
    server_fn::axum::register_explicit::<ldap::CreateLdapAcl>();
    server_fn::axum::register_explicit::<ldap::ToggleLdapAcl>();
    server_fn::axum::register_explicit::<ldap::DeleteLdapAcl>();
    server_fn::axum::register_explicit::<ldap::GetLdapSyncStatus>();

    use server_fns::mail;
    server_fn::axum::register_explicit::<mail::GetMailMetrics>();
    server_fn::axum::register_explicit::<mail::ListMailDomains>();
    server_fn::axum::register_explicit::<mail::SaveMailDomain>();
    server_fn::axum::register_explicit::<mail::DeleteMailDomain>();
    server_fn::axum::register_explicit::<mail::ListMailUsers>();
    server_fn::axum::register_explicit::<mail::CreateMailUser>();
    server_fn::axum::register_explicit::<mail::ToggleMailUser>();
    server_fn::axum::register_explicit::<mail::ResetMailUserPassword>();
    server_fn::axum::register_explicit::<mail::DeleteMailUser>();
    server_fn::axum::register_explicit::<mail::ListAliases>();
    server_fn::axum::register_explicit::<mail::SaveAlias>();
    server_fn::axum::register_explicit::<mail::DeleteAlias>();
    server_fn::axum::register_explicit::<mail::ListMailingLists>();
    server_fn::axum::register_explicit::<mail::CreateMailingList>();
    server_fn::axum::register_explicit::<mail::DeleteMailingList>();
    server_fn::axum::register_explicit::<mail::AddListMember>();
    server_fn::axum::register_explicit::<mail::RemoveListMember>();
    server_fn::axum::register_explicit::<mail::GetMailConfig>();
    server_fn::axum::register_explicit::<mail::SaveMailConfig>();
    server_fn::axum::register_explicit::<mail::ListMailMessages>();
    server_fn::axum::register_explicit::<mail::GetMailMessage>();
    server_fn::axum::register_explicit::<mail::GetDkim>();
    server_fn::axum::register_explicit::<mail::GenerateDkim>();
    server_fn::axum::register_explicit::<mail::SetDkimEnabled>();
    server_fn::axum::register_explicit::<mail::ListBackupMx>();
    server_fn::axum::register_explicit::<mail::SaveBackupMx>();
    server_fn::axum::register_explicit::<mail::DeleteBackupMx>();
    server_fn::axum::register_explicit::<mail::ListBackupQueue>();
    server_fn::axum::register_explicit::<mail::DeleteBackupQueue>();
    server_fn::axum::register_explicit::<mail::GetMailReplStatus>();

    use server_fns::proxy;
    server_fn::axum::register_explicit::<proxy::GetProxyMetrics>();
    server_fn::axum::register_explicit::<proxy::ListVhosts>();
    server_fn::axum::register_explicit::<proxy::SaveVhost>();
    server_fn::axum::register_explicit::<proxy::ToggleVhost>();
    server_fn::axum::register_explicit::<proxy::DeleteVhost>();
    server_fn::axum::register_explicit::<proxy::ListCertificates>();
    server_fn::axum::register_explicit::<proxy::CreateCertificate>();
    server_fn::axum::register_explicit::<proxy::DeleteCertificate>();
    server_fn::axum::register_explicit::<proxy::ListAclRules>();
    server_fn::axum::register_explicit::<proxy::SaveAclRule>();
    server_fn::axum::register_explicit::<proxy::SetAclPriority>();
    server_fn::axum::register_explicit::<proxy::ToggleAcl>();
    server_fn::axum::register_explicit::<proxy::DeleteAclRule>();
    server_fn::axum::register_explicit::<proxy::ListIpBlocks>();
    server_fn::axum::register_explicit::<proxy::SaveIpBlock>();
    server_fn::axum::register_explicit::<proxy::SetIpBlockOrder>();
    server_fn::axum::register_explicit::<proxy::ToggleIpBlock>();
    server_fn::axum::register_explicit::<proxy::DeleteIpBlock>();
    server_fn::axum::register_explicit::<proxy::ListForwardRules>();
    server_fn::axum::register_explicit::<proxy::SaveForwardRule>();
    server_fn::axum::register_explicit::<proxy::ToggleForwardRule>();
    server_fn::axum::register_explicit::<proxy::DeleteForwardRule>();
    server_fn::axum::register_explicit::<proxy::ListForwardUsers>();
    server_fn::axum::register_explicit::<proxy::CreateForwardUser>();
    server_fn::axum::register_explicit::<proxy::ToggleForwardUser>();
    server_fn::axum::register_explicit::<proxy::DeleteForwardUser>();
    server_fn::axum::register_explicit::<proxy::GetProxyHealth>();

    use server_fns::k8s;
    server_fn::axum::register_explicit::<k8s::GetK8sMetrics>();
    server_fn::axum::register_explicit::<k8s::ListK8sHosts>();
    server_fn::axum::register_explicit::<k8s::CreateK8sHost>();
    server_fn::axum::register_explicit::<k8s::DeleteK8sHost>();
    server_fn::axum::register_explicit::<k8s::ListK8sClusters>();
    server_fn::axum::register_explicit::<k8s::CreateK8sCluster>();
    server_fn::axum::register_explicit::<k8s::DeleteK8sCluster>();
    server_fn::axum::register_explicit::<k8s::ListK8sAlertRules>();
    server_fn::axum::register_explicit::<k8s::SaveK8sAlertRule>();
    server_fn::axum::register_explicit::<k8s::ToggleK8sRule>();
    server_fn::axum::register_explicit::<k8s::DeleteK8sAlertRule>();
    server_fn::axum::register_explicit::<k8s::ListK8sTemplates>();
    server_fn::axum::register_explicit::<k8s::SaveK8sTemplate>();
    server_fn::axum::register_explicit::<k8s::DeleteK8sTemplate>();
    server_fn::axum::register_explicit::<k8s::SetClusterApi>();
    server_fn::axum::register_explicit::<k8s::ListClusterWorkloads>();
    server_fn::axum::register_explicit::<k8s::GetPodLogs>();

    use server_fns::sso;
    server_fn::axum::register_explicit::<sso::GetSsoMetrics>();
    server_fn::axum::register_explicit::<sso::ListSsoProviders>();
    server_fn::axum::register_explicit::<sso::SaveProvider>();
    server_fn::axum::register_explicit::<sso::DeleteProvider>();
    server_fn::axum::register_explicit::<sso::ListOidcClients>();
    server_fn::axum::register_explicit::<sso::SaveOidcClient>();
    server_fn::axum::register_explicit::<sso::RegenerateClientSecret>();
    server_fn::axum::register_explicit::<sso::DeleteOidcClient>();
    server_fn::axum::register_explicit::<sso::ListSsoSessions>();
    server_fn::axum::register_explicit::<sso::RevokeSsoSessions>();

    use server_fns::watch;
    server_fn::axum::register_explicit::<watch::GetWatchMetrics>();
    server_fn::axum::register_explicit::<watch::ListWatchHosts>();
    server_fn::axum::register_explicit::<watch::HostsUnderMaintenance>();
    server_fn::axum::register_explicit::<watch::SaveWatchHost>();
    server_fn::axum::register_explicit::<watch::DeleteWatchHost>();
    server_fn::axum::register_explicit::<watch::ListWatchRules>();
    server_fn::axum::register_explicit::<watch::SaveWatchRule>();
    server_fn::axum::register_explicit::<watch::ToggleWatchRule>();
    server_fn::axum::register_explicit::<watch::DeleteWatchRule>();
    server_fn::axum::register_explicit::<watch::ListWatchGroups>();
    server_fn::axum::register_explicit::<watch::SaveWatchGroup>();
    server_fn::axum::register_explicit::<watch::DeleteWatchGroup>();
    server_fn::axum::register_explicit::<watch::ListWatchMaintenance>();
    server_fn::axum::register_explicit::<watch::CreateWatchMaintenance>();
    server_fn::axum::register_explicit::<watch::DeleteWatchMaintenance>();
    server_fn::axum::register_explicit::<watch::ListHostMetrics>();

    use server_fns::account;
    server_fn::axum::register_explicit::<account::ListLocalAccounts>();
    server_fn::axum::register_explicit::<account::CreateLocalAccount>();
    server_fn::axum::register_explicit::<account::SetAccountRole>();
    server_fn::axum::register_explicit::<account::SetAccountEnabled>();
    server_fn::axum::register_explicit::<account::DeleteLocalAccount>();
    server_fn::axum::register_explicit::<account::ResetAccountPassword>();
    server_fn::axum::register_explicit::<account::ListActiveSessions>();
    server_fn::axum::register_explicit::<account::RevokePortalSessions>();

    use server_fns::audit;
    server_fn::axum::register_explicit::<audit::QueryAuditLog>();

    use server_fns::settings;
    server_fn::axum::register_explicit::<settings::GetSystemSettings>();
    server_fn::axum::register_explicit::<settings::SaveSystemSettings>();

    use server_fns::logs;
    server_fn::axum::register_explicit::<logs::QueryLogs>();

    use server_fns::backup;
    server_fn::axum::register_explicit::<backup::ListBackups>();
    server_fn::axum::register_explicit::<backup::CreateBackup>();
    server_fn::axum::register_explicit::<backup::RestoreBackup>();
    server_fn::axum::register_explicit::<backup::DeleteBackup>();

    use server_fns::addc;
    server_fn::axum::register_explicit::<addc::ListAdPrincipals>();
    server_fn::axum::register_explicit::<addc::ListAdGroups>();
    server_fn::axum::register_explicit::<addc::GetAddcStatus>();
    server_fn::axum::register_explicit::<addc::ListGpos>();
    server_fn::axum::register_explicit::<addc::CreateGpo>();
    server_fn::axum::register_explicit::<addc::DeleteGpo>();
    server_fn::axum::register_explicit::<addc::ListLogonScripts>();
    server_fn::axum::register_explicit::<addc::CreateLogonScript>();
    server_fn::axum::register_explicit::<addc::DeleteLogonScript>();
    server_fn::axum::register_explicit::<addc::JoinDomain>();
    server_fn::axum::register_explicit::<addc::LeaveDomain>();
    server_fn::axum::register_explicit::<addc::ListFsmoRoles>();
    server_fn::axum::register_explicit::<addc::SeizeFsmoRole>();

    use server_fns::alert;
    server_fn::axum::register_explicit::<alert::ListAlerts>();
    server_fn::axum::register_explicit::<alert::AcknowledgeAlerts>();
    server_fn::axum::register_explicit::<alert::ResolveAlerts>();
    server_fn::axum::register_explicit::<alert::ListNotificationTargets>();
    server_fn::axum::register_explicit::<alert::CreateNotificationTarget>();
    server_fn::axum::register_explicit::<alert::SetNotificationTargetEnabled>();
    server_fn::axum::register_explicit::<alert::DeleteNotificationTarget>();
}

/// The HTML document shell used by SSR.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="ja">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone()/>
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

/// Root application component: contexts, stylesheet and routes.
#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    provide_i18n();
    components::theme::provide_theme_context();
    components::toast::provide_toast_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/magnetite.css"/>
        <Title text="Magnetite"/>
        <Router>
            <Routes fallback=|| view! { <p class="notfound">"404"</p> }>
                <Route path=path!("/auth/login") view=LoginPage/>
                <ParentRoute path=path!("/") view=AuthenticatedShell>
                    <Route path=path!("") view=DashboardPage/>
                    <Route path=path!("/audit") view=pages::audit::AuditPage/>
                    <Route path=path!("/alerts") view=pages::alerts::AlertsPage/>
                    <Route path=path!("/backup") view=pages::backup::BackupPage/>
                    <Route path=path!("/logs") view=pages::logs::LogsPage/>
                    <Route path=path!("/settings") view=pages::settings::SettingsPage/>
                    <Route path=path!("/account") view=pages::account::AccountPage/>
                    <Route path=path!("/dns") view=pages::dns::DnsDashboard/>
                    <Route path=path!("/dns/zones") view=pages::dns::ZonesPage/>
                    <Route path=path!("/dns/zones/:zone_id/records") view=pages::dns::RecordsPage/>
                    <Route path=path!("/dns/rpz") view=pages::dns::RpzPage/>
                    <Route path=path!("/dns/dnssec") view=pages::dns::DnssecPage/>
                    <Route path=path!("/dns/geo") view=pages::dns::GeoPage/>
                    <Route path=path!("/dns/forwarders") view=pages::dns::ForwardersPage/>
                    <Route path=path!("/dns/ddns") view=pages::dns::DdnsPage/>
                    <Route path=path!("/dns/replication") view=pages::dns::ReplicationPage/>
                    <Route path=path!("/dns/query-logs") view=pages::dns::QueryLogsPage/>
                    <Route path=path!("/dns/query-test") view=pages::dns::QueryTestPage/>
                    <Route path=path!("/dns/templates") view=|| view! { <PlaceholderPage title_key="domain.dns"/> }/>
                    <Route path=path!("/dhcp") view=pages::dhcp::DhcpDashboard/>
                    <Route path=path!("/dhcp/pools") view=pages::dhcp::PoolsPage/>
                    <Route path=path!("/dhcp/pools/:pool_id/reservations") view=pages::dhcp::ReservationsPage/>
                    <Route path=path!("/dhcp/leases") view=pages::dhcp::LeasesPage/>
                    <Route path=path!("/dhcp/config") view=pages::dhcp::ConfigPage/>
                    <Route path=path!("/ldap") view=pages::ldap::LdapDashboard/>
                    <Route path=path!("/ldap/tree") view=pages::ldap::TreePage/>
                    <Route path=path!("/ldap/users") view=pages::ldap::UsersPage/>
                    <Route path=path!("/ldap/groups") view=pages::ldap::GroupsPage/>
                    <Route path=path!("/ldap/computers") view=pages::ldap::ComputersPage/>
                    <Route path=path!("/ldap/ous") view=pages::ldap::OusPage/>
                    <Route path=path!("/ldap/acl") view=pages::ldap::AclPage/>
                    <Route path=path!("/ldap/replication") view=pages::ldap::LdapReplicationPage/>
                    <Route path=path!("/mail") view=pages::mail::MailDashboard/>
                    <Route path=path!("/mail/users") view=pages::mail::MailUsersPage/>
                    <Route path=path!("/mail/domains") view=pages::mail::DomainsPage/>
                    <Route path=path!("/mail/aliases") view=pages::mail::AliasesPage/>
                    <Route path=path!("/mail/mailing-lists") view=pages::mail::MailingListsPage/>
                    <Route path=path!("/mail/messages") view=pages::mail::MessagesPage/>
                    <Route path=path!("/mail/protocols") view=pages::mail::ProtocolsPage/>
                    <Route path=path!("/mail/dkim") view=pages::mail::DkimPage/>
                    <Route path=path!("/mail/backup-mx") view=pages::mail::BackupMxPage/>
                    <Route path=path!("/mail/replication") view=pages::mail::MailReplicationPage/>
                    <Route path=path!("/mail/relay") view=pages::mail::MailRelayPage/>
                    <Route path=path!("/mail/settings") view=pages::mail::MailSettingsPage/>
                    <Route path=path!("/proxy") view=pages::proxy::ProxyDashboard/>
                    <Route path=path!("/proxy/vhosts") view=pages::proxy::VhostsPage/>
                    <Route path=path!("/proxy/certificates") view=pages::proxy::CertificatesPage/>
                    <Route path=path!("/proxy/acl-rules") view=pages::proxy::AclRulesPage/>
                    <Route path=path!("/proxy/forward") view=pages::proxy::ForwardPage/>
                    <Route path=path!("/proxy/ip-blocklist") view=pages::proxy::IpBlocklistPage/>
                    <Route path=path!("/proxy/access-logs") view=pages::proxy::AccessLogsPage/>
                    <Route path=path!("/proxy/health") view=pages::proxy::HealthPage/>
                    <Route path=path!("/k8s") view=pages::k8s::K8sDashboard/>
                    <Route path=path!("/k8s/hosts") view=pages::k8s::HostsPage/>
                    <Route path=path!("/k8s/clusters") view=pages::k8s::ClustersPage/>
                    <Route path=path!("/k8s/workloads") view=pages::k8s::WorkloadsPage/>
                    <Route path=path!("/k8s/alerts") view=pages::k8s::AlertRulesPage/>
                    <Route path=path!("/k8s/templates") view=pages::k8s::TemplatesPage/>
                    <Route path=path!("/k8s/backups") view=|| view! { <PlaceholderPage title_key="nav.backup"/> }/>
                    <Route path=path!("/sso") view=pages::sso::ProvidersPage/>
                    <Route path=path!("/sso/clients") view=pages::sso::ClientsPage/>
                    <Route path=path!("/sso/sessions") view=pages::sso::SessionsPage/>
                    <Route path=path!("/sso/audit-sink") view=pages::sso::AuditSinkPage/>
                    <Route path=path!("/watch") view=pages::watch::WatchDashboard/>
                    <Route path=path!("/watch/hosts") view=pages::watch::WatchHostsPage/>
                    <Route path=path!("/watch/hosts/:id/metrics") view=pages::watch::MetricsPage/>
                    <Route path=path!("/watch/rules") view=pages::watch::WatchRulesPage/>
                    <Route path=path!("/watch/groups") view=pages::watch::WatchGroupsPage/>
                    <Route path=path!("/watch/maintenance") view=pages::watch::WatchMaintenancePage/>
                    <Route path=path!("/addc") view=pages::addc::AddcDashboard/>
                    <Route path=path!("/addc/gpo") view=pages::addc::GpoPage/>
                    <Route path=path!("/addc/logon-scripts") view=pages::addc::LogonScriptsPage/>
                    <Route path=path!("/addc/domain") view=pages::addc::DomainJoinPage/>
                    <Route path=path!("/addc/fsmo") view=pages::addc::FsmoPage/>
                </ParentRoute>
            </Routes>
        </Router>
    }
}
