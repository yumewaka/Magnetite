//! LDAP syncrepl consumer status (RFC 4533). Read-only view of whether this
//! instance replicates from an upstream provider and the persisted sync state.
//! Configuration lives in the server-side `magnetite.toml`
//! (`[domains.ldap.server.consumer]`); bind credentials are never shown.

use super::nav::LdapNav;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::ldap::get_ldap_sync_status;
use leptos::prelude::*;

#[component]
pub fn LdapReplicationPage() -> impl IntoView {
    let reload = RwSignal::new(0_u32);
    let status = Resource::new(move || reload.get(), |_| get_ldap_sync_status());

    view! {
        <PageHeader title=Signal::derive(|| "LDAP レプリケーション".to_string())>
            <button class="btn btn-secondary" on:click=move |_| reload.update(|n| *n += 1)>"更新"</button>
        </PageHeader>
        <LdapNav/>
        <p class="page-hint">
            "上流 LDAP サーバ（別 Magnetite / OpenLDAP）から RFC 4533 syncrepl でディレクトリ変更を取得し、\
             このインスタンスへ複製します（consumer / レプリカ）。設定はサーバの magnetite.toml\
             （[domains.ldap.server.consumer]）で行います（バインド認証情報は表示しません）。"
        </p>

        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                status.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(s) => {
                        let role = if !s.configured {
                            "未構成"
                        } else if s.enabled {
                            "consumer（上流から取得）"
                        } else {
                            "構成済み（無効）"
                        };
                        let mode = match s.mode.as_str() {
                            "ad-dirsync" => "AD DirSync（Samba/Windows AD、要レプリケーション権限）",
                            "ad-usn" => "AD USN ポーリング（読み取り専用アカウント可）",
                            _ => "syncrepl（RFC 4533 / OpenLDAP）",
                        };
                        let provider = s.provider_url.clone().unwrap_or_else(|| "-".into());
                        let last_sync = s.state.last_sync
                            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| "-".into());
                        let cookie = if s.state.cookie.is_empty() { "-".to_string() } else { s.state.cookie.clone() };
                        let err = s.state.last_error.clone();
                        view! {
                            <table class="data-table">
                                <tbody>
                                    <tr><th>"ロール"</th><td>{role}</td></tr>
                                    <tr><th>"方式"</th><td>{mode}</td></tr>
                                    <tr><th>"上流プロバイダ"</th><td>{provider}</td></tr>
                                    <tr><th>"ベース DN"</th><td>{s.base_dn.clone()}</td></tr>
                                    <tr><th>"取得間隔"</th><td>{format!("{}秒", s.interval_secs)}</td></tr>
                                    <tr><th>"最終同期"</th><td>{last_sync}</td></tr>
                                    <tr><th>"クッキー"</th><td class="cell-muted">{cookie}</td></tr>
                                    <tr><th>"適用（追加/更新）"</th><td>{s.state.applied}</td></tr>
                                    <tr><th>"適用（削除）"</th><td>{s.state.deleted}</td></tr>
                                    <tr><th>"最終エラー"</th><td class="cell-muted">{err.unwrap_or_else(|| "-".into())}</td></tr>
                                </tbody>
                            </table>
                        }.into_any()
                    }
                })
            }}
        </Suspense>
    }
}
