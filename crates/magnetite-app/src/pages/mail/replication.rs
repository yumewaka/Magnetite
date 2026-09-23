//! Mailbox replication status (Step 2 HA). Read-only view of this instance's
//! replication role (primary serves the feed / secondary pulls it) and the
//! persisted sync state. Configuration lives in the server-side `magnetite.toml`
//! (`[domains.mail.server.replication]`); the shared secret is never shown.

use super::nav::MailNav;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::mail::get_mail_repl_status;
use leptos::prelude::*;

#[component]
pub fn MailReplicationPage() -> impl IntoView {
    let reload = RwSignal::new(0_u32);
    let status = Resource::new(move || reload.get(), |_| get_mail_repl_status());

    view! {
        <PageHeader title=Signal::derive(|| "メールボックス レプリケーション".to_string())>
            <button class="btn btn-secondary" on:click=move |_| reload.update(|n| *n += 1)>"更新"</button>
        </PageHeader>
        <MailNav/>
        <p class="page-hint">
            "プライマリはメールボックスの変更フィード（追加・削除）を "
            <code>"/repl/mail"</code>
            " で配信し、セカンダリはそれを定期取得して自分のメールボックスへ反映します。\
             設定はサーバの magnetite.toml（[domains.mail.server.replication]）で行います（共有シークレットは表示しません）。"
        </p>

        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                status.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(s) => {
                        let role = if !s.configured {
                            "未構成"
                        } else if s.is_secondary {
                            "セカンダリ（プライマリから取得）"
                        } else {
                            "プライマリ（フィード配信）"
                        };
                        let enabled = if s.enabled { "有効" } else { "無効" };
                        let primary = s.primary_url.clone().unwrap_or_else(|| "-".into());
                        let last_sync = s.state.last_sync
                            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| "-".into());
                        let cursor = if s.state.cursor.is_empty() { "-".to_string() } else { s.state.cursor.clone() };
                        let err = s.state.last_error.clone();
                        view! {
                            <table class="data-table">
                                <tbody>
                                    <tr><th>"ロール"</th><td>{role}</td></tr>
                                    <tr><th>"状態"</th><td>{enabled}</td></tr>
                                    <tr><th>"プライマリ URL"</th><td>{primary}</td></tr>
                                    <tr><th>"取得間隔"</th><td>{format!("{}秒", s.interval_secs)}</td></tr>
                                    <tr><th>"最終同期"</th><td>{last_sync}</td></tr>
                                    <tr><th>"カーソル"</th><td class="cell-muted">{cursor}</td></tr>
                                    <tr><th>"適用（追加）"</th><td>{s.state.applied}</td></tr>
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
