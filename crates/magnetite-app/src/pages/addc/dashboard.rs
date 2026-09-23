//! AD DC dashboard (read-only). Shows the embedded domain controller's serving
//! status, endpoints, Kerberos service principals, DRS replication summary, the
//! well-known groups, and the AD principals sourced from the shared database.
//! Secret key material is never fetched to the browser.

use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::addc::{
    get_addc_status, list_ad_groups, list_ad_principals, AdGroupRow, AdPrincipalRow,
};
use leptos::prelude::*;

#[component]
pub fn AddcDashboard() -> impl IntoView {
    let reload = RwSignal::new(0_u32);
    let status = Resource::new(move || reload.get(), |_| get_addc_status());
    let groups = Resource::new(move || reload.get(), |_| list_ad_groups());
    let principals = Resource::new(move || reload.get(), |_| list_ad_principals());

    view! {
        <PageHeader title=Signal::derive(|| "AD ドメインコントローラ".to_string())>
            <button class="btn btn-secondary btn-sm" on:click=move |_| reload.update(|n| *n += 1)>
                "再読み込み"
            </button>
        </PageHeader>
        <super::nav::AddcNav/>

        // --- Serving status, endpoints, SPNs & replication ---
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || status.get().map(|res| match res {
                Err(_) => view! {
                    <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                }.into_any(),
                Ok(s) => {
                    let health = s.health.clone();
                    let spn_items = s.spns.iter().cloned().map(|spn| view! {
                        <li class="mono">{spn}</li>
                    }).collect_view();
                    view! {
                        <section class="addc-status">
                            <div class="addc-status-row">
                                <span class="field-label">"サーバ状態"</span>
                                <StatusBadge health=Signal::derive(move || health.clone())/>
                            </div>
                            <dl class="addc-status-summary">
                                <dt>"レルム"</dt><dd class="mono">{s.realm.clone()}</dd>
                                <dt>"プリンシパル数"</dt><dd>{s.principals}</dd>
                                <dt>"レプリケーション高水位 (USN)"</dt><dd>{s.high_water_usn}</dd>
                            </dl>

                            <h2 class="section-title">"エンドポイント"</h2>
                            <dl class="addc-status-summary">
                                <dt>"KDC (Kerberos)"</dt><dd class="mono">{s.kdc.clone()}</dd>
                                <dt>"SMB (SYSVOL / pipes)"</dt><dd class="mono">{s.smb.clone()}</dd>
                                <dt>"RPC / SAMR"</dt><dd class="mono">{s.rpc.clone()}</dd>
                                <dt>"DRSUAPI (DCSync)"</dt><dd class="mono">{s.drs.clone()}</dd>
                            </dl>

                            <h2 class="section-title">"サービスプリンシパル (SPN)"</h2>
                            <ul class="addc-spn-list">{spn_items}</ul>

                            <p class="field-hint">
                                "「未稼働」は [domains.addc.server.addc] が未設定で、KDC / SMB / RPC を起動していないことを示します（上記はデフォルトの構成値です）。"
                            </p>
                        </section>
                    }.into_any()
                }
            })}
        </Suspense>

        // --- Groups ---
        <h2 class="section-title">"グループ"</h2>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || groups.get().map(|res| match res {
                Err(_) => view! {
                    <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                }.into_any(),
                Ok(list) if list.is_empty() => view! {
                    <EmptyState message=Signal::derive(|| "グループがありません。".to_string())/>
                }.into_any(),
                Ok(list) => {
                    let rows = list.into_iter().map(|g: AdGroupRow| view! {
                        <tr><td>{g.name.clone()}</td><td class="mono">{g.rid}</td></tr>
                    }).collect_view();
                    view! {
                        <table class="data-table">
                            <thead><tr><th>"グループ"</th><th>"RID"</th></tr></thead>
                            <tbody>{rows}</tbody>
                        </table>
                    }.into_any()
                }
            })}
        </Suspense>

        // --- AD principals ---
        <h2 class="section-title">"ディレクトリ プリンシパル"</h2>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || principals.get().map(|res| match res {
                Err(_) => view! {
                    <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                }.into_any(),
                Ok(list) if list.is_empty() => view! {
                    <EmptyState message=Signal::derive(|| "プリンシパルがありません。".to_string())/>
                }.into_any(),
                Ok(list) => {
                    let rows = list.into_iter().map(|p: AdPrincipalRow| view! {
                        <tr>
                            <td>{p.sam_account_name.clone()}</td>
                            <td class="mono">{p.rid}</td>
                        </tr>
                    }).collect_view();
                    view! {
                        <table class="data-table">
                            <thead><tr><th>"sAMAccountName"</th><th>"RID"</th></tr></thead>
                            <tbody>{rows}</tbody>
                        </table>
                    }.into_any()
                }
            })}
        </Suspense>
    }
}
