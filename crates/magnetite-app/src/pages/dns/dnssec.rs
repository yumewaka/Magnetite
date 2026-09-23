//! DNSSEC online-signing management (S-DNS DNSSEC). Toggle signing per zone and
//! show the DNSKEY / key tag the operator publishes as a DS record at the
//! parent. Private signing keys stay server-side.

use super::nav::DnsNav;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::dns::{list_zones, DnssecKeyInfo, GetDnssecKeyInfo, SetZoneDnssec};
use leptos::prelude::*;
use magnetite_core::domains::dns::model::Zone;

#[component]
pub fn DnssecPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let zones = Resource::new(move || reload.get(), |_| list_zones());

    // The DNSKEY panel shows the last fetched/returned key material. `pending`
    // tracks which zone a dispatch is for (server-fns don't echo the name back).
    let key_panel = RwSignal::new(Option::<(String, DnssecKeyInfo)>::None);
    let pending_name = RwSignal::new(String::new());

    let toggle = ServerAction::<SetZoneDnssec>::new();
    Effect::new(move |_| {
        if let Some(result) = toggle.value().get() {
            match result {
                Ok(info) => {
                    toast.success("DNSSEC 設定を更新しました。");
                    reload.update(|n| *n += 1);
                    // On enable the server returns the new key material.
                    if let Some(info) = info {
                        key_panel.set(Some((pending_name.get_untracked(), info)));
                    }
                }
                Err(e) => toast.error(e.to_string()),
            }
        }
    });

    let show_key = ServerAction::<GetDnssecKeyInfo>::new();
    Effect::new(move |_| {
        if let Some(result) = show_key.value().get() {
            match result {
                Ok(Some(info)) => key_panel.set(Some((pending_name.get_untracked(), info))),
                Ok(None) => toast.error("この鍵はまだ生成されていません。"),
                Err(e) => toast.error(e.to_string()),
            }
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "DNSSEC".to_string())/>
        <DnsNav/>
        <p class="page-hint">
            "ゾーンごとにオンライン署名（RRSIG/DNSKEY）を切り替えます。有効化すると鍵をサーバー側で生成し、"
            "親ゾーンに公開する DS 情報を表示します。"
        </p>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                zones.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "ゾーンがありません。".to_string())/>
                    }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|zone: Zone| {
                            let Zone { id, name, dnssec_enabled, .. } = zone;
                            let health = if dnssec_enabled { "healthy" } else { "unknown" };
                            let status = if dnssec_enabled { "有効" } else { "無効" };
                            let (tid, tname) = (id.clone(), name.clone());
                            let kname = name.clone();
                            view! {
                                <tr>
                                    <td>{name.clone()}</td>
                                    <td>
                                        <StatusBadge health=Signal::derive(move || health.to_string())/>
                                        " "{status}
                                    </td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary"
                                            prop:disabled=move || toggle.pending().get()
                                            on:click=move |_| {
                                                pending_name.set(tname.clone());
                                                toggle.dispatch(SetZoneDnssec {
                                                    id: tid.clone(),
                                                    name: tname.clone(),
                                                    enabled: !dnssec_enabled,
                                                });
                                            }>
                                            {if dnssec_enabled { "無効化" } else { "有効化" }}
                                        </button>
                                        <Show when=move || dnssec_enabled fallback=|| ()>
                                            <button class="btn btn-secondary"
                                                on:click={
                                                    let kname = kname.clone();
                                                    move |_| {
                                                        pending_name.set(kname.clone());
                                                        show_key.dispatch(GetDnssecKeyInfo { name: kname.clone() });
                                                    }
                                                }>"鍵情報"</button>
                                        </Show>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr>
                                    <th>"ゾーン"</th><th>"DNSSEC"</th><th>"操作"</th>
                                </tr></thead>
                                <tbody>{rows}</tbody>
                            </table>
                        }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || key_panel.get().is_some() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| key_panel.set(None)>
                <div class="slideover" on:click=|ev| ev.stop_propagation()>
                    {move || key_panel.get().map(|(name, info)| view! {
                        <h2 class="slideover-title">{format!("{name} の DNSSEC 鍵")}</h2>
                        <label class="field">
                            <span class="field-label">"キータグ (Key Tag)"</span>
                            <input class="input" readonly=true prop:value=info.key_tag.to_string()/>
                        </label>
                        <label class="field">
                            <span class="field-label">"DNSKEY レコード"</span>
                            <textarea class="input" rows="4" readonly=true prop:value=info.dnskey_record.clone()></textarea>
                        </label>
                        <p class="page-hint">
                            "親ゾーンにこの鍵の DS レコードを登録すると信頼チェーンが確立します。"
                        </p>
                    })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| key_panel.set(None)>"閉じる"</button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
