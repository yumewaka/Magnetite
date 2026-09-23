//! GeoDNS rule management (S-DNS GeoDNS): subnet/region-based answer routing.
//! A rule owns one `(name, type)` and returns per-region data when the client IP
//! matches a region's CIDRs, else the default answer. Editing is delete+recreate.

use super::nav::DnsNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::dns::{
    list_geo_rules, list_zones, CreateGeoRule, DeleteGeoRule, ToggleGeoRule,
};
use leptos::prelude::*;
use magnetite_core::domains::dns::model::{GeoRegion, GeoRule, RecordType};

/// Record types the GeoDNS form supports (address answers).
const TYPES: [(RecordType, &str); 2] = [(RecordType::A, "A"), (RecordType::Aaaa, "AAAA")];

fn address_of(data: &serde_json::Value) -> String {
    data.get("address")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

#[component]
pub fn GeoPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let rules = Resource::new(move || reload.get(), |_| list_geo_rules());
    let zones = Resource::new(|| (), |_| list_zones());

    let form_open = RwSignal::new(false);
    let zone = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let rtype = RwSignal::new("A".to_string());
    let ttl = RwSignal::new("300".to_string());
    let default_addr = RwSignal::new(String::new());
    let regions_text = RwSignal::new(String::new());

    let open_create = move |_| {
        zone.set(String::new());
        name.set(String::new());
        rtype.set("A".into());
        ttl.set("300".into());
        default_addr.set(String::new());
        regions_text.set(String::new());
        form_open.set(true);
    };

    let save = ServerAction::<CreateGeoRule>::new();
    let save_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = save.value().get() {
            match result {
                Ok(()) => {
                    save_error.set(None);
                    form_open.set(false);
                    toast.success("保存しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => save_error.set(Some(e.to_string())),
            }
        }
    });

    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let rt = RecordType::from_str(&rtype.get()).unwrap_or(RecordType::A);
        let ttl_val: u32 = ttl.get().trim().parse().unwrap_or(300);
        // Parse the region lines: `label | cidr1,cidr2 | address`.
        let mut regions = Vec::new();
        for line in regions_text.get().lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(3, '|').map(|s| s.trim()).collect();
            if parts.len() != 3 || parts[0].is_empty() || parts[2].is_empty() {
                save_error.set(Some(format!(
                    "リージョン行の書式が不正です: 「{line}」（ラベル | CIDR,… | アドレス）"
                )));
                return;
            }
            let cidrs: Vec<String> = parts[1]
                .split(',')
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty())
                .collect();
            regions.push(GeoRegion {
                region: parts[0].to_string(),
                cidrs,
                data: serde_json::json!({ "address": parts[2] }),
            });
        }
        let now = chrono::Utc::now();
        let rule = GeoRule {
            id: String::new(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            zone: zone.get(),
            name: name.get(),
            record_type: rt,
            ttl: ttl_val,
            default_data: serde_json::json!({ "address": default_addr.get() }),
            regions,
            enabled: true,
        };
        save.dispatch(CreateGeoRule { rule });
    };

    let toggle = ServerAction::<ToggleGeoRule>::new();
    Effect::new(move |_| {
        if let Some(Ok(())) = toggle.value().get() {
            reload.update(|n| *n += 1);
        }
    });

    let delete = ServerAction::<DeleteGeoRule>::new();
    let confirm_open = RwSignal::new(false);
    let delete_target = RwSignal::new(Option::<(String, String)>::None);
    Effect::new(move |_| {
        if let Some(Ok(())) = delete.value().get() {
            toast.success("削除しました。");
            reload.update(|n| *n += 1);
        }
    });
    Effect::new(move |_| {
        if !confirm_open.get() {
            delete_target.set(None);
        }
    });
    let confirm_body = Signal::derive(move || match delete_target.get() {
        Some((_, n)) => format!("GeoDNS ルール「{n}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = delete_target.get() {
            delete.dispatch(DeleteGeoRule { id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "GeoDNS".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <DnsNav/>
        <p class="page-hint">
            "クライアントのサブネットに応じて応答を振り分けます。どのリージョンにも一致しない場合は既定の応答を返します。"
        </p>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                rules.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "GeoDNS ルールがありません。".to_string())/>
                    }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|rule| {
                            let health = if rule.enabled { "healthy" } else { "unknown" };
                            let (tid, ten) = (rule.id.clone(), rule.enabled);
                            let (did, dname) = (rule.id.clone(), rule.name.clone());
                            let region_count = rule.regions.len();
                            view! {
                                <tr>
                                    <td>{rule.name.clone()}</td>
                                    <td>{rule.record_type.as_str().to_string()}</td>
                                    <td>{rule.ttl}</td>
                                    <td>{address_of(&rule.default_data)}</td>
                                    <td>{region_count}</td>
                                    <td><StatusBadge health=Signal::derive(move || health.to_string())/></td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="有効/無効"
                                            on:click=move |_| { toggle.dispatch(ToggleGeoRule { id: tid.clone(), enabled: !ten }); }>
                                            {if ten { "\u{23F8}" } else { "\u{25B6}" }}
                                        </button>
                                        <button class="icon-button" title="削除"
                                            on:click=move |_| {
                                                delete_target.set(Some((did.clone(), dname.clone())));
                                                confirm_open.set(true);
                                            }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr>
                                    <th>"名前"</th><th>"種別"</th><th>"TTL"</th><th>"既定"</th>
                                    <th>"リージョン"</th><th>"状態"</th><th>"操作"</th>
                                </tr></thead>
                                <tbody>{rows}</tbody>
                            </table>
                        }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">"GeoDNS ルールの作成"</h2>
                    <label class="field">
                        <span class="field-label">"ゾーン"</span>
                        <select class="input" prop:value=move || zone.get()
                            on:change=move |ev| zone.set(event_target_value(&ev))>
                            <option value="">"（選択）"</option>
                            <Suspense fallback=|| ()>
                                {move || zones.get().map(|res| match res {
                                    Ok(list) => list.into_iter().map(|z| view! {
                                        <option value=z.id.clone()>{z.name.clone()}</option>
                                    }).collect_view().into_any(),
                                    Err(_) => ().into_any(),
                                })}
                            </Suspense>
                        </select>
                    </label>
                    <label class="field">
                        <span class="field-label">"名前 (FQDN)"</span>
                        <input class="input" prop:value=move || name.get()
                            on:input=move |ev| name.set(event_target_value(&ev))/>
                    </label>
                    <label class="field">
                        <span class="field-label">"種別"</span>
                        <select class="input" prop:value=move || rtype.get()
                            on:change=move |ev| rtype.set(event_target_value(&ev))>
                            {TYPES.into_iter().map(|(t, label)| view! {
                                <option value=t.as_str()>{label}</option>
                            }).collect_view()}
                        </select>
                    </label>
                    <label class="field">
                        <span class="field-label">"TTL (秒)"</span>
                        <input class="input" type="number" prop:value=move || ttl.get()
                            on:input=move |ev| ttl.set(event_target_value(&ev))/>
                    </label>
                    <label class="field">
                        <span class="field-label">"既定アドレス"</span>
                        <input class="input" prop:value=move || default_addr.get()
                            on:input=move |ev| default_addr.set(event_target_value(&ev))/>
                    </label>
                    <label class="field">
                        <span class="field-label">"リージョン（1行に1件：ラベル | CIDR,… | アドレス）"</span>
                        <textarea class="input" rows="4" prop:value=move || regions_text.get()
                            on:input=move |ev| regions_text.set(event_target_value(&ev))
                            placeholder="EU | 10.0.0.0/8,192.168.0.0/16 | 203.0.113.10"></textarea>
                    </label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || save.pending().get()>"保存"</button>
                    </div>
                </form>
            </div>
        </Show>

        <ConfirmDialog
            title=Signal::derive(|| "削除の確認".to_string())
            body=confirm_body
            open=confirm_open
            on_confirm=on_confirm_delete
        />
    }
}
