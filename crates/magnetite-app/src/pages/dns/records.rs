//! DNS record list / create / edit for one zone (S-DNS-03). The value input and
//! the persisted `data` JSON switch on the record type.

use super::nav::DnsNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::dns::{get_zone, list_records, DeleteRecord, SaveRecord};
use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use magnetite_core::domains::dns::model::{Record, RecordType};
use serde_json::json;

fn format_data(record: &Record) -> String {
    let d = &record.data;
    let s = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    match record.record_type {
        RecordType::A | RecordType::Aaaa => s("address"),
        RecordType::Cname => s("target"),
        RecordType::Ns => s("nsdname"),
        RecordType::Ptr => s("ptrdname"),
        RecordType::Mx => {
            let pref = d
                .get("preference")
                .and_then(magnetite_core::domains::dns::validate::as_u64_lenient)
                .unwrap_or(0);
            format!("{pref} {}", s("exchange"))
        }
        RecordType::Txt => s("text"),
        RecordType::Srv | RecordType::Caa => s("value"),
    }
}

#[component]
pub fn RecordsPage() -> impl IntoView {
    let params = use_params_map();
    let zone_id = Signal::derive(move || params.get().get("zone_id").unwrap_or_default());

    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let zone = Resource::new(move || zone_id.get(), get_zone);
    let records = Resource::new(
        move || (zone_id.get(), reload.get()),
        |(id, _)| list_records(id),
    );

    // Form state.
    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let rtype = RwSignal::new(RecordType::A.as_str().to_string());
    let ttl = RwSignal::new(3600_u32.to_string());
    let enabled = RwSignal::new(true);
    // Per-type value fields.
    let address = RwSignal::new(String::new());
    let target = RwSignal::new(String::new());
    let nsdname = RwSignal::new(String::new());
    let ptrdname = RwSignal::new(String::new());
    let preference = RwSignal::new("10".to_string());
    let exchange = RwSignal::new(String::new());
    let text = RwSignal::new(String::new());
    let value = RwSignal::new(String::new());

    let clear_value_fields = move || {
        address.set(String::new());
        target.set(String::new());
        nsdname.set(String::new());
        ptrdname.set(String::new());
        preference.set("10".to_string());
        exchange.set(String::new());
        text.set(String::new());
        value.set(String::new());
    };

    let open_create = move |_| {
        edit_id.set(String::new());
        name.set(String::new());
        rtype.set(RecordType::A.as_str().to_string());
        ttl.set(3600.to_string());
        enabled.set(true);
        clear_value_fields();
        form_open.set(true);
    };
    let open_edit = move |rec: Record| {
        edit_id.set(rec.id.clone());
        name.set(rec.name.clone());
        rtype.set(rec.record_type.as_str().to_string());
        ttl.set(rec.ttl.to_string());
        enabled.set(rec.enabled);
        clear_value_fields();
        let s = |k: &str| {
            rec.data
                .get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        match rec.record_type {
            RecordType::A | RecordType::Aaaa => address.set(s("address")),
            RecordType::Cname => target.set(s("target")),
            RecordType::Ns => nsdname.set(s("nsdname")),
            RecordType::Ptr => ptrdname.set(s("ptrdname")),
            RecordType::Mx => {
                preference.set(
                    rec.data
                        .get("preference")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(10)
                        .to_string(),
                );
                exchange.set(s("exchange"));
            }
            RecordType::Txt => text.set(s("text")),
            RecordType::Srv | RecordType::Caa => value.set(s("value")),
        }
        form_open.set(true);
    };

    let save = ServerAction::<SaveRecord>::new();
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
        let data = match rt {
            RecordType::A | RecordType::Aaaa => json!({ "address": address.get() }),
            RecordType::Cname => json!({ "target": target.get() }),
            RecordType::Ns => json!({ "nsdname": nsdname.get() }),
            RecordType::Ptr => json!({ "ptrdname": ptrdname.get() }),
            RecordType::Mx => json!({
                "preference": preference.get().trim().parse::<u16>().unwrap_or(0),
                "exchange": exchange.get(),
            }),
            RecordType::Txt => json!({ "text": text.get() }),
            RecordType::Srv | RecordType::Caa => json!({ "value": value.get() }),
        };
        let now = chrono::Utc::now();
        let record = Record {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            zone: zone_id.get(),
            name: name.get(),
            ttl: ttl.get().trim().parse::<u32>().unwrap_or(3600),
            record_type: rt,
            data,
            enabled: enabled.get(),
        };
        save.dispatch(SaveRecord { record });
    };

    // Delete.
    let delete = ServerAction::<DeleteRecord>::new();
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
        Some((_, n)) => format!("レコード「{n}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = delete_target.get() {
            delete.dispatch(DeleteRecord { id });
        }
    });

    let zone_name = Signal::derive(move || {
        zone.get()
            .and_then(|r| r.ok())
            .flatten()
            .map(|z| z.name)
            .unwrap_or_default()
    });

    view! {
        <PageHeader title=Signal::derive(move || format!("ゾーン {} のレコード", zone_name.get()))>
            <A href="/dns/zones" attr:class="btn btn-secondary">"← 戻る"</A>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <DnsNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                records.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "このゾーンにはレコードがありません。".to_string())/>
                    }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|rec| {
                            let r_edit = rec.clone();
                            let r_del = rec.clone();
                            let disp = format_data(&rec);
                            view! {
                                <tr>
                                    <td>{rec.name.clone()}</td>
                                    <td><span class="badge">{rec.record_type.as_str()}</span></td>
                                    <td class="mono">{disp}</td>
                                    <td>{rec.ttl}</td>
                                    <td>{if rec.enabled { "有効" } else { "無効" }}</td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="編集"
                                            on:click=move |_| open_edit(r_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除"
                                            on:click=move |_| {
                                                delete_target.set(Some((r_del.id.clone(), r_del.name.clone())));
                                                confirm_open.set(true);
                                            }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr>
                                    <th>"名前"</th><th>"種別"</th><th>"値"</th><th>"TTL"</th><th>"状態"</th><th>"操作"</th>
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
                    <h2 class="slideover-title">
                        {move || if edit_id.get().is_empty() { "レコードの作成" } else { "レコードの編集" }}
                    </h2>
                    <label class="field">
                        <span class="field-label">"名前"</span>
                        <input class="input" prop:value=move || name.get()
                            on:input=move |ev| name.set(event_target_value(&ev))/>
                    </label>
                    <label class="field">
                        <span class="field-label">"種別"</span>
                        <select class="input" on:change=move |ev| rtype.set(event_target_value(&ev))
                            prop:value=move || rtype.get()>
                            {RecordType::ALL.into_iter().map(|t| view! {
                                <option value=t.as_str()>{t.as_str()}</option>
                            }).collect_view()}
                        </select>
                    </label>
                    {move || record_value_input(
                        RecordType::from_str(&rtype.get()).unwrap_or(RecordType::A),
                        address, target, nsdname, ptrdname, preference, exchange, text, value,
                    )}
                    <label class="field">
                        <span class="field-label">"TTL（秒）"</span>
                        <input class="input" type="number" prop:value=move || ttl.get()
                            on:input=move |ev| ttl.set(event_target_value(&ev))/>
                    </label>
                    <label class="field field-inline">
                        <input type="checkbox" prop:checked=move || enabled.get()
                            on:change=move |ev| enabled.set(event_target_checked(&ev))/>
                        <span>"有効"</span>
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

/// The value input(s) for the selected record type.
#[allow(clippy::too_many_arguments)]
fn record_value_input(
    rt: RecordType,
    address: RwSignal<String>,
    target: RwSignal<String>,
    nsdname: RwSignal<String>,
    ptrdname: RwSignal<String>,
    preference: RwSignal<String>,
    exchange: RwSignal<String>,
    text: RwSignal<String>,
    value: RwSignal<String>,
) -> AnyView {
    let single = |label: &'static str, sig: RwSignal<String>| {
        view! {
            <label class="field">
                <span class="field-label">{label}</span>
                <input class="input" prop:value=move || sig.get()
                    on:input=move |ev| sig.set(event_target_value(&ev))/>
            </label>
        }
        .into_any()
    };
    match rt {
        RecordType::A => single("アドレス (IPv4)", address),
        RecordType::Aaaa => single("アドレス (IPv6)", address),
        RecordType::Cname => single("ターゲット (FQDN)", target),
        RecordType::Ns => single("ネームサーバー (FQDN)", nsdname),
        RecordType::Ptr => single("ポインタ先 (FQDN)", ptrdname),
        RecordType::Txt => single("テキスト", text),
        RecordType::Srv | RecordType::Caa => single("値", value),
        RecordType::Mx => view! {
            <label class="field">
                <span class="field-label">"優先度 (0〜65535)"</span>
                <input class="input" type="number" prop:value=move || preference.get()
                    on:input=move |ev| preference.set(event_target_value(&ev))/>
            </label>
            <label class="field">
                <span class="field-label">"交換先 (FQDN)"</span>
                <input class="input" prop:value=move || exchange.get()
                    on:input=move |ev| exchange.set(event_target_value(&ev))/>
            </label>
        }
        .into_any(),
    }
}
