//! DNS zone list / create / edit (S-DNS-02). Includes the SOA form and the
//! AC-13 cascade-delete confirmation.

use super::nav::DnsNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::dns::{count_zone_records, list_zones, DeleteZone, SaveZone};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;
use magnetite_core::domains::dns::model::{Soa, Zone};

#[component]
pub fn ZonesPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let zones = Resource::new(move || reload.get(), |_| list_zones());

    // Form state ("" id = create).
    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let mname = RwSignal::new(String::new());
    let rname = RwSignal::new(String::new());
    let serial = RwSignal::new(1_u32.to_string());
    let refresh = RwSignal::new(3600_u32.to_string());
    let retry = RwSignal::new(900_u32.to_string());
    let expire = RwSignal::new(604_800_u32.to_string());
    let minimum = RwSignal::new(86_400_u32.to_string());
    let enabled = RwSignal::new(true);

    let open_create = move |_| {
        edit_id.set(String::new());
        name.set(String::new());
        let d = Soa::default();
        mname.set(String::new());
        rname.set(String::new());
        serial.set(d.serial.to_string());
        refresh.set(d.refresh.to_string());
        retry.set(d.retry.to_string());
        expire.set(d.expire.to_string());
        minimum.set(d.minimum.to_string());
        enabled.set(true);
        form_open.set(true);
    };
    let open_edit = move |zone: Zone| {
        edit_id.set(zone.id.clone());
        name.set(zone.name.clone());
        mname.set(zone.soa.mname.clone());
        rname.set(zone.soa.rname.clone());
        serial.set(zone.soa.serial.to_string());
        refresh.set(zone.soa.refresh.to_string());
        retry.set(zone.soa.retry.to_string());
        expire.set(zone.soa.expire.to_string());
        minimum.set(zone.soa.minimum.to_string());
        enabled.set(zone.enabled);
        form_open.set(true);
    };

    // Save.
    let save = ServerAction::<SaveZone>::new();
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
        let parse = |s: &RwSignal<String>| s.get().trim().parse::<u32>().unwrap_or(0);
        let soa = Soa {
            mname: mname.get(),
            rname: rname.get(),
            serial: parse(&serial),
            refresh: parse(&refresh),
            retry: parse(&retry),
            expire: parse(&expire),
            minimum: parse(&minimum),
        };
        save.dispatch(SaveZone {
            id: edit_id.get(),
            name: name.get(),
            soa,
            enabled: enabled.get(),
        });
    };

    // Delete with cascade confirmation.
    let delete = ServerAction::<DeleteZone>::new();
    let delete_target = RwSignal::new(Option::<(String, String, u64)>::None);
    Effect::new(move |_| {
        if let Some(Ok(())) = delete.value().get() {
            toast.success("削除しました。");
            reload.update(|n| *n += 1);
        }
    });
    let confirm_open = RwSignal::new(false);
    let request_delete = move |zone: Zone| {
        spawn_local(async move {
            let count = count_zone_records(zone.id.clone()).await.unwrap_or(0);
            delete_target.set(Some((zone.id, zone.name, count)));
            confirm_open.set(true);
        });
    };
    let confirm_body = Signal::derive(move || match delete_target.get() {
        Some((_, name, count)) if count > 0 => {
            format!(
                "このゾーンには {count} 件のレコードがあります。まとめて削除しますか？（{name}）"
            )
        }
        Some((_, name, _)) => format!("ゾーン「{name}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    // When the dialog closes (cancel or confirm), drop the pending target.
    Effect::new(move |_| {
        if !confirm_open.get() {
            delete_target.set(None);
        }
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _, _)) = delete_target.get() {
            delete.dispatch(DeleteZone { id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "DNS ゾーン".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <DnsNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                zones.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }
                    .into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "DNS ゾーンがありません。".to_string())/>
                    }
                    .into_any(),
                    Ok(list) => {
                        let rows = list
                            .into_iter()
                            .map(|zone| {
                                let z_edit = zone.clone();
                                let z_del = zone.clone();
                                let health = if zone.enabled { "healthy" } else { "unknown" };
                                let records_href = format!("/dns/zones/{}/records", zone.id);
                                view! {
                                    <tr>
                                        <td><A href=records_href attr:class="link">{zone.name.clone()}</A></td>
                                        <td>{zone.soa.mname.clone()}</td>
                                        <td>{zone.soa.rname.clone()}</td>
                                        <td>{zone.soa.serial}</td>
                                        <td><StatusBadge health=Signal::derive(move || health.to_string())/></td>
                                        <td class="row-actions">
                                            <button class="icon-button" title="編集"
                                                on:click=move |_| open_edit(z_edit.clone())>"\u{270E}"</button>
                                            <button class="icon-button" title="削除"
                                                on:click=move |_| request_delete(z_del.clone())>"\u{1F5D1}"</button>
                                        </td>
                                    </tr>
                                }
                            })
                            .collect_view();
                        view! {
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>"ゾーン名"</th><th>"Primary NS"</th><th>"管理者"</th>
                                        <th>"Serial"</th><th>"状態"</th><th>"操作"</th>
                                    </tr>
                                </thead>
                                <tbody>{rows}</tbody>
                            </table>
                        }
                        .into_any()
                    }
                })
            }}
        </Suspense>

        // Create/edit slide-over.
        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">
                        {move || if edit_id.get().is_empty() { "ゾーンの作成" } else { "ゾーンの編集" }}
                    </h2>
                    <label class="field">
                        <span class="field-label">"ゾーン名"</span>
                        <input class="input" prop:value=move || name.get()
                            prop:disabled=move || !edit_id.get().is_empty()
                            on:input=move |ev| name.set(event_target_value(&ev))/>
                    </label>
                    <label class="field">
                        <span class="field-label">"Primary NS (mname)"</span>
                        <input class="input" prop:value=move || mname.get()
                            on:input=move |ev| mname.set(event_target_value(&ev))/>
                    </label>
                    <label class="field">
                        <span class="field-label">"管理者Email (rname・ドット表記)"</span>
                        <input class="input" prop:value=move || rname.get()
                            on:input=move |ev| rname.set(event_target_value(&ev))/>
                    </label>
                    <details class="soa-details">
                        <summary>"SOA 詳細"</summary>
                        <div class="soa-grid">
                            {soa_number("Serial", serial)}
                            {soa_number("Refresh", refresh)}
                            {soa_number("Retry", retry)}
                            {soa_number("Expire", expire)}
                            {soa_number("Minimum", minimum)}
                        </div>
                    </details>
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

/// A labelled SOA number input bound to a string signal.
fn soa_number(label: &'static str, sig: RwSignal<String>) -> impl IntoView {
    view! {
        <label class="field">
            <span class="field-label">{label}</span>
            <input class="input" type="number" prop:value=move || sig.get()
                on:input=move |ev| sig.set(event_target_value(&ev))/>
        </label>
    }
}
