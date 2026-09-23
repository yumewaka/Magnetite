//! DHCP reservation list / create (S-DHCP-03) for one pool.

use super::nav::DhcpNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::dhcp::{get_pool, list_reservations, CreateReservation, DeleteReservation};
use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use magnetite_core::domains::dhcp::model::Reservation;

#[component]
pub fn ReservationsPage() -> impl IntoView {
    let params = use_params_map();
    let pool_id = Signal::derive(move || params.get().get("pool_id").unwrap_or_default());

    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let pool = Resource::new(move || pool_id.get(), get_pool);
    let reservations = Resource::new(
        move || (pool_id.get(), reload.get()),
        |(id, _)| list_reservations(id),
    );

    let form_open = RwSignal::new(false);
    let mac = RwSignal::new(String::new());
    let ip = RwSignal::new(String::new());
    let hostname = RwSignal::new(String::new());

    let open_create = move |_| {
        mac.set(String::new());
        ip.set(String::new());
        hostname.set(String::new());
        form_open.set(true);
    };

    let create = ServerAction::<CreateReservation>::new();
    let save_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = create.value().get() {
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
        let now = chrono::Utc::now();
        let reservation = Reservation {
            id: String::new(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            pool_ref: pool_id.get(),
            mac_address: mac.get(),
            ip_address: ip.get(),
            hostname: {
                let h = hostname.get();
                if h.trim().is_empty() {
                    None
                } else {
                    Some(h)
                }
            },
            description: None,
        };
        create.dispatch(CreateReservation { reservation });
    };

    let delete = ServerAction::<DeleteReservation>::new();
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
        Some((_, m)) => format!("予約「{m}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = delete_target.get() {
            delete.dispatch(DeleteReservation { id });
        }
    });

    let pool_name = Signal::derive(move || {
        pool.get()
            .and_then(|r| r.ok())
            .flatten()
            .map(|p| p.name)
            .unwrap_or_default()
    });

    view! {
        <PageHeader title=Signal::derive(move || format!("プール {} の予約", pool_name.get()))>
            <A href="/dhcp/pools" attr:class="btn btn-secondary">"← 戻る"</A>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <DhcpNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                reservations.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "予約がありません。".to_string())/>
                    }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|r| {
                            let r_del = r.clone();
                            view! {
                                <tr>
                                    <td class="mono">{r.mac_address.clone()}</td>
                                    <td class="mono">{r.ip_address.clone()}</td>
                                    <td>{r.hostname.clone().unwrap_or_default()}</td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="削除"
                                            on:click=move |_| {
                                                delete_target.set(Some((r_del.id.clone(), r_del.mac_address.clone())));
                                                confirm_open.set(true);
                                            }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr>
                                    <th>"MAC アドレス"</th><th>"IP アドレス"</th><th>"ホスト名"</th><th>"操作"</th>
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
                    <h2 class="slideover-title">"予約の作成"</h2>
                    <label class="field">
                        <span class="field-label">"MAC アドレス"</span>
                        <input class="input" prop:value=move || mac.get()
                            on:input=move |ev| mac.set(event_target_value(&ev))/>
                    </label>
                    <label class="field">
                        <span class="field-label">"予約 IP"</span>
                        <input class="input" prop:value=move || ip.get()
                            on:input=move |ev| ip.set(event_target_value(&ev))/>
                    </label>
                    <label class="field">
                        <span class="field-label">"ホスト名（任意）"</span>
                        <input class="input" prop:value=move || hostname.get()
                            on:input=move |ev| hostname.set(event_target_value(&ev))/>
                    </label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || create.pending().get()>"保存"</button>
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
