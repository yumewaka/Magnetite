//! DHCP pool list / create / edit (S-DHCP-02). IPv4/IPv6 range fields with the
//! AC-14 overlap check (server-side) and a delete confirmation.

use super::nav::DhcpNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::dhcp::{count_pool_active_leases, list_pools, DeletePool, SavePool};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;
use magnetite_core::domains::dhcp::model::Pool;

fn opt(s: String) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

#[component]
pub fn PoolsPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let pools = Resource::new(move || reload.get(), |_| list_pools());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let subnet_v4 = RwSignal::new(String::new());
    let start_v4 = RwSignal::new(String::new());
    let end_v4 = RwSignal::new(String::new());
    let gateway = RwSignal::new(String::new());
    let dns_servers = RwSignal::new(String::new());
    let domain_name = RwSignal::new(String::new());
    let lease_secs = RwSignal::new(String::new());
    let enabled = RwSignal::new(true);

    let open_create = move |_| {
        edit_id.set(String::new());
        name.set(String::new());
        subnet_v4.set(String::new());
        start_v4.set(String::new());
        end_v4.set(String::new());
        gateway.set(String::new());
        dns_servers.set(String::new());
        domain_name.set(String::new());
        lease_secs.set(String::new());
        enabled.set(true);
        form_open.set(true);
    };
    let open_edit = move |p: Pool| {
        edit_id.set(p.id.clone());
        name.set(p.name.clone());
        subnet_v4.set(p.subnet_v4.clone().unwrap_or_default());
        start_v4.set(p.range_start_v4.clone().unwrap_or_default());
        end_v4.set(p.range_end_v4.clone().unwrap_or_default());
        gateway.set(p.gateway.clone().unwrap_or_default());
        dns_servers.set(p.dns_servers.join(", "));
        domain_name.set(p.domain_name.clone().unwrap_or_default());
        lease_secs.set(
            p.lease_duration_secs
                .map(|n| n.to_string())
                .unwrap_or_default(),
        );
        enabled.set(p.enabled);
        form_open.set(true);
    };

    let save = ServerAction::<SavePool>::new();
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
        let now = chrono::Utc::now();
        let servers: Vec<String> = dns_servers
            .get()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let pool = Pool {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            name: name.get(),
            subnet_v4: opt(subnet_v4.get()),
            range_start_v4: opt(start_v4.get()),
            range_end_v4: opt(end_v4.get()),
            subnet_v6: None,
            range_start_v6: None,
            range_end_v6: None,
            gateway: opt(gateway.get()),
            dns_servers: servers,
            domain_name: opt(domain_name.get()),
            lease_duration_secs: lease_secs.get().trim().parse::<u32>().ok(),
            enabled: enabled.get(),
        };
        save.dispatch(SavePool { pool });
    };

    let delete = ServerAction::<DeletePool>::new();
    let confirm_open = RwSignal::new(false);
    let delete_target = RwSignal::new(Option::<(String, String, u64)>::None);
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
    let request_delete = move |p: Pool| {
        spawn_local(async move {
            let count = count_pool_active_leases(p.id.clone()).await.unwrap_or(0);
            delete_target.set(Some((p.id, p.name, count)));
            confirm_open.set(true);
        });
    };
    let confirm_body = Signal::derive(move || match delete_target.get() {
        Some((_, n, c)) if c > 0 => {
            format!("有効なリースを持つプール「{n}」を削除します。よろしいですか？（有効リース {c} 件）")
        }
        Some((_, n, _)) => format!("プール「{n}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _, _)) = delete_target.get() {
            delete.dispatch(DeletePool { id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "DHCP プール".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <DhcpNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                pools.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "プールがありません。".to_string())/>
                    }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|p| {
                            let p_edit = p.clone();
                            let p_del = p.clone();
                            let health = if p.enabled { "healthy" } else { "unknown" };
                            let range = format!(
                                "{} - {}",
                                p.range_start_v4.clone().unwrap_or_default(),
                                p.range_end_v4.clone().unwrap_or_default(),
                            );
                            let res_href = format!("/dhcp/pools/{}/reservations", p.id);
                            view! {
                                <tr>
                                    <td><A href=res_href attr:class="link">{p.name.clone()}</A></td>
                                    <td>{p.subnet_v4.clone().unwrap_or_default()}</td>
                                    <td class="mono">{range}</td>
                                    <td>{p.gateway.clone().unwrap_or_default()}</td>
                                    <td><StatusBadge health=Signal::derive(move || health.to_string())/></td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="編集"
                                            on:click=move |_| open_edit(p_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除"
                                            on:click=move |_| request_delete(p_del.clone())>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr>
                                    <th>"名前"</th><th>"サブネット"</th><th>"範囲"</th><th>"GW"</th><th>"状態"</th><th>"操作"</th>
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
                        {move || if edit_id.get().is_empty() { "プールの作成" } else { "プールの編集" }}
                    </h2>
                    {text_field("プール名", name)}
                    {text_field("サブネット (CIDR)", subnet_v4)}
                    {text_field("範囲開始 IP", start_v4)}
                    {text_field("範囲終了 IP", end_v4)}
                    {text_field("ゲートウェイ", gateway)}
                    {text_field("DNS サーバー（カンマ区切り）", dns_servers)}
                    {text_field("ドメイン名", domain_name)}
                    {text_field("リース期間（秒・任意）", lease_secs)}
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

fn text_field(label: &'static str, sig: RwSignal<String>) -> impl IntoView {
    view! {
        <label class="field">
            <span class="field-label">{label}</span>
            <input class="input" prop:value=move || sig.get()
                on:input=move |ev| sig.set(event_target_value(&ev))/>
        </label>
    }
}
