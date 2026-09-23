//! DHCP lease list + release (S-DHCP-04). Release is enabled only for
//! active/offered leases (08_dhcp_logic §4.2).

use super::nav::DhcpNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::dhcp::{list_leases, ReleaseLease};
use leptos::prelude::*;
use magnetite_core::domains::dhcp::model::{Lease, LeaseState};

fn lease_health(state: LeaseState) -> &'static str {
    match state {
        LeaseState::Active => "healthy",
        LeaseState::Offered => "warning",
        LeaseState::Expired | LeaseState::Released => "unknown",
    }
}

#[component]
pub fn LeasesPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let leases = Resource::new(move || reload.get(), |_| list_leases(None));

    let release = ServerAction::<ReleaseLease>::new();
    let confirm_open = RwSignal::new(false);
    let target = RwSignal::new(Option::<(String, String)>::None);
    Effect::new(move |_| {
        if let Some(Ok(())) = release.value().get() {
            toast.success("リースを解放しました。");
            reload.update(|n| *n += 1);
        }
    });
    Effect::new(move |_| {
        if !confirm_open.get() {
            target.set(None);
        }
    });
    let confirm_body = Signal::derive(move || match target.get() {
        Some((_, ip)) => format!("IP {ip} のリースを解放します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm = Callback::new(move |_| {
        if let Some((id, _)) = target.get() {
            release.dispatch(ReleaseLease { id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "DHCP リース".to_string())>
            <button class="btn btn-secondary" on:click=move |_| reload.update(|n| *n += 1)>"更新"</button>
        </PageHeader>
        <DhcpNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                leases.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "該当するリースはありません。".to_string())/>
                    }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|l: Lease| {
                            let health = lease_health(l.state);
                            let releasable = l.state.is_releasable();
                            let id = l.id.clone();
                            let ip = l.ip_address.clone();
                            let expiry = l.lease_expiry.format("%Y-%m-%d %H:%M").to_string();
                            view! {
                                <tr>
                                    <td class="mono">{l.ip_address.clone()}</td>
                                    <td>{l.hostname.clone().unwrap_or_default()}</td>
                                    <td><StatusBadge health=Signal::derive(move || health.to_string())/></td>
                                    <td class="mono">{expiry}</td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm"
                                            prop:disabled=!releasable
                                            on:click=move |_| {
                                                target.set(Some((id.clone(), ip.clone())));
                                                confirm_open.set(true);
                                            }>"解放"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr>
                                    <th>"IP"</th><th>"ホスト名"</th><th>"状態"</th><th>"有効期限"</th><th>"操作"</th>
                                </tr></thead>
                                <tbody>{rows}</tbody>
                            </table>
                        }.into_any()
                    }
                })
            }}
        </Suspense>

        <ConfirmDialog
            title=Signal::derive(|| "リース解放の確認".to_string())
            body=confirm_body
            open=confirm_open
            on_confirm=on_confirm
        />
    }
}
