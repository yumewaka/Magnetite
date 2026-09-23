//! DHCP dashboard (S-DHCP-01): pool / reservation / active-lease counts.

use super::nav::DhcpNav;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::dhcp::get_dhcp_metrics;
use leptos::prelude::*;

#[component]
pub fn DhcpDashboard() -> impl IntoView {
    let metrics = Resource::new(|| (), |_| get_dhcp_metrics());
    let reload = Callback::new(move |_| metrics.refetch());

    view! {
        <PageHeader title=Signal::derive(|| "DHCP ダッシュボード".to_string())>
            <button class="btn btn-secondary" on:click=move |_| metrics.refetch()>"更新"</button>
        </PageHeader>
        <DhcpNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                metrics.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=reload/> }.into_any(),
                    Ok(m) => view! {
                        <div class="dashboard-grid">
                            <div class="stat-card">
                                <span class="stat-value">{m.pool_count}</span>
                                <span class="stat-label">"プール数"</span>
                            </div>
                            <div class="stat-card">
                                <span class="stat-value">{m.active_lease_count}</span>
                                <span class="stat-label">"アクティブリース"</span>
                            </div>
                            <div class="stat-card">
                                <span class="stat-value">{m.reservation_count}</span>
                                <span class="stat-label">"予約数"</span>
                            </div>
                        </div>
                    }
                    .into_any(),
                })
            }}
        </Suspense>
    }
}
