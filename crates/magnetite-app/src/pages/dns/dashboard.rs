//! DNS dashboard (S-DNS-01): zone/record counts. Live query metrics arrive
//! with daemon integration; Phase-1 shows the DB-derived counts.

use super::nav::DnsNav;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::dns::get_dns_metrics;
use leptos::prelude::*;

#[component]
pub fn DnsDashboard() -> impl IntoView {
    let metrics = Resource::new(|| (), |_| get_dns_metrics());
    let reload = Callback::new(move |_| metrics.refetch());

    view! {
        <PageHeader title=Signal::derive(|| "DNS ダッシュボード".to_string())>
            <button class="btn btn-secondary" on:click=move |_| metrics.refetch()>"更新"</button>
        </PageHeader>
        <DnsNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                metrics.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=reload/> }.into_any(),
                    Ok(m) => view! {
                        <div class="dashboard-grid">
                            <div class="stat-card">
                                <span class="stat-value">{m.zone_count}</span>
                                <span class="stat-label">"ゾーン数"</span>
                            </div>
                            <div class="stat-card">
                                <span class="stat-value">{m.record_count}</span>
                                <span class="stat-label">"レコード数"</span>
                            </div>
                        </div>
                    }
                    .into_any(),
                })
            }}
        </Suspense>
    }
}
