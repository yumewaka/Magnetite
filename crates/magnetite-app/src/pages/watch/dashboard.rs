//! Watch dashboard (S-WATCH-01): host status summary and rule count.

use super::nav::WatchNav;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::watch::get_watch_metrics;
use leptos::prelude::*;

#[component]
pub fn WatchDashboard() -> impl IntoView {
    let metrics = Resource::new(|| (), |_| get_watch_metrics());
    let reload = Callback::new(move |_| metrics.refetch());

    view! {
        <PageHeader title=Signal::derive(|| "監視 ダッシュボード".to_string())>
            <button class="btn btn-secondary" on:click=move |_| metrics.refetch()>"更新"</button>
        </PageHeader>
        <WatchNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                metrics.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=reload/> }.into_any(),
                    Ok(m) => view! {
                        <div class="dashboard-grid">
                            <div class="stat-card"><span class="stat-value">{m.host_total}</span><span class="stat-label">"ホスト総数"</span></div>
                            <div class="stat-card"><span class="stat-value">{m.online}</span><span class="stat-label">"オンライン"</span></div>
                            <div class="stat-card"><span class="stat-value">{m.offline}</span><span class="stat-label">"オフライン"</span></div>
                            <div class="stat-card"><span class="stat-value">{m.warning}</span><span class="stat-label">"警告"</span></div>
                            <div class="stat-card"><span class="stat-value">{m.rule_count}</span><span class="stat-label">"監視ルール数"</span></div>
                        </div>
                    }.into_any(),
                })
            }}
        </Suspense>
    }
}
