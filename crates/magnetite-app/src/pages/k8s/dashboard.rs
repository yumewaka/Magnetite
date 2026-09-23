//! K8s dashboard (S-K8S-01): cluster / host / rule counts.

use super::nav::K8sNav;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::k8s::get_k8s_metrics;
use leptos::prelude::*;

#[component]
pub fn K8sDashboard() -> impl IntoView {
    let metrics = Resource::new(|| (), |_| get_k8s_metrics());
    let reload = Callback::new(move |_| metrics.refetch());

    view! {
        <PageHeader title=Signal::derive(|| "Kubernetes ダッシュボード".to_string())>
            <button class="btn btn-secondary" on:click=move |_| metrics.refetch()>"更新"</button>
        </PageHeader>
        <K8sNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                metrics.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=reload/> }.into_any(),
                    Ok(m) => view! {
                        <div class="dashboard-grid">
                            <div class="stat-card"><span class="stat-value">{m.cluster_count}</span><span class="stat-label">"クラスタ数"</span></div>
                            <div class="stat-card"><span class="stat-value">{m.host_count}</span><span class="stat-label">"ホスト数"</span></div>
                            <div class="stat-card"><span class="stat-value">{m.rule_count}</span><span class="stat-label">"アラートルール数"</span></div>
                        </div>
                    }.into_any(),
                })
            }}
        </Suspense>
    }
}
