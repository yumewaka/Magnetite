//! Watch host metrics view (S-WATCH-06). Reference-only. Charts render once a
//! metric collector is wired in; for now it shows the latest recorded samples.

use super::nav::WatchNav;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::watch::list_host_metrics;
use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use magnetite_core::domains::watch::model::Metric;

#[component]
pub fn MetricsPage() -> impl IntoView {
    let params = use_params_map();
    let host = Signal::derive(move || params.get().get("id").unwrap_or_default());
    let reload = RwSignal::new(0_u32);
    let metrics = Resource::new(
        move || (host.get(), reload.get()),
        |(h, _)| list_host_metrics(h),
    );

    view! {
        <PageHeader title=Signal::derive(move || format!("{} のメトリクス", host.get()))>
            <A href="/watch/hosts" attr:class="btn btn-secondary">"← ホストへ戻る"</A>
            <button class="btn btn-secondary" on:click=move |_| reload.update(|n| *n += 1)>"更新"</button>
        </PageHeader>
        <WatchNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                metrics.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "この期間のメトリクスはありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().rev().take(50).map(|m: Metric| {
                            let ts = m.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
                            view! {
                                <tr>
                                    <td class="mono">{ts}</td>
                                    <td class="mono">{m.name.clone()}</td>
                                    <td class="mono">{m.value}</td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"時刻"</th><th>"メトリクス"</th><th>"値"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>
    }
}
