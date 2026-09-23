//! Mail dashboard (S-MAIL-01): user/domain/list counts and used storage.

use super::nav::MailNav;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::mail::get_mail_metrics;
use leptos::prelude::*;

fn format_gb(bytes: u64) -> String {
    let gb = bytes as f64 / 1_073_741_824.0;
    format!("{gb:.2} GB")
}

#[component]
pub fn MailDashboard() -> impl IntoView {
    let metrics = Resource::new(|| (), |_| get_mail_metrics());
    let reload = Callback::new(move |_| metrics.refetch());

    view! {
        <PageHeader title=Signal::derive(|| "Mail ダッシュボード".to_string())>
            <button class="btn btn-secondary" on:click=move |_| metrics.refetch()>"更新"</button>
        </PageHeader>
        <MailNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                metrics.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=reload/> }.into_any(),
                    Ok(m) => {
                        let used = format_gb(m.used_bytes);
                        view! {
                            <div class="dashboard-grid">
                                <div class="stat-card"><span class="stat-value">{m.user_count}</span><span class="stat-label">"ユーザ数"</span></div>
                                <div class="stat-card"><span class="stat-value">{m.domain_count}</span><span class="stat-label">"ドメイン数"</span></div>
                                <div class="stat-card"><span class="stat-value">{m.list_count}</span><span class="stat-label">"リスト数"</span></div>
                                <div class="stat-card"><span class="stat-value">{used}</span><span class="stat-label">"使用容量"</span></div>
                            </div>
                        }
                        .into_any()
                    }
                })
            }}
        </Suspense>
    }
}
