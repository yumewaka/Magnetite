//! DNS query logs (S-DNS query-logs). A DNS-scoped view of the shared `log`
//! table, populated by the embedded DNS server (Phase E1d). The cross-cutting
//! viewer is S-Logs; this is the domain-local shortcut.

use super::nav::DnsNav;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::logs::query_logs;
use leptos::prelude::*;
use magnetite_core::models::common::LogLevel;
use magnetite_core::models::LogEntry;

fn level_meta(level: LogLevel) -> (&'static str, &'static str) {
    match level {
        LogLevel::Debug => ("DEBUG", "badge badge-unknown"),
        LogLevel::Info => ("INFO", "badge badge-success"),
        LogLevel::Warn => ("WARN", "badge badge-warning"),
        LogLevel::Error => ("ERROR", "badge badge-danger"),
    }
}

#[component]
pub fn QueryLogsPage() -> impl IntoView {
    let reload = RwSignal::new(0_u32);
    // Fixed filter: DNS domain, query kind.
    let logs = Resource::new(
        move || reload.get(),
        |_| query_logs("dns".to_string(), "query".to_string(), String::new()),
    );

    view! {
        <PageHeader title=Signal::derive(|| "DNS クエリログ".to_string())/>
        <DnsNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || logs.get().map(|res| match res {
                Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "クエリログはまだありません。".to_string())/> }.into_any(),
                Ok(list) => {
                    let rows = list.into_iter().map(|l: LogEntry| {
                        let at = l.at.format("%m-%d %H:%M:%S").to_string();
                        let (lvl, lvl_class) = level_meta(l.level);
                        view! {
                            <tr>
                                <td class="mono">{at}</td>
                                <td><span class=lvl_class>{lvl}</span></td>
                                <td class="log-message">{l.message}</td>
                            </tr>
                        }
                    }).collect_view();
                    view! {
                        <table class="data-table log-table">
                            <thead><tr><th>"時刻"</th><th>"レベル"</th><th>"メッセージ"</th></tr></thead>
                            <tbody>{rows}</tbody>
                        </table>
                    }.into_any()
                }
            })}
        </Suspense>
    }
}
