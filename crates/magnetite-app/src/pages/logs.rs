//! Integrated log viewer (S-Logs / F-08, read-only). Filters by domain / kind /
//! level, optional follow (追尾) that periodically re-fetches, and a client-side
//! search box that filters the visible lines and highlights matches.
//!
//! TODO(ingestion): the `log` table is empty until log ingestion is wired
//! (magnetite-db `append_log`), so this view shows its empty state for now.

use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::logs::query_logs;
use leptos::prelude::*;
use magnetite_core::domain::DomainKey;
use magnetite_core::i18n::use_i18n;
use magnetite_core::models::common::{LogKind, LogLevel};
use magnetite_core::models::LogEntry;
use std::time::Duration;

fn level_meta(level: LogLevel) -> (&'static str, &'static str) {
    match level {
        LogLevel::Debug => ("DEBUG", "badge badge-unknown"),
        LogLevel::Info => ("INFO", "badge badge-success"),
        LogLevel::Warn => ("WARN", "badge badge-warning"),
        LogLevel::Error => ("ERROR", "badge badge-danger"),
    }
}
fn kind_label(kind: LogKind) -> &'static str {
    match kind {
        LogKind::Operation => "動作",
        LogKind::Query => "クエリ",
        LogKind::Access => "アクセス",
    }
}
fn domain_label(key: DomainKey, i18n: magnetite_core::i18n::I18nContext) -> String {
    if key == DomainKey::Portal {
        "システム".to_string()
    } else {
        i18n.t(key.label_key()).to_string()
    }
}

/// Split `message` around case-insensitive matches of `needle`, wrapping hits
/// in `<mark>` (E-03 highlight). An empty needle returns the text unchanged.
fn highlight(message: &str, needle: &str) -> Vec<AnyView> {
    if needle.is_empty() {
        return vec![message.to_string().into_any()];
    }
    let lower = message.to_lowercase();
    let n = needle.to_lowercase();
    let mut parts: Vec<AnyView> = Vec::new();
    let mut start = 0;
    while let Some(rel) = lower[start..].find(&n) {
        let abs = start + rel;
        if abs > start {
            parts.push(message[start..abs].to_string().into_any());
        }
        let end = abs + n.len();
        parts.push(view! { <mark>{message[abs..end].to_string()}</mark> }.into_any());
        start = end;
    }
    parts.push(message[start..].to_string().into_any());
    parts
}

#[component]
pub fn LogsPage() -> impl IntoView {
    let i18n = use_i18n();
    let reload = RwSignal::new(0_u32);
    let fdomain = RwSignal::new(String::new());
    let fkind = RwSignal::new("operation".to_string());
    let flevel = RwSignal::new(String::new());
    let search = RwSignal::new(String::new());
    let tail = RwSignal::new(false);
    let expanded = RwSignal::new(Option::<String>::None);

    let logs = Resource::new(
        move || (reload.get(), fdomain.get(), fkind.get(), flevel.get()),
        |(_, domain, kind, level)| query_logs(domain, kind, level),
    );

    // Follow (追尾): while on, re-fetch every few seconds (E-02). The effect
    // clears the previous interval when toggled and runs client-side only.
    Effect::new(move |prev: Option<Option<IntervalHandle>>| {
        if let Some(Some(handle)) = prev {
            handle.clear();
        }
        if tail.get() {
            set_interval_with_handle(move || reload.update(|n| *n += 1), Duration::from_secs(3))
                .ok()
        } else {
            None
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "統合ログ".to_string())/>

        <div class="audit-filters">
            <label class="filter">
                <span class="filter-label">"ドメイン"</span>
                <select class="input" prop:value=move || fdomain.get() on:change=move |ev| fdomain.set(event_target_value(&ev))>
                    <option value="">"全ドメイン"</option>
                    {DomainKey::DOMAINS.iter().map(|d| {
                        let value = d.as_str();
                        let label = i18n.t(d.label_key());
                        view! { <option value=value>{label}</option> }
                    }).collect_view()}
                    <option value="portal">"システム"</option>
                </select>
            </label>
            <label class="filter">
                <span class="filter-label">"ログ種別"</span>
                <select class="input" prop:value=move || fkind.get() on:change=move |ev| fkind.set(event_target_value(&ev))>
                    <option value="">"全種別"</option>
                    <option value="operation">"動作"</option>
                    <option value="query">"クエリ"</option>
                    <option value="access">"アクセス"</option>
                </select>
            </label>
            <label class="filter">
                <span class="filter-label">"レベル"</span>
                <select class="input" prop:value=move || flevel.get() on:change=move |ev| flevel.set(event_target_value(&ev))>
                    <option value="">"全レベル"</option>
                    <option value="DEBUG">"DEBUG"</option>
                    <option value="INFO">"INFO"</option>
                    <option value="WARN">"WARN"</option>
                    <option value="ERROR">"ERROR"</option>
                </select>
            </label>
            <label class="filter">
                <span class="filter-label">"検索"</span>
                <input class="input" type="search" placeholder="メッセージ" prop:value=move || search.get()
                    on:input=move |ev| search.set(event_target_value(&ev))/>
            </label>
            <label class="filter toggle-row follow-toggle">
                <input type="checkbox" prop:checked=move || tail.get() on:change=move |ev| tail.set(event_target_checked(&ev))/>
                <span>"追尾"</span>
            </label>
        </div>

        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                let needle = search.get();
                logs.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) => {
                        let filtered: Vec<LogEntry> = list
                            .into_iter()
                            .filter(|l| needle.is_empty() || l.message.to_lowercase().contains(&needle.to_lowercase()))
                            .collect();
                        if filtered.is_empty() {
                            return view! { <EmptyState message=Signal::derive(|| "表示できるログがありません。".to_string())/> }.into_any();
                        }
                        let needle_row = needle.clone();
                        let rows = filtered.into_iter().map(|l: LogEntry| {
                            let id_open = l.id.clone();
                            let is_open = { let id = l.id.clone(); move || expanded.get().as_deref() == Some(id.as_str()) };
                            let is_detail = is_open.clone();
                            let at = l.at.format("%m-%d %H:%M:%S").to_string();
                            let (lvl, lvl_class) = level_meta(l.level);
                            let dom = domain_label(l.domain, i18n);
                            let kind = kind_label(l.log_kind);
                            let msg_parts = highlight(&l.message, &needle_row);
                            let meta = l.meta.as_ref().map(|m| m.to_string());
                            let full_msg = l.message.clone();
                            view! {
                                <tr class="log-row" on:click=move |_| {
                                    expanded.update(|cur| {
                                        if cur.as_deref() == Some(id_open.as_str()) { *cur = None; } else { *cur = Some(id_open.clone()); }
                                    });
                                }>
                                    <td class="mono">{at}</td>
                                    <td><span class=lvl_class>{lvl}</span></td>
                                    <td>{dom}</td>
                                    <td>{kind}</td>
                                    <td class="log-message">{msg_parts}</td>
                                </tr>
                                <Show when=is_detail.clone() fallback=|| ()>
                                    <tr class="audit-detail-row">
                                        <td colspan="5">
                                            <dl class="audit-detail">
                                                <dt>"メッセージ"</dt><dd>{full_msg.clone()}</dd>
                                                {meta.clone().map(|m| view! { <dt>"メタ"</dt><dd class="mono audit-detail-json">{m}</dd> })}
                                            </dl>
                                        </td>
                                    </tr>
                                </Show>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table log-table">
                                <thead><tr><th>"時刻"</th><th>"レベル"</th><th>"ドメイン"</th><th>"種別"</th><th>"メッセージ"</th></tr></thead>
                                <tbody>{rows}</tbody>
                            </table>
                        }.into_any()
                    }
                })
            }}
        </Suspense>
    }
}
