//! Cross-cutting audit log viewer (S-Audit / F-04 / AC-07). Read-only: filter by
//! period / domain / action / actor, expand a row for IP and change detail, and
//! page through the results. No mutation UI (the log is append-only).

use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use chrono::{Duration, NaiveDate, TimeZone, Utc};
use leptos::prelude::*;
use magnetite_core::domain::DomainKey;
use magnetite_core::i18n::use_i18n;
use magnetite_core::models::common::ActionKind;
use magnetite_core::models::{AuditEntry, OpResult};

use crate::server_fns::audit::query_audit_log;

const PER_PAGE: usize = 50;

/// Japanese label for an audited action kind (screen_audit §1).
fn action_label(action: ActionKind) -> &'static str {
    match action {
        ActionKind::Create => "作成",
        ActionKind::Update => "更新",
        ActionKind::Delete => "削除",
        ActionKind::Control => "制御",
        ActionKind::Login => "ログイン",
        ActionKind::Logout => "ログアウト",
        ActionKind::Restore => "復元",
    }
}

/// Convert a `YYYY-MM-DD` string into an RFC3339 UTC bound, or empty on failure.
fn day_bound(day: &str, end: bool) -> String {
    let (h, m, s) = if end { (23, 59, 59) } else { (0, 0, 0) };
    NaiveDate::parse_from_str(day, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(h, m, s))
        .map(|ndt| Utc.from_utc_datetime(&ndt).to_rfc3339())
        .unwrap_or_default()
}

/// Resolve the active period selection into inclusive RFC3339 bounds. An empty
/// bound means unbounded on that side.
fn compute_bounds(period: &str, custom_from: &str, custom_to: &str) -> (String, String) {
    let now = Utc::now();
    match period {
        "24h" => ((now - Duration::hours(24)).to_rfc3339(), String::new()),
        "today" => {
            let start = now
                .date_naive()
                .and_hms_opt(0, 0, 0)
                .map(|ndt| Utc.from_utc_datetime(&ndt).to_rfc3339())
                .unwrap_or_default();
            (start, String::new())
        }
        "7d" => ((now - Duration::days(7)).to_rfc3339(), String::new()),
        "30d" => ((now - Duration::days(30)).to_rfc3339(), String::new()),
        "custom" => (day_bound(custom_from, false), day_bound(custom_to, true)),
        _ => (String::new(), String::new()),
    }
}

#[component]
pub fn AuditPage() -> impl IntoView {
    let i18n = use_i18n();

    let period = RwSignal::new("24h".to_string());
    let custom_from = RwSignal::new(String::new());
    let custom_to = RwSignal::new(String::new());
    let fdomain = RwSignal::new(String::new());
    let faction = RwSignal::new(String::new());
    let factor = RwSignal::new(String::new());
    let descending = RwSignal::new(true);
    let page = RwSignal::new(0_usize);
    let expanded = RwSignal::new(Option::<String>::None);

    // Any filter change returns to the first page (E-01).
    let reset = move || {
        page.set(0);
        expanded.set(None);
    };

    // Custom range validation (§5): start must not be after end.
    let range_error = Signal::derive(move || {
        if period.get() == "custom" {
            let (f, t) = (custom_from.get(), custom_to.get());
            if !f.is_empty() && !t.is_empty() && f > t {
                return Some("開始日は終了日より前にしてください。".to_string());
            }
        }
        None
    });

    let query = Resource::new(
        move || {
            (
                fdomain.get(),
                faction.get(),
                factor.get(),
                period.get(),
                custom_from.get(),
                custom_to.get(),
                descending.get(),
                page.get(),
            )
        },
        |(domain, action, actor, period, cf, ct, descending, page)| async move {
            let (from, to) = compute_bounds(&period, &cf, &ct);
            query_audit_log(domain, action, actor, from, to, descending, page, PER_PAGE).await
        },
    );

    let toggle_sort = move |_| {
        descending.update(|d| *d = !*d);
        reset();
    };

    view! {
        <PageHeader title=Signal::derive(|| "監査ログ".to_string())/>

        <div class="audit-filters">
            <label class="filter">
                <span class="filter-label">"期間"</span>
                <select class="input" prop:value=move || period.get()
                    on:change=move |ev| { period.set(event_target_value(&ev)); reset(); }>
                    <option value="24h">"直近24時間"</option>
                    <option value="today">"今日"</option>
                    <option value="7d">"7日間"</option>
                    <option value="30d">"30日間"</option>
                    <option value="all">"全期間"</option>
                    <option value="custom">"カスタム"</option>
                </select>
            </label>
            <Show when=move || period.get() == "custom" fallback=|| ()>
                <label class="filter">
                    <span class="filter-label">"開始"</span>
                    <input class="input" type="date" prop:value=move || custom_from.get()
                        on:change=move |ev| { custom_from.set(event_target_value(&ev)); reset(); }/>
                </label>
                <label class="filter">
                    <span class="filter-label">"終了"</span>
                    <input class="input" type="date" prop:value=move || custom_to.get()
                        on:change=move |ev| { custom_to.set(event_target_value(&ev)); reset(); }/>
                </label>
            </Show>
            <label class="filter">
                <span class="filter-label">"ドメイン"</span>
                <select class="input" prop:value=move || fdomain.get()
                    on:change=move |ev| { fdomain.set(event_target_value(&ev)); reset(); }>
                    <option value="">"全ドメイン"</option>
                    {DomainKey::DOMAINS.iter().chain(std::iter::once(&DomainKey::Portal)).map(|d| {
                        let value = d.as_str();
                        let label = i18n.t(d.label_key());
                        view! { <option value=value>{label}</option> }
                    }).collect_view()}
                </select>
            </label>
            <label class="filter">
                <span class="filter-label">"操作種別"</span>
                <select class="input" prop:value=move || faction.get()
                    on:change=move |ev| { faction.set(event_target_value(&ev)); reset(); }>
                    <option value="">"全種別"</option>
                    <option value="create">"作成"</option>
                    <option value="update">"更新"</option>
                    <option value="delete">"削除"</option>
                    <option value="control">"制御"</option>
                    <option value="login">"ログイン"</option>
                    <option value="logout">"ログアウト"</option>
                    <option value="restore">"復元"</option>
                </select>
            </label>
            <label class="filter">
                <span class="filter-label">"実行者"</span>
                <input class="input" type="text" placeholder="ユーザ名" prop:value=move || factor.get()
                    on:change=move |ev| { factor.set(event_target_value(&ev)); reset(); }/>
            </label>
        </div>
        {move || range_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}

        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                query.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| query.refetch())/> }.into_any(),
                    Ok(pageset) if pageset.entries.is_empty() => {
                        view! { <EmptyState message=Signal::derive(|| "条件に一致する監査ログはありません。".to_string())/> }.into_any()
                    }
                    Ok(pageset) => {
                        let total = pageset.total;
                        let sort_indicator = if descending.get() { " ▾" } else { " ▴" };
                        let rows = pageset.entries.into_iter().map(|e: AuditEntry| {
                            let id_open = e.id.clone();
                            let is_open = { let id = e.id.clone(); move || expanded.get().as_deref() == Some(id.as_str()) };
                            let at = e.at.format("%Y-%m-%d %H:%M:%S").to_string();
                            let domain_label = i18n.t(e.domain.label_key());
                            let action = action_label(e.action);
                            let target = if e.target_id.is_empty() { e.target_kind.clone() } else { format!("{}:{}", e.target_kind, e.target_id) };
                            let (result_label, result_class) = match e.result {
                                OpResult::Success => ("成功", "badge badge-success"),
                                OpResult::Failure => ("失敗", "badge badge-danger"),
                            };
                            let ip = e.ip.clone();
                            let detail = e.detail.as_ref().map(|d| d.to_string());
                            let target_detail = target.clone();
                            let is_open_detail = is_open.clone();
                            view! {
                                <tr class="audit-row" on:click=move |_| {
                                    expanded.update(|cur| {
                                        if cur.as_deref() == Some(id_open.as_str()) { *cur = None; } else { *cur = Some(id_open.clone()); }
                                    });
                                }>
                                    <td class="mono">{at}</td>
                                    <td>{e.actor.clone()}</td>
                                    <td>{domain_label}</td>
                                    <td>{action}</td>
                                    <td class="mono">{target}</td>
                                    <td><span class=result_class>{result_label}</span></td>
                                    <td class="expand-caret">{move || if is_open() { "▾" } else { "▸" }}</td>
                                </tr>
                                <Show when=is_open_detail.clone() fallback=|| ()>
                                    <tr class="audit-detail-row">
                                        <td colspan="7">
                                            <dl class="audit-detail">
                                                <dt>"IP"</dt><dd class="mono">{ip.clone()}</dd>
                                                <dt>"対象"</dt><dd class="mono">{target_detail.clone()}</dd>
                                                {detail.clone().map(|d| view! { <dt>"詳細"</dt><dd class="mono audit-detail-json">{d}</dd> })}
                                            </dl>
                                        </td>
                                    </tr>
                                </Show>
                            }
                        }).collect_view();

                        let start = page.get() * PER_PAGE;
                        let shown_from = if total == 0 { 0 } else { start + 1 };
                        let shown_to = (start + PER_PAGE).min(total);
                        let has_prev = move || page.get() > 0;
                        let has_next = move || (page.get() + 1) * PER_PAGE < total;
                        view! {
                            <table class="data-table audit-table">
                                <thead><tr>
                                    <th class="sortable" on:click=toggle_sort>{format!("日時{sort_indicator}")}</th>
                                    <th>"実行者"</th>
                                    <th>"ドメイン"</th>
                                    <th>"操作"</th>
                                    <th>"対象"</th>
                                    <th>"結果"</th>
                                    <th></th>
                                </tr></thead>
                                <tbody>{rows}</tbody>
                            </table>
                            <div class="pagination">
                                <span class="pagination-info">{format!("{shown_from}–{shown_to} / {total} 件")}</span>
                                <div class="pagination-actions">
                                    <button class="btn btn-secondary btn-sm" prop:disabled=move || !has_prev()
                                        on:click=move |_| { page.update(|p| *p = p.saturating_sub(1)); expanded.set(None); }>"前へ"</button>
                                    <button class="btn btn-secondary btn-sm" prop:disabled=move || !has_next()
                                        on:click=move |_| { page.update(|p| *p += 1); expanded.set(None); }>"次へ"</button>
                                </div>
                            </div>
                        }.into_any()
                    }
                })
            }}
        </Suspense>
    }
}
