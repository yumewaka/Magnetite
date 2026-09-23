//! Watch rule management (S-WATCH-03) — the alert-generating rules.

use super::nav::WatchNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::watch::{
    list_watch_hosts, list_watch_rules, DeleteWatchRule, SaveWatchRule, ToggleWatchRule,
};
use leptos::prelude::*;
use magnetite_core::domains::watch::model::MonitorRule;
use magnetite_core::models::common::Severity;

const METRICS: [&str; 8] = [
    "cpu_percent",
    "memory_percent",
    "disk_percent",
    "net_rx",
    "net_tx",
    "process_missing",
    "port_down",
    "command_failed",
];

#[component]
pub fn WatchRulesPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let rules = Resource::new(move || reload.get(), |_| list_watch_rules());
    let hosts = Resource::new(|| (), |_| list_watch_hosts());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let target_host = RwSignal::new(String::new());
    let metric = RwSignal::new("cpu_percent".to_string());
    let warning = RwSignal::new(String::new());
    let critical = RwSignal::new(String::new());
    let severity = RwSignal::new("warning".to_string());
    let interval = RwSignal::new("60".to_string());
    let enabled = RwSignal::new(true);

    let open_create = move |_| {
        edit_id.set(String::new());
        name.set(String::new());
        target_host.set(String::new());
        metric.set("cpu_percent".into());
        warning.set(String::new());
        critical.set(String::new());
        severity.set("warning".into());
        interval.set("60".into());
        enabled.set(true);
        form_open.set(true);
    };
    let open_edit = move |r: MonitorRule| {
        edit_id.set(r.id.clone());
        name.set(r.name.clone());
        target_host.set(r.target_host.clone().unwrap_or_default());
        metric.set(r.metric.clone());
        warning.set(
            r.warning_threshold
                .map(|v| v.to_string())
                .unwrap_or_default(),
        );
        critical.set(
            r.critical_threshold
                .map(|v| v.to_string())
                .unwrap_or_default(),
        );
        severity.set(
            match r.severity {
                Severity::Critical => "critical",
                Severity::Info => "info",
                Severity::Warning => "warning",
            }
            .into(),
        );
        interval.set(r.eval_interval_secs.to_string());
        enabled.set(r.enabled);
        form_open.set(true);
    };

    let save = ServerAction::<SaveWatchRule>::new();
    let save_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = save.value().get() {
            match result {
                Ok(()) => {
                    save_error.set(None);
                    form_open.set(false);
                    toast.success("保存しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => save_error.set(Some(e.to_string())),
            }
        }
    });
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let now = chrono::Utc::now();
        let th = target_host.get();
        let rule = MonitorRule {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            name: name.get(),
            target_host: if th.trim().is_empty() { None } else { Some(th) },
            metric: metric.get(),
            warning_threshold: warning.get().trim().parse::<f64>().ok(),
            critical_threshold: critical.get().trim().parse::<f64>().ok(),
            severity: match severity.get().as_str() {
                "critical" => Severity::Critical,
                "info" => Severity::Info,
                _ => Severity::Warning,
            },
            eval_interval_secs: interval.get().trim().parse::<u32>().unwrap_or(60),
            enabled: enabled.get(),
        };
        save.dispatch(SaveWatchRule { rule });
    };

    let toggle = ServerAction::<ToggleWatchRule>::new();
    Effect::new(move |_| {
        if let Some(Ok(())) = toggle.value().get() {
            toast.success("更新しました。");
            reload.update(|n| *n += 1);
        }
    });

    let delete = ServerAction::<DeleteWatchRule>::new();
    let confirm_open = RwSignal::new(false);
    let delete_target = RwSignal::new(Option::<(String, String)>::None);
    Effect::new(move |_| {
        if let Some(Ok(())) = delete.value().get() {
            toast.success("削除しました。");
            reload.update(|n| *n += 1);
        }
    });
    Effect::new(move |_| {
        if !confirm_open.get() {
            delete_target.set(None);
        }
    });
    let confirm_body = Signal::derive(move || match delete_target.get() {
        Some((_, n)) => format!("ルール「{n}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = delete_target.get() {
            delete.dispatch(DeleteWatchRule { id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "監視ルール".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <WatchNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                rules.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "監視ルールがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|r: MonitorRule| {
                            let r_edit = r.clone();
                            let id_tog = r.id.clone();
                            let id_del = r.id.clone();
                            let name_del = r.name.clone();
                            let enabled = r.enabled;
                            let target = r.target_host.clone().unwrap_or_else(|| "(全体)".into());
                            let w = r.warning_threshold.map(|v| v.to_string()).unwrap_or_default();
                            let c = r.critical_threshold.map(|v| v.to_string()).unwrap_or_default();
                            view! {
                                <tr>
                                    <td>{r.name.clone()}</td>
                                    <td>{target}</td>
                                    <td class="mono">{r.metric.clone()}</td>
                                    <td>{w}</td>
                                    <td>{c}</td>
                                    <td>
                                        <button class="btn btn-secondary btn-sm" role="switch" attr:aria-checked=move || enabled.to_string()
                                            on:click=move |_| { toggle.dispatch(ToggleWatchRule { id: id_tog.clone(), enabled: !enabled }); }>
                                            {if enabled { "有効" } else { "無効" }}
                                        </button>
                                    </td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="編集" on:click=move |_| open_edit(r_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_del.clone(), name_del.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"名前"</th><th>"対象ホスト"</th><th>"メトリクス"</th><th>"警告"</th><th>"危険"</th><th>"有効"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">{move || if edit_id.get().is_empty() { "ルールの作成" } else { "ルールの編集" }}</h2>
                    <label class="field"><span class="field-label">"ルール名"</span><input class="input" prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"対象ホスト"</span>
                        <select class="input" prop:value=move || target_host.get() on:change=move |ev| target_host.set(event_target_value(&ev))>
                            <option value="">"(全体)"</option>
                            <Suspense fallback=|| ()>
                                {move || hosts.get().map(|res| res.unwrap_or_default().into_iter().map(|h| { let n = h.name.clone(); view! { <option value=h.name>{n}</option> } }).collect_view())}
                            </Suspense>
                        </select></label>
                    <label class="field"><span class="field-label">"メトリクス"</span>
                        <select class="input" prop:value=move || metric.get() on:change=move |ev| metric.set(event_target_value(&ev))>
                            {METRICS.into_iter().map(|m| view! { <option value=m>{m}</option> }).collect_view()}
                        </select></label>
                    <label class="field"><span class="field-label">"警告閾値"</span><input class="input" type="number" prop:value=move || warning.get() on:input=move |ev| warning.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"危険閾値"</span><input class="input" type="number" prop:value=move || critical.get() on:input=move |ev| critical.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"重大度"</span>
                        <select class="input" prop:value=move || severity.get() on:change=move |ev| severity.set(event_target_value(&ev))>
                            <option value="critical">"Critical"</option><option value="warning">"Warning"</option><option value="info">"Info"</option>
                        </select></label>
                    <label class="field"><span class="field-label">"評価間隔（秒）"</span><input class="input" type="number" prop:value=move || interval.get() on:input=move |ev| interval.set(event_target_value(&ev))/></label>
                    <label class="field field-inline"><input type="checkbox" prop:checked=move || enabled.get() on:change=move |ev| enabled.set(event_target_checked(&ev))/><span>"有効"</span></label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || save.pending().get()>"保存"</button>
                    </div>
                </form>
            </div>
        </Show>

        <ConfirmDialog title=Signal::derive(|| "削除の確認".to_string()) body=confirm_body open=confirm_open on_confirm=on_confirm_delete/>
    }
}
