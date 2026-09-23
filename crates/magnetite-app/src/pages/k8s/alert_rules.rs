//! K8s alert rule management (S-K8S-04). Inline enable/disable toggle.

use super::nav::K8sNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::k8s::{
    list_k8s_alert_rules, DeleteK8sAlertRule, SaveK8sAlertRule, ToggleK8sRule,
};
use leptos::prelude::*;
use magnetite_core::domains::k8s::model::{
    AlertConditionKind, AlertRule, AlertTargetKind, Comparator,
};
use magnetite_core::models::common::Severity;

#[component]
pub fn AlertRulesPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let rules = Resource::new(move || reload.get(), |_| list_k8s_alert_rules());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let target_ref = RwSignal::new(String::new());
    let condition = RwSignal::new("cpu".to_string());
    let comparator = RwSignal::new("gte".to_string());
    let threshold = RwSignal::new("80".to_string());
    let severity = RwSignal::new("warning".to_string());
    let enabled = RwSignal::new(true);

    let open_create = move |_| {
        edit_id.set(String::new());
        name.set(String::new());
        target_ref.set(String::new());
        condition.set("cpu".into());
        comparator.set("gte".into());
        threshold.set("80".into());
        severity.set("warning".into());
        enabled.set(true);
        form_open.set(true);
    };
    let open_edit = move |r: AlertRule| {
        edit_id.set(r.id.clone());
        name.set(r.name.clone());
        target_ref.set(r.target_ref.clone());
        condition.set(r.condition.as_str().into());
        comparator.set(r.comparator.as_str().into());
        threshold.set(r.threshold.to_string());
        severity.set(
            match r.severity {
                Severity::Critical => "critical",
                Severity::Info => "info",
                Severity::Warning => "warning",
            }
            .into(),
        );
        enabled.set(r.enabled);
        form_open.set(true);
    };

    let save = ServerAction::<SaveK8sAlertRule>::new();
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
        let rule = AlertRule {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            name: name.get(),
            target_ref: target_ref.get(),
            target_kind: AlertTargetKind::Cluster,
            condition: AlertConditionKind::from_str(&condition.get()),
            comparator: Comparator::from_str(&comparator.get()),
            threshold: threshold.get().trim().parse::<f64>().unwrap_or(0.0),
            severity: match severity.get().as_str() {
                "critical" => Severity::Critical,
                "info" => Severity::Info,
                _ => Severity::Warning,
            },
            enabled: enabled.get(),
        };
        save.dispatch(SaveK8sAlertRule { rule });
    };

    let toggle = ServerAction::<ToggleK8sRule>::new();
    Effect::new(move |_| {
        if let Some(Ok(())) = toggle.value().get() {
            toast.success("ルールを切り替えました。");
            reload.update(|n| *n += 1);
        }
    });

    let delete = ServerAction::<DeleteK8sAlertRule>::new();
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
            delete.dispatch(DeleteK8sAlertRule { id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "アラートルール".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 作成"</button>
        </PageHeader>
        <K8sNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                rules.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "アラートルールがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|r: AlertRule| {
                            let r_edit = r.clone();
                            let id_tog = r.id.clone();
                            let id_del = r.id.clone();
                            let name_del = r.name.clone();
                            let enabled = r.enabled;
                            let thr = format!("{} {} {}", r.condition.as_str(), r.comparator.as_str(), r.threshold);
                            view! {
                                <tr>
                                    <td>{r.name.clone()}</td>
                                    <td>{r.target_ref.clone()}</td>
                                    <td class="mono">{thr}</td>
                                    <td>
                                        <button class="btn btn-secondary btn-sm" role="switch" attr:aria-checked=move || enabled.to_string()
                                            on:click=move |_| { toggle.dispatch(ToggleK8sRule { id: id_tog.clone(), enabled: !enabled }); }>
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
                        view! { <table class="data-table"><thead><tr><th>"ルール名"</th><th>"対象"</th><th>"条件"</th><th>"有効"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">{move || if edit_id.get().is_empty() { "ルールの作成" } else { "ルールの編集" }}</h2>
                    <label class="field"><span class="field-label">"ルール名"</span><input class="input" prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"対象クラスタ名"</span><input class="input" prop:value=move || target_ref.get() on:input=move |ev| target_ref.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"種別"</span>
                        <select class="input" prop:value=move || condition.get() on:change=move |ev| condition.set(event_target_value(&ev))>
                            <option value="cpu">"CPU"</option><option value="memory">"メモリ"</option><option value="pod_restart">"Pod 再起動"</option><option value="node_not_ready">"ノード未準備"</option>
                        </select></label>
                    <label class="field"><span class="field-label">"比較"</span>
                        <select class="input" prop:value=move || comparator.get() on:change=move |ev| comparator.set(event_target_value(&ev))>
                            <option value="gt">">"</option><option value="gte">">="</option><option value="lt">"<"</option><option value="lte">"<="</option>
                        </select></label>
                    <label class="field"><span class="field-label">"閾値"</span><input class="input" type="number" prop:value=move || threshold.get() on:input=move |ev| threshold.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"重大度"</span>
                        <select class="input" prop:value=move || severity.get() on:change=move |ev| severity.set(event_target_value(&ev))>
                            <option value="critical">"Critical"</option><option value="warning">"Warning"</option><option value="info">"Info"</option>
                        </select></label>
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
