//! Cross-cutting alerts & notification settings (S-Alerts / F-05). Two tabs:
//! the alert list (filter / acknowledge / resolve, single & bulk) and
//! notification-target CRUD. Listing is Viewer+; state changes are Operator+
//! (Viewer sees the action buttons disabled, AC-04).

use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::alert::{
    list_alerts, list_notification_targets, AcknowledgeAlerts, CreateNotificationTarget,
    DeleteNotificationTarget, ResolveAlerts, SetNotificationTargetEnabled,
};
use crate::server_fns::auth::get_current_user;
use leptos::prelude::*;
use magnetite_core::authz::Role;
use magnetite_core::domain::DomainKey;
use magnetite_core::i18n::use_i18n;
use magnetite_core::models::common::{AlertState, NotifyKind, Severity};
use magnetite_core::models::{Alert, NotificationTarget};

fn severity_meta(s: Severity) -> (&'static str, &'static str) {
    match s {
        Severity::Critical => ("重大", "badge badge-danger"),
        Severity::Warning => ("警告", "badge badge-warning"),
        Severity::Info => ("情報", "badge badge-unknown"),
    }
}
fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::Warning => 1,
        Severity::Info => 2,
    }
}
fn state_label(s: AlertState) -> &'static str {
    match s {
        AlertState::Open => "未確認",
        AlertState::Acknowledged => "確認済",
        AlertState::Resolved => "解決済",
    }
}

#[component]
pub fn AlertsPage() -> impl IntoView {
    let tab = RwSignal::new("alerts");
    view! {
        <PageHeader title=Signal::derive(|| "アラート / 通知設定".to_string())/>
        <nav class="sub-nav">
            <button class="sub-nav-link" class:active=move || tab.get() == "alerts" on:click=move |_| tab.set("alerts")>"アラート"</button>
            <button class="sub-nav-link" class:active=move || tab.get() == "notify" on:click=move |_| tab.set("notify")>"通知設定"</button>
        </nav>
        <Show when=move || tab.get() == "alerts" fallback=move || view! { <NotifyTab/> }>
            <AlertsTab/>
        </Show>
    }
}

#[component]
fn AlertsTab() -> impl IntoView {
    let i18n = use_i18n();
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let me = Resource::new(|| (), |_| get_current_user());
    let can_write = move || matches!(me.get(), Some(Ok(Some(u))) if u.role >= Role::Operator);

    let fstate = RwSignal::new("open".to_string());
    let fseverity = RwSignal::new(String::new());
    let fdomain = RwSignal::new(String::new());
    let expanded = RwSignal::new(Option::<String>::None);
    let selected = RwSignal::new(Vec::<String>::new());

    let alerts = Resource::new(
        move || (reload.get(), fstate.get(), fseverity.get(), fdomain.get()),
        |(_, state, severity, domain)| list_alerts(state, severity, domain),
    );
    let refresh = move || {
        selected.set(Vec::new());
        expanded.set(None);
        reload.update(|n| *n += 1);
    };

    let ack = ServerAction::<AcknowledgeAlerts>::new();
    let resolve = ServerAction::<ResolveAlerts>::new();
    Effect::new(move |_| {
        if let Some(Ok(n)) = ack.value().get() {
            toast.success(format!("{n} 件を確認応答しました。"));
            refresh();
        }
    });
    Effect::new(move |_| {
        if let Some(Ok(n)) = resolve.value().get() {
            toast.success(format!("{n} 件を解決しました。"));
            refresh();
        }
    });

    view! {
        <div class="audit-filters">
            <label class="filter">
                <span class="filter-label">"状態"</span>
                <select class="input" prop:value=move || fstate.get()
                    on:change=move |ev| { fstate.set(event_target_value(&ev)); selected.set(Vec::new()); }>
                    <option value="open">"未確認"</option>
                    <option value="acknowledged">"確認済"</option>
                    <option value="resolved">"解決済"</option>
                    <option value="">"全状態"</option>
                </select>
            </label>
            <label class="filter">
                <span class="filter-label">"重大度"</span>
                <select class="input" prop:value=move || fseverity.get()
                    on:change=move |ev| { fseverity.set(event_target_value(&ev)); selected.set(Vec::new()); }>
                    <option value="">"全重大度"</option>
                    <option value="critical">"重大"</option>
                    <option value="warning">"警告"</option>
                    <option value="info">"情報"</option>
                </select>
            </label>
            <label class="filter">
                <span class="filter-label">"ドメイン"</span>
                <select class="input" prop:value=move || fdomain.get()
                    on:change=move |ev| { fdomain.set(event_target_value(&ev)); selected.set(Vec::new()); }>
                    <option value="">"全ドメイン"</option>
                    {DomainKey::DOMAINS.iter().chain(std::iter::once(&DomainKey::Portal)).map(|d| {
                        let value = d.as_str();
                        let label = i18n.t(d.label_key());
                        view! { <option value=value>{label}</option> }
                    }).collect_view()}
                </select>
            </label>
            <div class="tab-actions bulk-actions">
                <button class="btn btn-secondary btn-sm" prop:disabled=move || !can_write() || selected.get().is_empty()
                    on:click=move |_| { ack.dispatch(AcknowledgeAlerts { alert_ids: selected.get() }); }>"選択を確認"</button>
                <button class="btn btn-secondary btn-sm" prop:disabled=move || !can_write() || selected.get().is_empty()
                    on:click=move |_| { resolve.dispatch(ResolveAlerts { alert_ids: selected.get() }); }>"選択を解決"</button>
            </div>
        </div>

        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                let writable = can_write();
                alerts.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "対象のアラートはありません。".to_string())/> }.into_any(),
                    Ok(mut list) => {
                        list.sort_by_key(|a| severity_rank(a.severity));
                        let rows = list.into_iter().map(|a: Alert| {
                            let id = a.meta.id.clone();
                            let id_open = id.clone();
                            let id_sel = id.clone();
                            let id_ack = id.clone();
                            let id_res = id.clone();
                            let is_open = { let id = id.clone(); move || expanded.get().as_deref() == Some(id.as_str()) };
                            let is_detail = is_open.clone();
                            let checked = { let id = id.clone(); move || selected.get().contains(&id) };
                            let (sev_label, sev_class) = severity_meta(a.severity);
                            let domain_label = i18n.t(a.domain.label_key());
                            let at = a.meta.created_at.format("%m-%d %H:%M").to_string();
                            let state = a.state;
                            let selectable = state != AlertState::Resolved;
                            let is_unack = state == AlertState::Open;
                            let summary = a.summary.clone();
                            let source = a.source_ref.clone().unwrap_or_else(|| "-".into());
                            let rule = a.rule_ref.clone().unwrap_or_else(|| "-".into());
                            let ack_by = a.acknowledged_by.clone();
                            let res_by = a.resolved_by.clone();
                            let suppressed = a.suppressed;
                            view! {
                                <tr class="alert-row" class:row-unack=is_unack>
                                    <td>
                                        {selectable.then(|| view! {
                                            <input type="checkbox" prop:checked=checked
                                                on:change=move |ev| {
                                                    let on = event_target_checked(&ev);
                                                    selected.update(|v| { if on { if !v.contains(&id_sel) { v.push(id_sel.clone()); } } else { v.retain(|x| x != &id_sel); } });
                                                }/>
                                        })}
                                    </td>
                                    <td><span class=sev_class>{sev_label}</span></td>
                                    <td>{domain_label}</td>
                                    <td>
                                        {summary}
                                        {suppressed.then(|| view! { <span class="badge badge-unknown suppressed-badge">"抑止中"</span> })}
                                    </td>
                                    <td class="mono">{at}</td>
                                    <td>{state_label(state)}</td>
                                    <td class="row-actions">
                                        {(writable && state == AlertState::Open).then(|| view! {
                                            <button class="btn btn-secondary btn-sm"
                                                on:click=move |_| { ack.dispatch(AcknowledgeAlerts { alert_ids: vec![id_ack.clone()] }); }>"確認"</button>
                                        })}
                                        {(writable && state != AlertState::Resolved).then(|| view! {
                                            <button class="btn btn-secondary btn-sm"
                                                on:click=move |_| { resolve.dispatch(ResolveAlerts { alert_ids: vec![id_res.clone()] }); }>"解決"</button>
                                        })}
                                    </td>
                                    <td class="expand-caret" on:click=move |_| {
                                        expanded.update(|cur| {
                                            if cur.as_deref() == Some(id_open.as_str()) { *cur = None; } else { *cur = Some(id_open.clone()); }
                                        });
                                    }>{move || if is_open() { "▾" } else { "▸" }}</td>
                                </tr>
                                <Show when=is_detail.clone() fallback=|| ()>
                                    <tr class="audit-detail-row">
                                        <td colspan="8">
                                            <dl class="audit-detail">
                                                <dt>"対象"</dt><dd class="mono">{source.clone()}</dd>
                                                <dt>"ルール"</dt><dd class="mono">{rule.clone()}</dd>
                                                {ack_by.clone().map(|by| view! { <dt>"確認者"</dt><dd>{by}</dd> })}
                                                {res_by.clone().map(|by| view! { <dt>"解決者"</dt><dd>{by}</dd> })}
                                            </dl>
                                        </td>
                                    </tr>
                                </Show>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table alert-table">
                                <thead><tr>
                                    <th></th>
                                    <th>"重大度"</th>
                                    <th>"ドメイン"</th>
                                    <th>"概要"</th>
                                    <th>"発生"</th>
                                    <th>"状態"</th>
                                    <th>"操作"</th>
                                    <th></th>
                                </tr></thead>
                                <tbody>{rows}</tbody>
                            </table>
                        }.into_any()
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
fn NotifyTab() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let me = Resource::new(|| (), |_| get_current_user());
    let can_write = move || matches!(me.get(), Some(Ok(Some(u))) if u.role >= Role::Operator);
    let targets = Resource::new(move || reload.get(), |_| list_notification_targets());

    // Create form.
    let form_open = RwSignal::new(false);
    let name = RwSignal::new(String::new());
    let kind = RwSignal::new("webhook".to_string());
    let endpoint = RwSignal::new(String::new());
    let min_severity = RwSignal::new("warning".to_string());
    let signing_secret = RwSignal::new(String::new());
    let save_error = RwSignal::new(Option::<String>::None);
    let create = ServerAction::<CreateNotificationTarget>::new();
    Effect::new(move |_| {
        if let Some(result) = create.value().get() {
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
    let open_create = move |_| {
        name.set(String::new());
        endpoint.set(String::new());
        kind.set("webhook".into());
        min_severity.set("warning".into());
        signing_secret.set(String::new());
        save_error.set(None);
        form_open.set(true);
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create.dispatch(CreateNotificationTarget {
            name: name.get(),
            kind: kind.get(),
            endpoint: endpoint.get(),
            min_severity: min_severity.get(),
            signing_secret: signing_secret.get(),
            enabled: true,
        });
    };

    let toggle = ServerAction::<SetNotificationTargetEnabled>::new();
    let delete = ServerAction::<DeleteNotificationTarget>::new();
    Effect::new(move |_| {
        if let Some(Ok(())) = toggle.value().get() {
            toast.success("更新しました。");
            reload.update(|n| *n += 1);
        }
    });
    let confirm_open = RwSignal::new(false);
    let del_target = RwSignal::new(Option::<(String, String)>::None);
    Effect::new(move |_| {
        if let Some(result) = delete.value().get() {
            match result {
                Ok(()) => {
                    toast.success("削除しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => toast.error(e.to_string()),
            }
        }
    });
    Effect::new(move |_| {
        if !confirm_open.get() {
            del_target.set(None);
        }
    });
    let confirm_body = Signal::derive(move || match del_target.get() {
        Some((_, name)) => format!("通知先「{name}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = del_target.get() {
            delete.dispatch(DeleteNotificationTarget { target_id: id });
        }
    });

    view! {
        <div class="tab-actions">
            <button class="btn btn-primary" prop:disabled=move || !can_write() on:click=open_create>"＋ 追加"</button>
        </div>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                let writable = can_write();
                targets.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "通知先がありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|t: NotificationTarget| {
                            let id_tog = t.meta.id.clone();
                            let id_del = t.meta.id.clone();
                            let name_del = t.name.clone();
                            let enabled = t.enabled;
                            let kind_label = match t.kind { NotifyKind::Webhook => "Webhook", NotifyKind::AuditSink => "監査連携", NotifyKind::Email => "メール" };
                            let sev = t.min_severity.map(|s| severity_meta(s).0).unwrap_or("-");
                            view! {
                                <tr>
                                    <td>{t.name.clone()}</td>
                                    <td>{kind_label}</td>
                                    <td class="mono">{t.endpoint.clone()}</td>
                                    <td>{sev}</td>
                                    <td>{if enabled { "有効" } else { "無効" }}</td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm" prop:disabled=move || !writable
                                            on:click=move |_| { toggle.dispatch(SetNotificationTargetEnabled { target_id: id_tog.clone(), enabled: !enabled }); }>{if enabled { "無効化" } else { "有効化" }}</button>
                                        <button class="icon-button" title="削除" prop:disabled=move || !writable
                                            on:click=move |_| { del_target.set(Some((id_del.clone(), name_del.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"名称"</th><th>"種別"</th><th>"エンドポイント"</th><th>"対象重大度"</th><th>"状態"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">"通知先の追加"</h2>
                    <label class="field"><span class="field-label">"名称"</span><input class="input" prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"種別"</span>
                        <select class="input" prop:value=move || kind.get() on:change=move |ev| kind.set(event_target_value(&ev))>
                            <option value="webhook">"Webhook"</option>
                            <option value="audit_sink">"監査連携"</option>
                            <option value="email">"メール"</option>
                        </select></label>
                    <label class="field">
                        <span class="field-label">{move || if kind.get() == "email" { "宛先メールアドレス" } else { "エンドポイント URL" }}</span>
                        <input class="input" prop:value=move || endpoint.get() on:input=move |ev| endpoint.set(event_target_value(&ev)) prop:placeholder=move || if kind.get() == "email" { "ops@example.com" } else { "https://..." }/></label>
                    <label class="field"><span class="field-label">"対象重大度（この重大度以上）"</span>
                        <select class="input" prop:value=move || min_severity.get() on:change=move |ev| min_severity.set(event_target_value(&ev))>
                            <option value="critical">"重大"</option>
                            <option value="warning">"警告"</option>
                            <option value="info">"情報"</option>
                        </select></label>
                    <Show when=move || kind.get() != "email" fallback=|| ()>
                        <label class="field"><span class="field-label">"署名シークレット（任意, HMAC-SHA256）"</span><input class="input" type="password" prop:value=move || signing_secret.get() on:input=move |ev| signing_secret.set(event_target_value(&ev))/></label>
                    </Show>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || create.pending().get()>"保存"</button>
                    </div>
                </form>
            </div>
        </Show>

        <ConfirmDialog title=Signal::derive(|| "削除の確認".to_string()) body=confirm_body open=confirm_open on_confirm=on_confirm_delete/>
    }
}
