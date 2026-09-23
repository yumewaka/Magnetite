//! SSO audit-sink settings (S-SSO-06): configure the external destinations that
//! receive forwarded audit events. These are the cross-cutting `NotificationTarget`s
//! of kind `AuditSink` (shared with the alerting feature) — this screen presents only
//! that kind, filtered from the same store the alerts screen manages.

use super::nav::SsoNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::alert::{
    list_notification_targets, CreateNotificationTarget, DeleteNotificationTarget,
    SetNotificationTargetEnabled,
};
use leptos::prelude::*;
use magnetite_core::models::common::NotifyKind;
use magnetite_core::models::NotificationTarget;

fn severity_label(t: &NotificationTarget) -> &'static str {
    use magnetite_core::models::common::Severity;
    match t.min_severity {
        Some(Severity::Critical) => "重大以上",
        Some(Severity::Warning) => "警告以上",
        Some(Severity::Info) => "情報以上",
        None => "-",
    }
}

#[component]
pub fn AuditSinkPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let targets = Resource::new(move || reload.get(), |_| list_notification_targets());

    let form_open = RwSignal::new(false);
    let name = RwSignal::new(String::new());
    let endpoint = RwSignal::new(String::new());
    let min_severity = RwSignal::new("info".to_string());
    let signing_secret = RwSignal::new(String::new());
    let create = ServerAction::<CreateNotificationTarget>::new();
    let save_error = RwSignal::new(Option::<String>::None);
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
        min_severity.set("info".into());
        signing_secret.set(String::new());
        save_error.set(None);
        form_open.set(true);
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create.dispatch(CreateNotificationTarget {
            name: name.get(),
            kind: "audit_sink".to_string(),
            endpoint: endpoint.get(),
            min_severity: min_severity.get(),
            signing_secret: signing_secret.get(),
            enabled: true,
        });
    };

    let toggle = ServerAction::<SetNotificationTargetEnabled>::new();
    Effect::new(move |_| {
        if let Some(Ok(())) = toggle.value().get() {
            toast.success("更新しました。");
            reload.update(|n| *n += 1);
        }
    });

    let delete = ServerAction::<DeleteNotificationTarget>::new();
    let confirm_open = RwSignal::new(false);
    let del_target = RwSignal::new(Option::<(String, String)>::None);
    Effect::new(move |_| {
        if let Some(Ok(())) = delete.value().get() {
            toast.success("削除しました。");
            reload.update(|n| *n += 1);
        }
    });
    Effect::new(move |_| {
        if !confirm_open.get() {
            del_target.set(None);
        }
    });
    let confirm_body = Signal::derive(move || match del_target.get() {
        Some((_, name)) => format!("監査連携先「{name}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = del_target.get() {
            delete.dispatch(DeleteNotificationTarget { target_id: id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "監査連携先".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <SsoNav/>
        <p class="page-intro">
            "監査イベントを転送する外部の連携先（SIEM 等）を設定します。ここで作成した連携先は"
            "「監査連携」種別の通知先として、アラート通知の仕組みと同じ配信経路で送信されます。"
        </p>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                targets.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) => {
                        let sinks: Vec<NotificationTarget> = list.into_iter().filter(|t| t.kind == NotifyKind::AuditSink).collect();
                        if sinks.is_empty() {
                            return view! { <EmptyState message=Signal::derive(|| "監査連携先がありません。".to_string())/> }.into_any();
                        }
                        let rows = sinks.into_iter().map(|t: NotificationTarget| {
                            let id_tog = t.meta.id.clone();
                            let id_del = t.meta.id.clone();
                            let name_del = t.name.clone();
                            let enabled = t.enabled;
                            let sev = severity_label(&t);
                            view! {
                                <tr>
                                    <td>{t.name.clone()}</td>
                                    <td class="mono">{t.endpoint.clone()}</td>
                                    <td>{sev}</td>
                                    <td><span class=if enabled { "badge badge-success" } else { "badge badge-unknown" }>{if enabled { "有効" } else { "無効" }}</span></td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm" on:click=move |_| { toggle.dispatch(SetNotificationTargetEnabled { target_id: id_tog.clone(), enabled: !enabled }); }>{if enabled { "無効化" } else { "有効化" }}</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { del_target.set(Some((id_del.clone(), name_del.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr><th>"名称"</th><th>"エンドポイント"</th><th>"対象重大度"</th><th>"状態"</th><th>"操作"</th></tr></thead>
                                <tbody>{rows}</tbody>
                            </table>
                        }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">"監査連携先の追加"</h2>
                    <label class="field"><span class="field-label">"名称"</span><input class="input" prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"エンドポイント URL"</span><input class="input" prop:value=move || endpoint.get() on:input=move |ev| endpoint.set(event_target_value(&ev)) placeholder="https://siem.example.com/ingest"/></label>
                    <label class="field"><span class="field-label">"対象重大度（この重大度以上）"</span>
                        <select class="input" prop:value=move || min_severity.get() on:change=move |ev| min_severity.set(event_target_value(&ev))>
                            <option value="critical">"重大"</option>
                            <option value="warning">"警告"</option>
                            <option value="info">"情報"</option>
                        </select></label>
                    <label class="field"><span class="field-label">"署名シークレット（任意, HMAC-SHA256）"</span><input class="input" type="password" prop:value=move || signing_secret.get() on:input=move |ev| signing_secret.set(event_target_value(&ev))/></label>
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
