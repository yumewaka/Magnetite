//! Proxy ACL rule management (S-PROXY-04). Priority up/down and enable toggle
//! reflect immediately (E-P02/E-P03).

use super::nav::ProxyNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::proxy::{
    list_acl_rules, DeleteAclRule, SaveAclRule, SetAclPriority, ToggleAcl,
};
use leptos::prelude::*;
use magnetite_core::domains::proxy::model::{AclAction, AclRule, AclScope};

#[component]
pub fn AclRulesPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let rules = Resource::new(move || reload.get(), |_| list_acl_rules());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let cidr = RwSignal::new(String::new());
    let action = RwSignal::new("deny".to_string());
    let scope = RwSignal::new("global".to_string());
    let vhost_ref = RwSignal::new(String::new());
    let priority = RwSignal::new("0".to_string());
    let enabled = RwSignal::new(true);
    let description = RwSignal::new(String::new());

    let open_create = move |_| {
        edit_id.set(String::new());
        cidr.set(String::new());
        action.set("deny".into());
        scope.set("global".into());
        vhost_ref.set(String::new());
        priority.set("0".into());
        enabled.set(true);
        description.set(String::new());
        form_open.set(true);
    };
    let open_edit = move |r: AclRule| {
        edit_id.set(r.id.clone());
        cidr.set(r.cidr.clone());
        action.set(r.action.as_str().into());
        scope.set(
            match r.scope {
                AclScope::Vhost => "vhost",
                AclScope::Global => "global",
            }
            .into(),
        );
        vhost_ref.set(r.vhost_ref.clone().unwrap_or_default());
        priority.set(r.priority.to_string());
        enabled.set(r.enabled);
        description.set(r.description.clone().unwrap_or_default());
        form_open.set(true);
    };

    let save = ServerAction::<SaveAclRule>::new();
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
        let rule = AclRule {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            cidr: cidr.get(),
            action: AclAction::from_str(&action.get()),
            scope: if scope.get() == "vhost" {
                AclScope::Vhost
            } else {
                AclScope::Global
            },
            vhost_ref: {
                let v = vhost_ref.get();
                if v.trim().is_empty() {
                    None
                } else {
                    Some(v)
                }
            },
            priority: priority.get().trim().parse::<i32>().unwrap_or(0),
            enabled: enabled.get(),
            description: {
                let d = description.get();
                if d.trim().is_empty() {
                    None
                } else {
                    Some(d)
                }
            },
        };
        save.dispatch(SaveAclRule { rule });
    };

    let reprioritize = ServerAction::<SetAclPriority>::new();
    Effect::new(move |_| {
        if let Some(Ok(())) = reprioritize.value().get() {
            toast.success("優先度を変更しました。");
            reload.update(|n| *n += 1);
        }
    });
    let toggle = ServerAction::<ToggleAcl>::new();
    Effect::new(move |_| {
        if let Some(Ok(())) = toggle.value().get() {
            toast.success("保存しました。");
            reload.update(|n| *n += 1);
        }
    });

    let delete = ServerAction::<DeleteAclRule>::new();
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
        Some((_, c)) => format!("ACL ルール「{c}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = delete_target.get() {
            delete.dispatch(DeleteAclRule { id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "ACL ルール".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 作成"</button>
        </PageHeader>
        <ProxyNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                rules.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "ACL ルールがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|r: AclRule| {
                            let r_edit = r.clone();
                            let id_up = r.id.clone();
                            let id_down = r.id.clone();
                            let id_tog = r.id.clone();
                            let id_del = r.id.clone();
                            let cidr_del = r.cidr.clone();
                            let prio = r.priority;
                            let enabled = r.enabled;
                            let (acls, alabel) = if r.action == AclAction::Deny { ("badge badge-danger", "Deny") } else { ("badge badge-success", "Allow") };
                            let scope_s = if r.scope == AclScope::Vhost { r.vhost_ref.clone().unwrap_or_default() } else { "Global".into() };
                            view! {
                                <tr>
                                    <td class="prio-cell">
                                        <button class="icon-button" title="上げる" on:click=move |_| { reprioritize.dispatch(SetAclPriority { id: id_up.clone(), priority: prio - 1 }); }>"\u{25B2}"</button>
                                        <span>{prio}</span>
                                        <button class="icon-button" title="下げる" on:click=move |_| { reprioritize.dispatch(SetAclPriority { id: id_down.clone(), priority: prio + 1 }); }>"\u{25BC}"</button>
                                    </td>
                                    <td class="mono">{r.cidr.clone()}</td>
                                    <td><span class=acls>{alabel}</span></td>
                                    <td>{scope_s}</td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm" on:click=move |_| { toggle.dispatch(ToggleAcl { id: id_tog.clone(), enabled: !enabled }); }>{if enabled { "無効化" } else { "有効化" }}</button>
                                        <button class="icon-button" title="編集" on:click=move |_| open_edit(r_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_del.clone(), cidr_del.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"優先度"</th><th>"CIDR"</th><th>"アクション"</th><th>"スコープ"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">{move || if edit_id.get().is_empty() { "ACL ルールの作成" } else { "ACL ルールの編集" }}</h2>
                    <label class="field"><span class="field-label">"CIDR"</span><input class="input" prop:value=move || cidr.get() on:input=move |ev| cidr.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"アクション"</span><select class="input" prop:value=move || action.get() on:change=move |ev| action.set(event_target_value(&ev))><option value="allow">"Allow"</option><option value="deny">"Deny"</option></select></label>
                    <label class="field"><span class="field-label">"スコープ"</span><select class="input" prop:value=move || scope.get() on:change=move |ev| scope.set(event_target_value(&ev))><option value="global">"Global"</option><option value="vhost">"Vhost"</option></select></label>
                    <Show when=move || scope.get() == "vhost" fallback=|| ()>
                        <label class="field"><span class="field-label">"対象ホスト名"</span><input class="input" prop:value=move || vhost_ref.get() on:input=move |ev| vhost_ref.set(event_target_value(&ev))/></label>
                    </Show>
                    <label class="field"><span class="field-label">"優先度"</span><input class="input" type="number" prop:value=move || priority.get() on:input=move |ev| priority.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"説明（任意）"</span><input class="input" prop:value=move || description.get() on:input=move |ev| description.set(event_target_value(&ev))/></label>
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
