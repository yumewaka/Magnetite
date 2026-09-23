//! LDAP access-control rules (S-LDAP-07). Rules are evaluated in priority order;
//! the first match decides. With no rules the directory is fully open; once any
//! rule exists, an unmatched request is denied. Editing is delete + recreate.

use super::nav::LdapNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::ldap::{list_ldap_acls, CreateLdapAcl, DeleteLdapAcl, ToggleLdapAcl};
use leptos::prelude::*;
use magnetite_core::domains::ldap::model::{
    LdapAclEffect, LdapAclOperation, LdapAclRule, LdapAclSubject,
};

const OPS: [(LdapAclOperation, &str); 7] = [
    (LdapAclOperation::Search, "検索"),
    (LdapAclOperation::Read, "読取"),
    (LdapAclOperation::Add, "追加"),
    (LdapAclOperation::Modify, "変更"),
    (LdapAclOperation::Delete, "削除"),
    (LdapAclOperation::ModifyDn, "DN変更"),
    (LdapAclOperation::Compare, "比較"),
];

fn op_label(op: LdapAclOperation) -> &'static str {
    OPS.iter()
        .find(|(o, _)| *o == op)
        .map(|(_, l)| *l)
        .unwrap_or("?")
}

fn subject_text(subject: &LdapAclSubject) -> String {
    match subject {
        LdapAclSubject::Anyone => "全員".to_string(),
        LdapAclSubject::Anonymous => "匿名".to_string(),
        LdapAclSubject::Authenticated => "認証済み".to_string(),
        LdapAclSubject::Dn(dn) => format!("DN: {dn}"),
        LdapAclSubject::GroupMember(dn) => format!("グループ員: {dn}"),
    }
}

#[component]
pub fn AclPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let rules = Resource::new(move || reload.get(), |_| list_ldap_acls());

    let form_open = RwSignal::new(false);
    let priority = RwSignal::new("100".to_string());
    let target_dn = RwSignal::new("*".to_string());
    let ops = RwSignal::new(vec![LdapAclOperation::Search, LdapAclOperation::Read]);
    let subject_type = RwSignal::new("anyone".to_string());
    let subject_value = RwSignal::new(String::new());
    let effect = RwSignal::new("allow".to_string());

    let open_create = move |_| {
        priority.set("100".into());
        target_dn.set("*".into());
        ops.set(vec![LdapAclOperation::Search, LdapAclOperation::Read]);
        subject_type.set("anyone".into());
        subject_value.set(String::new());
        effect.set("allow".into());
        form_open.set(true);
    };

    let save = ServerAction::<CreateLdapAcl>::new();
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
        let subject = match subject_type.get().as_str() {
            "anonymous" => LdapAclSubject::Anonymous,
            "authenticated" => LdapAclSubject::Authenticated,
            "dn" => LdapAclSubject::Dn(subject_value.get()),
            "group_member" => LdapAclSubject::GroupMember(subject_value.get()),
            _ => LdapAclSubject::Anyone,
        };
        let effect_val = if effect.get() == "deny" {
            LdapAclEffect::Deny
        } else {
            LdapAclEffect::Allow
        };
        let now = chrono::Utc::now();
        let rule = LdapAclRule {
            id: String::new(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            priority: priority.get().trim().parse().unwrap_or(100),
            target_dn: target_dn.get(),
            operations: ops.get(),
            subject,
            effect: effect_val,
            enabled: true,
        };
        save.dispatch(CreateLdapAcl { rule });
    };

    let toggle = ServerAction::<ToggleLdapAcl>::new();
    Effect::new(move |_| {
        if let Some(Ok(())) = toggle.value().get() {
            reload.update(|n| *n += 1);
        }
    });

    let delete = ServerAction::<DeleteLdapAcl>::new();
    let confirm_open = RwSignal::new(false);
    let delete_target = RwSignal::new(Option::<String>::None);
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
    let confirm_body =
        Signal::derive(|| "この ACL ルールを削除します。よろしいですか？".to_string());
    let on_confirm_delete = Callback::new(move |_| {
        if let Some(id) = delete_target.get() {
            delete.dispatch(DeleteLdapAcl { id });
        }
    });

    let subject_needs_value = move || matches!(subject_type.get().as_str(), "dn" | "group_member");

    view! {
        <PageHeader title=Signal::derive(|| "アクセス制御".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <LdapNav/>
        <p class="page-hint">
            "ルールは優先度の小さい順に評価され、最初に一致したルールで判定します。"
            "ルールが1つも無い場合はすべて許可、ルールがあり一致しない場合は拒否です。"
        </p>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                rules.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "ACL ルールがありません（全許可）。".to_string())/>
                    }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|rule| {
                            let health = if rule.enabled { "healthy" } else { "unknown" };
                            let (tid, ten) = (rule.id.clone(), rule.enabled);
                            let did = rule.id.clone();
                            let ops_text = rule.operations.iter().map(|o| op_label(*o)).collect::<Vec<_>>().join(", ");
                            let effect_text = match rule.effect {
                                LdapAclEffect::Allow => "許可",
                                LdapAclEffect::Deny => "拒否",
                            };
                            view! {
                                <tr>
                                    <td>{rule.priority}</td>
                                    <td>{rule.target_dn.clone()}</td>
                                    <td>{ops_text}</td>
                                    <td>{subject_text(&rule.subject)}</td>
                                    <td>{effect_text}</td>
                                    <td><StatusBadge health=Signal::derive(move || health.to_string())/></td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="有効/無効"
                                            on:click=move |_| { toggle.dispatch(ToggleLdapAcl { id: tid.clone(), enabled: !ten }); }>
                                            {if ten { "\u{23F8}" } else { "\u{25B6}" }}
                                        </button>
                                        <button class="icon-button" title="削除"
                                            on:click=move |_| {
                                                delete_target.set(Some(did.clone()));
                                                confirm_open.set(true);
                                            }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr>
                                    <th>"優先度"</th><th>"対象 DN"</th><th>"操作"</th>
                                    <th>"主体"</th><th>"効果"</th><th>"状態"</th><th>"操作"</th>
                                </tr></thead>
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
                    <h2 class="slideover-title">"ACL ルールの作成"</h2>
                    <label class="field">
                        <span class="field-label">"優先度（小さいほど先に評価）"</span>
                        <input class="input" type="number" prop:value=move || priority.get()
                            on:input=move |ev| priority.set(event_target_value(&ev))/>
                    </label>
                    <label class="field">
                        <span class="field-label">"対象 DN（* で全体、サブツリーも一致）"</span>
                        <input class="input" prop:value=move || target_dn.get()
                            on:input=move |ev| target_dn.set(event_target_value(&ev))/>
                    </label>
                    <fieldset class="field">
                        <span class="field-label">"操作"</span>
                        <div class="checkbox-row">
                            {OPS.into_iter().map(|(op, label)| {
                                let checked = move || ops.get().contains(&op);
                                view! {
                                    <label class="field-inline">
                                        <input type="checkbox" prop:checked=checked
                                            on:change=move |ev| {
                                                let on = event_target_checked(&ev);
                                                ops.update(|v| {
                                                    if on {
                                                        if !v.contains(&op) { v.push(op); }
                                                    } else {
                                                        v.retain(|o| *o != op);
                                                    }
                                                });
                                            }/>
                                        <span>{label}</span>
                                    </label>
                                }
                            }).collect_view()}
                        </div>
                    </fieldset>
                    <label class="field">
                        <span class="field-label">"主体"</span>
                        <select class="input" prop:value=move || subject_type.get()
                            on:change=move |ev| subject_type.set(event_target_value(&ev))>
                            <option value="anyone">"全員"</option>
                            <option value="anonymous">"匿名"</option>
                            <option value="authenticated">"認証済み"</option>
                            <option value="dn">"指定 DN"</option>
                            <option value="group_member">"グループ員"</option>
                        </select>
                    </label>
                    <Show when=subject_needs_value fallback=|| ()>
                        <label class="field">
                            <span class="field-label">"DN"</span>
                            <input class="input" prop:value=move || subject_value.get()
                                on:input=move |ev| subject_value.set(event_target_value(&ev))/>
                        </label>
                    </Show>
                    <label class="field">
                        <span class="field-label">"効果"</span>
                        <select class="input" prop:value=move || effect.get()
                            on:change=move |ev| effect.set(event_target_value(&ev))>
                            <option value="allow">"許可"</option>
                            <option value="deny">"拒否"</option>
                        </select>
                    </label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || save.pending().get()>"保存"</button>
                    </div>
                </form>
            </div>
        </Show>

        <ConfirmDialog
            title=Signal::derive(|| "削除の確認".to_string())
            body=confirm_body
            open=confirm_open
            on_confirm=on_confirm_delete
        />
    }
}
