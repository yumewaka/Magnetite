//! DNS RPZ rule list / create / edit (S-DNS-06). The redirect-target field only
//! appears for the Redirect action.

use super::nav::DnsNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::dns::{list_rpz, DeleteRpz, SaveRpz};
use leptos::prelude::*;
use magnetite_core::domains::dns::model::{RpzAction, RpzRule};

const ACTIONS: [(RpzAction, &str); 4] = [
    (RpzAction::Nxdomain, "NXDOMAIN"),
    (RpzAction::Nodata, "NODATA"),
    (RpzAction::Redirect, "Redirect"),
    (RpzAction::Drop, "Drop"),
];

#[component]
pub fn RpzPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let rules = Resource::new(move || reload.get(), |_| list_rpz());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let domain = RwSignal::new(String::new());
    let action = RwSignal::new(RpzAction::Nxdomain.as_str().to_string());
    let redirect_to = RwSignal::new(String::new());
    let enabled = RwSignal::new(true);

    let open_create = move |_| {
        edit_id.set(String::new());
        domain.set(String::new());
        action.set(RpzAction::Nxdomain.as_str().to_string());
        redirect_to.set(String::new());
        enabled.set(true);
        form_open.set(true);
    };
    let open_edit = move |rule: RpzRule| {
        edit_id.set(rule.id.clone());
        domain.set(rule.domain.clone());
        action.set(rule.action.as_str().to_string());
        redirect_to.set(rule.redirect_to.clone().unwrap_or_default());
        enabled.set(rule.enabled);
        form_open.set(true);
    };

    let save = ServerAction::<SaveRpz>::new();
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
        let act = RpzAction::from_str(&action.get()).unwrap_or(RpzAction::Nxdomain);
        let redirect = if act == RpzAction::Redirect {
            Some(redirect_to.get())
        } else {
            None
        };
        let now = chrono::Utc::now();
        let rule = RpzRule {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            domain: domain.get(),
            action: act,
            redirect_to: redirect,
            enabled: enabled.get(),
        };
        save.dispatch(SaveRpz { rule });
    };

    let delete = ServerAction::<DeleteRpz>::new();
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
        Some((_, d)) => format!("RPZ ルール「{d}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = delete_target.get() {
            delete.dispatch(DeleteRpz { id });
        }
    });

    let is_redirect = move || RpzAction::from_str(&action.get()) == Some(RpzAction::Redirect);

    view! {
        <PageHeader title=Signal::derive(|| "RPZ 管理".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <DnsNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                rules.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "RPZ ルールがありません。".to_string())/>
                    }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|rule| {
                            let r_edit = rule.clone();
                            let r_del = rule.clone();
                            let health = if rule.enabled { "healthy" } else { "unknown" };
                            view! {
                                <tr>
                                    <td>{rule.domain.clone()}</td>
                                    <td>{rule.action.as_str().to_uppercase()}</td>
                                    <td>{rule.redirect_to.clone().unwrap_or_default()}</td>
                                    <td><StatusBadge health=Signal::derive(move || health.to_string())/></td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="編集"
                                            on:click=move |_| open_edit(r_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除"
                                            on:click=move |_| {
                                                delete_target.set(Some((r_del.id.clone(), r_del.domain.clone())));
                                                confirm_open.set(true);
                                            }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr>
                                    <th>"ドメイン"</th><th>"アクション"</th><th>"リダイレクト先"</th><th>"状態"</th><th>"操作"</th>
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
                    <h2 class="slideover-title">
                        {move || if edit_id.get().is_empty() { "RPZ ルールの作成" } else { "RPZ ルールの編集" }}
                    </h2>
                    <label class="field">
                        <span class="field-label">"ドメイン"</span>
                        <input class="input" prop:value=move || domain.get()
                            on:input=move |ev| domain.set(event_target_value(&ev))/>
                    </label>
                    <label class="field">
                        <span class="field-label">"アクション"</span>
                        <select class="input" prop:value=move || action.get()
                            on:change=move |ev| action.set(event_target_value(&ev))>
                            {ACTIONS.into_iter().map(|(a, label)| view! {
                                <option value=a.as_str()>{label}</option>
                            }).collect_view()}
                        </select>
                    </label>
                    <Show when=is_redirect fallback=|| ()>
                        <label class="field">
                            <span class="field-label">"リダイレクト先 (FQDN)"</span>
                            <input class="input" prop:value=move || redirect_to.get()
                                on:input=move |ev| redirect_to.set(event_target_value(&ev))/>
                        </label>
                    </Show>
                    <label class="field field-inline">
                        <input type="checkbox" prop:checked=move || enabled.get()
                            on:change=move |ev| enabled.set(event_target_checked(&ev))/>
                        <span>"有効"</span>
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
