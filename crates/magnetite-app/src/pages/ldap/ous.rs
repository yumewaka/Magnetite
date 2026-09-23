//! LDAP OU management (S-LDAP-05): list, create and delete. Deleting an OU with
//! children is refused server-side (AC-15) and surfaced as an error toast.

use super::nav::LdapNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::ldap::{list_ous, list_parents, CreateOu, DeleteEntry};
use leptos::prelude::*;
use magnetite_core::domains::ldap::model::LdapOu;

#[component]
pub fn OusPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let ous = Resource::new(move || reload.get(), |_| list_ous());
    let parents = Resource::new(|| (), |_| list_parents());

    let form_open = RwSignal::new(false);
    let parent_dn = RwSignal::new(String::new());
    let ou = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());
    let create = ServerAction::<CreateOu>::new();
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
        ou.set(String::new());
        description.set(String::new());
        save_error.set(None);
        form_open.set(true);
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create.dispatch(CreateOu {
            parent_dn: parent_dn.get(),
            ou: ou.get(),
            description: description.get(),
        });
    };

    // Delete (guard error surfaced as a toast).
    let delete = ServerAction::<DeleteEntry>::new();
    let confirm_open = RwSignal::new(false);
    let delete_target = RwSignal::new(Option::<(String, String)>::None);
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
            delete_target.set(None);
        }
    });
    let confirm_body = Signal::derive(move || match delete_target.get() {
        Some((_, ou)) => format!("OU「{ou}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((dn, _)) = delete_target.get() {
            delete.dispatch(DeleteEntry { dn });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "LDAP OU".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <LdapNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                ous.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "OU がありません。".to_string())/>
                    }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|o: LdapOu| {
                            let dn_d = o.dn.clone();
                            let ou_d = o.ou.clone();
                            view! {
                                <tr>
                                    <td>{o.ou.clone()}</td>
                                    <td class="mono">{o.dn.clone()}</td>
                                    <td>{o.description.clone().unwrap_or_default()}</td>
                                    <td>{if o.has_children { "配下あり" } else { "空" }}</td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="削除"
                                            on:click=move |_| { delete_target.set(Some((dn_d.clone(), ou_d.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr><th>"OU"</th><th>"DN"</th><th>"説明"</th><th>"配下"</th><th>"操作"</th></tr></thead>
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
                    <h2 class="slideover-title">"OU の作成"</h2>
                    <label class="field">
                        <span class="field-label">"親 DN"</span>
                        <select class="input" on:change=move |ev| parent_dn.set(event_target_value(&ev)) prop:value=move || parent_dn.get()>
                            <Suspense fallback=|| ()>
                                {move || parents.get().map(|res| res.unwrap_or_default().into_iter().map(|dn| { let label = dn.clone(); view! { <option value=dn>{label}</option> } }).collect_view())}
                            </Suspense>
                        </select>
                    </label>
                    <label class="field"><span class="field-label">"OU 名"</span>
                        <input class="input" prop:value=move || ou.get() on:input=move |ev| ou.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"説明（任意）"</span>
                        <input class="input" prop:value=move || description.get() on:input=move |ev| description.set(event_target_value(&ev))/></label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || create.pending().get()>"保存"</button>
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
