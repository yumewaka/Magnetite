//! Mailing list management (S-MAIL-05): list, create, delete and member
//! add/remove.

use super::nav::MailNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::mail::{
    list_mail_domains, list_mailing_lists, AddListMember, CreateMailingList, DeleteMailingList,
    RemoveListMember,
};
use leptos::prelude::*;
use magnetite_core::domains::mail::model::MailingList;

#[component]
pub fn MailingListsPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let lists = Resource::new(move || reload.get(), |_| list_mailing_lists());
    let domains = Resource::new(|| (), |_| list_mail_domains());

    // Create form.
    let form_open = RwSignal::new(false);
    let address = RwSignal::new(String::new());
    let domain = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let owner = RwSignal::new(String::new());
    let reply_policy = RwSignal::new("list".to_string());
    let create = ServerAction::<CreateMailingList>::new();
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
        address.set(String::new());
        name.set(String::new());
        owner.set(String::new());
        reply_policy.set("list".to_string());
        save_error.set(None);
        form_open.set(true);
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create.dispatch(CreateMailingList {
            address: address.get(),
            domain: domain.get(),
            name: name.get(),
            owner: owner.get(),
            reply_policy: reply_policy.get(),
        });
    };

    // Member management.
    let members_open = RwSignal::new(false);
    let members_list = RwSignal::new(Option::<MailingList>::None);
    let m_email = RwSignal::new(String::new());
    let m_name = RwSignal::new(String::new());
    let member_error = RwSignal::new(Option::<String>::None);
    let add = ServerAction::<AddListMember>::new();
    let remove = ServerAction::<RemoveListMember>::new();
    Effect::new(move |_| {
        if let Some(result) = add.value().get() {
            match result {
                Ok(()) => {
                    member_error.set(None);
                    m_email.set(String::new());
                    m_name.set(String::new());
                    toast.success("保存しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => member_error.set(Some(e.to_string())),
            }
        }
    });
    Effect::new(move |_| {
        if let Some(Ok(())) = remove.value().get() {
            toast.success("削除しました。");
            reload.update(|n| *n += 1);
        }
    });
    Effect::new(move |_| {
        if let (Some(Ok(list)), Some(current)) = (lists.get(), members_list.get()) {
            if let Some(updated) = list.into_iter().find(|l| l.id == current.id) {
                members_list.set(Some(updated));
            }
        }
    });

    // Delete.
    let delete = ServerAction::<DeleteMailingList>::new();
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
        Some((_, a)) => format!("メーリングリスト「{a}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = delete_target.get() {
            delete.dispatch(DeleteMailingList { id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "メーリングリスト".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <MailNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                lists.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "メーリングリストがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|l: MailingList| {
                            let l_members = l.clone();
                            let id_d = l.id.clone();
                            let addr_d = l.address.clone();
                            let count = l.members.len();
                            view! {
                                <tr>
                                    <td class="mono">{l.address.clone()}</td>
                                    <td>{l.name.clone()}</td>
                                    <td>{count}</td>
                                    <td>{l.reply_policy.as_str()}</td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm" on:click=move |_| { members_list.set(Some(l_members.clone())); member_error.set(None); members_open.set(true); }>"メンバー"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_d.clone(), addr_d.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr><th>"リストアドレス"</th><th>"名前"</th><th>"メンバー数"</th><th>"返信"</th><th>"操作"</th></tr></thead>
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
                    <h2 class="slideover-title">"メーリングリストの作成"</h2>
                    <label class="field"><span class="field-label">"リストアドレス"</span>
                        <input class="input" prop:value=move || address.get() on:input=move |ev| address.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"ドメイン"</span>
                        <select class="input" on:change=move |ev| domain.set(event_target_value(&ev)) prop:value=move || domain.get()>
                            <option value="">"（選択）"</option>
                            <Suspense fallback=|| ()>
                                {move || domains.get().map(|res| res.unwrap_or_default().into_iter().map(|d| { let n = d.name.clone(); view! { <option value=d.name>{n}</option> } }).collect_view())}
                            </Suspense>
                        </select>
                    </label>
                    <label class="field"><span class="field-label">"リスト名"</span>
                        <input class="input" prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"オーナー（メールユーザ）"</span>
                        <input class="input" prop:value=move || owner.get() on:input=move |ev| owner.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"返信ポリシー"</span>
                        <select class="input" prop:value=move || reply_policy.get() on:change=move |ev| reply_policy.set(event_target_value(&ev))>
                            <option value="list">"リスト"</option>
                            <option value="sender">"送信者"</option>
                            <option value="both">"両方"</option>
                        </select>
                    </label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || create.pending().get()>"保存"</button>
                    </div>
                </form>
            </div>
        </Show>

        <Show when=move || members_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| members_open.set(false)>
                <div class="slideover" on:click=|ev| ev.stop_propagation()>
                    <h2 class="slideover-title">"メンバー管理"</h2>
                    {move || members_list.get().map(|l| {
                        let id_add = l.id.clone();
                        let member_rows = l.members.iter().map(|m| {
                            let id = l.id.clone();
                            let email = m.email.clone();
                            let email_disp = m.email.clone();
                            view! {
                                <li class="member-row">
                                    <span class="mono">{email_disp}</span>
                                    <button class="icon-button" title="削除" on:click=move |_| { remove.dispatch(RemoveListMember { id: id.clone(), email: email.clone() }); }>"\u{2715}"</button>
                                </li>
                            }
                        }).collect_view();
                        view! {
                            <p class="mono">{l.address.clone()}</p>
                            <ul class="member-list">{member_rows}</ul>
                            <label class="field"><span class="field-label">"メンバー email"</span>
                                <input class="input" prop:value=move || m_email.get() on:input=move |ev| m_email.set(event_target_value(&ev))/></label>
                            <label class="field"><span class="field-label">"名前（任意）"</span>
                                <input class="input" prop:value=move || m_name.get() on:input=move |ev| m_name.set(event_target_value(&ev))/></label>
                            {move || member_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                            <button class="btn btn-primary" type="button" on:click=move |_| { add.dispatch(AddListMember { id: id_add.clone(), email: m_email.get(), name: m_name.get(), receive: true, can_post: true }); }>"追加"</button>
                        }
                    })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| members_open.set(false)>"閉じる"</button>
                    </div>
                </div>
            </div>
        </Show>

        <ConfirmDialog title=Signal::derive(|| "削除の確認".to_string()) body=confirm_body open=confirm_open on_confirm=on_confirm_delete/>
    }
}
