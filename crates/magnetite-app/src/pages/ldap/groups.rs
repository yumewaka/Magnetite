//! LDAP group management (S-LDAP-04): list, create, delete and member
//! add/remove.

use super::nav::LdapNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::ldap::{
    list_groups, list_parents, AddMember, CreateGroup, DeleteEntry, RemoveMember,
};
use leptos::prelude::*;
use magnetite_core::domains::ldap::model::LdapGroup;

#[component]
pub fn GroupsPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let groups = Resource::new(move || reload.get(), |_| list_groups());
    let parents = Resource::new(|| (), |_| list_parents());

    // Create form.
    let form_open = RwSignal::new(false);
    let parent_dn = RwSignal::new(String::new());
    let cn = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());
    let create = ServerAction::<CreateGroup>::new();
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
        cn.set(String::new());
        description.set(String::new());
        save_error.set(None);
        form_open.set(true);
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create.dispatch(CreateGroup {
            parent_dn: parent_dn.get(),
            cn: cn.get(),
            description: description.get(),
        });
    };

    // Member management slide-over.
    let members_open = RwSignal::new(false);
    let members_group = RwSignal::new(Option::<LdapGroup>::None);
    let new_member = RwSignal::new(String::new());
    let member_error = RwSignal::new(Option::<String>::None);
    let add = ServerAction::<AddMember>::new();
    let remove = ServerAction::<RemoveMember>::new();
    let refresh_members = move || {
        // Refetch groups and update the open panel from the fresh list.
        reload.update(|n| *n += 1);
    };
    Effect::new(move |_| {
        if let Some(result) = add.value().get() {
            match result {
                Ok(()) => {
                    member_error.set(None);
                    new_member.set(String::new());
                    toast.success("メンバーを追加しました。");
                    refresh_members();
                }
                Err(e) => member_error.set(Some(e.to_string())),
            }
        }
    });
    Effect::new(move |_| {
        if let Some(Ok(())) = remove.value().get() {
            toast.success("メンバーを削除しました。");
            refresh_members();
        }
    });
    // Keep the open members panel in sync with refetched group data.
    Effect::new(move |_| {
        if let (Some(Ok(list)), Some(current)) = (groups.get(), members_group.get()) {
            if let Some(updated) = list.into_iter().find(|g| g.dn == current.dn) {
                members_group.set(Some(updated));
            }
        }
    });

    // Delete.
    let delete = ServerAction::<DeleteEntry>::new();
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
        Some((_, cn)) => format!("グループ「{cn}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((dn, _)) = delete_target.get() {
            delete.dispatch(DeleteEntry { dn });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "LDAP グループ".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <LdapNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                groups.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "グループがありません。".to_string())/>
                    }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|g: LdapGroup| {
                            let g_members = g.clone();
                            let dn_d = g.dn.clone();
                            let cn_d = g.cn.clone();
                            let count = g.members.len();
                            view! {
                                <tr>
                                    <td>{g.cn.clone()}</td>
                                    <td>{g.description.clone().unwrap_or_default()}</td>
                                    <td>{count}</td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm"
                                            on:click=move |_| { members_group.set(Some(g_members.clone())); member_error.set(None); members_open.set(true); }>"メンバー"</button>
                                        <button class="icon-button" title="削除"
                                            on:click=move |_| { delete_target.set(Some((dn_d.clone(), cn_d.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr><th>"CN"</th><th>"説明"</th><th>"メンバー数"</th><th>"操作"</th></tr></thead>
                                <tbody>{rows}</tbody>
                            </table>
                        }.into_any()
                    }
                })
            }}
        </Suspense>

        // Create slide-over.
        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">"グループの作成"</h2>
                    <label class="field">
                        <span class="field-label">"親 DN"</span>
                        <select class="input" on:change=move |ev| parent_dn.set(event_target_value(&ev)) prop:value=move || parent_dn.get()>
                            <Suspense fallback=|| ()>
                                {move || parents.get().map(|res| res.unwrap_or_default().into_iter().map(|dn| { let label = dn.clone(); view! { <option value=dn>{label}</option> } }).collect_view())}
                            </Suspense>
                        </select>
                    </label>
                    <label class="field"><span class="field-label">"CN"</span>
                        <input class="input" prop:value=move || cn.get() on:input=move |ev| cn.set(event_target_value(&ev))/></label>
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

        // Member management slide-over.
        <Show when=move || members_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| members_open.set(false)>
                <div class="slideover" on:click=|ev| ev.stop_propagation()>
                    <h2 class="slideover-title">"メンバー管理"</h2>
                    {move || members_group.get().map(|g| {
                        let gdn_add = g.dn.clone();
                        let member_rows = g.members.iter().cloned().map(|m| {
                            let gdn = g.dn.clone();
                            let m_disp = m.clone();
                            view! {
                                <li class="member-row">
                                    <span class="mono">{m_disp}</span>
                                    <button class="icon-button" title="削除"
                                        on:click=move |_| { remove.dispatch(RemoveMember { group_dn: gdn.clone(), member_dn: m.clone() }); }>"\u{2715}"</button>
                                </li>
                            }
                        }).collect_view();
                        view! {
                            <p class="mono">{g.dn.clone()}</p>
                            <ul class="member-list">{member_rows}</ul>
                            <label class="field"><span class="field-label">"メンバー DN を追加"</span>
                                <input class="input" prop:value=move || new_member.get() on:input=move |ev| new_member.set(event_target_value(&ev))/></label>
                            {move || member_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                            <button class="btn btn-primary" type="button"
                                on:click=move |_| { add.dispatch(AddMember { group_dn: gdn_add.clone(), member_dn: new_member.get() }); }>"追加"</button>
                        }
                    })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| members_open.set(false)>"閉じる"</button>
                    </div>
                </div>
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
