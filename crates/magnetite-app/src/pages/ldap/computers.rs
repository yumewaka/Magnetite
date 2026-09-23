//! LDAP computer management: list `computer` entries and create one under a chosen
//! OU (objectClass `computer`, `sAMAccountName=<cn>$`, optional `dNSHostName`).
//! Deletion reuses the generic entry delete (OU/children guard applies server-side).

use super::nav::LdapNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::ldap::{list_computers, list_parents, CreateComputer, DeleteEntry};
use leptos::prelude::*;
use magnetite_core::domains::ldap::model::DirectoryEntry;

/// First value of `attr` (case-insensitive) on `e`, or empty.
fn attr(e: &DirectoryEntry, name: &str) -> String {
    e.attributes
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.first())
        .cloned()
        .unwrap_or_default()
}

#[component]
pub fn ComputersPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let computers = Resource::new(move || reload.get(), |_| list_computers());
    let parents = Resource::new(|| (), |_| list_parents());

    let form_open = RwSignal::new(false);
    let parent_dn = RwSignal::new(String::new());
    let cn = RwSignal::new(String::new());
    let dns_host = RwSignal::new(String::new());
    let create = ServerAction::<CreateComputer>::new();
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
        dns_host.set(String::new());
        save_error.set(None);
        form_open.set(true);
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create.dispatch(CreateComputer {
            parent_dn: parent_dn.get(),
            cn: cn.get(),
            dns_host_name: dns_host.get(),
        });
    };

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
        Some((_, cn)) => format!("コンピュータ「{cn}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((dn, _)) = delete_target.get() {
            delete.dispatch(DeleteEntry { dn });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "LDAP コンピュータ".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <LdapNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                computers.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "コンピュータがありません。".to_string())/>
                    }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|e: DirectoryEntry| {
                            let cn_v = attr(&e, "cn");
                            let sam = attr(&e, "sAMAccountName");
                            let host = attr(&e, "dNSHostName");
                            let dn_d = e.dn.clone();
                            let cn_d = cn_v.clone();
                            view! {
                                <tr>
                                    <td>{cn_v}</td>
                                    <td class="mono">{sam}</td>
                                    <td class="mono">{host}</td>
                                    <td class="mono">{e.dn.clone()}</td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="削除"
                                            on:click=move |_| { delete_target.set(Some((dn_d.clone(), cn_d.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr><th>"名前"</th><th>"sAMAccountName"</th><th>"dNSHostName"</th><th>"DN"</th><th>"操作"</th></tr></thead>
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
                    <h2 class="slideover-title">"コンピュータの作成"</h2>
                    <label class="field">
                        <span class="field-label">"親 DN"</span>
                        <select class="input" on:change=move |ev| parent_dn.set(event_target_value(&ev)) prop:value=move || parent_dn.get()>
                            <Suspense fallback=|| ()>
                                {move || parents.get().map(|res| res.unwrap_or_default().into_iter().map(|dn| { let label = dn.clone(); view! { <option value=dn>{label}</option> } }).collect_view())}
                            </Suspense>
                        </select>
                    </label>
                    <label class="field"><span class="field-label">"コンピュータ名 (cn)"</span>
                        <input class="input" prop:value=move || cn.get() on:input=move |ev| cn.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"DNS ホスト名（任意）"</span>
                        <input class="input" prop:value=move || dns_host.get() on:input=move |ev| dns_host.set(event_target_value(&ev)) placeholder="host.example.com"/></label>
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
