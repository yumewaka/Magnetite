//! Watch host group management (S-WATCH-04).

use super::nav::WatchNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::watch::{
    list_watch_groups, list_watch_hosts, DeleteWatchGroup, SaveWatchGroup,
};
use leptos::prelude::*;
use magnetite_core::domains::watch::model::HostGroup;

#[component]
pub fn WatchGroupsPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let groups = Resource::new(move || reload.get(), |_| list_watch_groups());
    let hosts = Resource::new(|| (), |_| list_watch_hosts());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());
    let members = RwSignal::new(Vec::<String>::new());

    let open_create = move |_| {
        edit_id.set(String::new());
        name.set(String::new());
        description.set(String::new());
        members.set(Vec::new());
        form_open.set(true);
    };
    let open_edit = move |g: HostGroup| {
        edit_id.set(g.id.clone());
        name.set(g.name.clone());
        description.set(g.description.clone().unwrap_or_default());
        members.set(g.members.clone());
        form_open.set(true);
    };

    let save = ServerAction::<SaveWatchGroup>::new();
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
        let group = HostGroup {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            name: name.get(),
            description: {
                let d = description.get();
                if d.trim().is_empty() {
                    None
                } else {
                    Some(d)
                }
            },
            members: members.get(),
        };
        save.dispatch(SaveWatchGroup { group });
    };

    let delete = ServerAction::<DeleteWatchGroup>::new();
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
        Some((_, n)) => format!("グループ「{n}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, name)) = delete_target.get() {
            delete.dispatch(DeleteWatchGroup { id, name });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "ホストグループ".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <WatchNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                groups.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "グループがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|g: HostGroup| {
                            let g_edit = g.clone();
                            let id_d = g.id.clone();
                            let name_d = g.name.clone();
                            let count = g.members.len();
                            view! {
                                <tr>
                                    <td>{g.name.clone()}</td>
                                    <td>{g.description.clone().unwrap_or_default()}</td>
                                    <td>{count}</td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="編集" on:click=move |_| open_edit(g_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_d.clone(), name_d.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"名前"</th><th>"説明"</th><th>"ホスト数"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">{move || if edit_id.get().is_empty() { "グループの作成" } else { "グループの編集" }}</h2>
                    <label class="field"><span class="field-label">"名前"</span><input class="input" prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"説明（任意）"</span><input class="input" prop:value=move || description.get() on:input=move |ev| description.set(event_target_value(&ev))/></label>
                    <span class="field-label">"メンバー"</span>
                    <div class="host-picker">
                        <Suspense fallback=|| ()>
                            {move || hosts.get().map(|res| res.unwrap_or_default().into_iter().map(|h| {
                                let hn = h.name.clone();
                                let hn2 = h.name.clone();
                                let checked = { let n = h.name.clone(); move || members.get().contains(&n) };
                                view! {
                                    <label class="host-check">
                                        <input type="checkbox" prop:checked=checked on:change=move |ev| {
                                            let on = event_target_checked(&ev);
                                            members.update(|m| { if on { if !m.contains(&hn) { m.push(hn.clone()); } } else { m.retain(|x| x != &hn); } });
                                        }/>
                                        <span class="mono">{hn2}</span>
                                    </label>
                                }
                            }).collect_view())}
                        </Suspense>
                    </div>
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
