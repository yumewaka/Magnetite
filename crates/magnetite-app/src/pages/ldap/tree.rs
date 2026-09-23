//! LDAP directory tree (S-LDAP-02): lazy-expanded DIT with an entry detail
//! panel. Nodes fetch their children on expand.

use super::nav::LdapNav;
use crate::components::toast::use_toast;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::ldap::{get_entry, get_tree_children, get_tree_root, list_ous, MoveEntry};
use leptos::prelude::*;
use magnetite_core::domains::ldap::model::{LdapOu, TreeNode};

/// Shared selected-DN signal for the detail panel.
#[derive(Clone, Copy)]
struct SelectedDn(RwSignal<Option<String>>);

/// Shared tree-reload counter so the detail panel can refresh the tree after a move.
#[derive(Clone, Copy)]
struct TreeReload(RwSignal<u32>);

#[component]
pub fn TreePage() -> impl IntoView {
    let selected = RwSignal::new(Option::<String>::None);
    provide_context(SelectedDn(selected));
    let reload_sig = RwSignal::new(0_u32);
    provide_context(TreeReload(reload_sig));
    let roots = Resource::new(move || reload_sig.get(), |_| get_tree_root());
    let reload = Callback::new(move |_| roots.refetch());

    view! {
        <PageHeader title=Signal::derive(|| "ディレクトリツリー".to_string())>
            <button class="btn btn-secondary" on:click=move |_| roots.refetch()>"再取得"</button>
        </PageHeader>
        <LdapNav/>
        <div class="tree-layout">
            <div class="tree-panel" role="tree">
                <Suspense fallback=|| view! { <LoadingState/> }>
                    {move || {
                        roots.get().map(|res| match res {
                            Err(_) => view! { <ErrorState on_retry=reload/> }.into_any(),
                            Ok(nodes) if nodes.is_empty() => {
                                view! { <p class="empty-note">"ディレクトリにエントリがありません。"</p> }.into_any()
                            }
                            Ok(nodes) => view! {
                                <ul class="tree-list">
                                    {nodes.into_iter().map(|n| view! { <TreeNodeItem node=n/> }).collect_view()}
                                </ul>
                            }.into_any(),
                        })
                    }}
                </Suspense>
            </div>
            <div class="detail-panel">
                <DetailPanel/>
            </div>
        </div>
    }
}

#[component]
fn TreeNodeItem(node: TreeNode) -> impl IntoView {
    let selected = expect_context::<SelectedDn>().0;
    let expanded = RwSignal::new(false);
    let dn = node.dn.clone();
    let has_children = node.has_children;

    let children = Resource::new(
        move || (expanded.get(), dn.clone()),
        |(exp, dn)| async move {
            if exp {
                get_tree_children(dn).await
            } else {
                Ok(Vec::new())
            }
        },
    );

    let dn_select = node.dn.clone();
    let is_selected = {
        let dn = node.dn.clone();
        move || selected.get().as_deref() == Some(dn.as_str())
    };

    view! {
        <li class="tree-node" role="treeitem" aria-expanded=move || expanded.get().to_string()>
            <div class="tree-node-row" class:selected=is_selected>
                <Show when=move || has_children fallback=|| view! { <span class="tree-toggle-spacer"></span> }>
                    <button class="tree-toggle" on:click=move |_| expanded.update(|e| *e = !*e)>
                        {move || if expanded.get() { "\u{25BC}" } else { "\u{25B6}" }}
                    </button>
                </Show>
                <button class="tree-label" on:click={
                    let dn = dn_select.clone();
                    move |_| selected.set(Some(dn.clone()))
                }>
                    {node.rdn.clone()}
                </button>
            </div>
            <Show when=move || expanded.get() fallback=|| ()>
                <Suspense fallback=|| view! { <span class="tree-loading">"…"</span> }>
                    {move || children.get().map(|res| match res {
                        Ok(nodes) => view! {
                            <ul class="tree-list">
                                {nodes.into_iter().map(|n| view! { <TreeNodeItem node=n/> }).collect_view()}
                            </ul>
                        }.into_any(),
                        Err(_) => view! { <span class="tree-error">"取得失敗"</span> }.into_any(),
                    })}
                </Suspense>
            </Show>
        </li>
    }
}

#[component]
fn DetailPanel() -> impl IntoView {
    let toast = use_toast();
    let selected = expect_context::<SelectedDn>().0;
    let tree_reload = expect_context::<TreeReload>().0;
    let entry_reload = RwSignal::new(0_u32);
    let entry = Resource::new(
        move || (selected.get(), entry_reload.get()),
        |(dn, _)| async move {
            match dn {
                Some(dn) => get_entry(dn).await,
                None => Ok(None),
            }
        },
    );
    let ous = Resource::new(|| (), |_| list_ous());

    // Move state: the chosen target parent OU + the move action.
    let target_parent = RwSignal::new(String::new());
    let move_action = ServerAction::<MoveEntry>::new();
    Effect::new(move |_| {
        if let Some(result) = move_action.value().get() {
            match result {
                Ok(()) => {
                    toast.success("移動しました。");
                    // Follow the entry to its new location and refresh both views.
                    if let (Some(dn), parent) = (selected.get(), target_parent.get()) {
                        if let Some((rdn, _)) = dn.split_once(',') {
                            selected.set(Some(format!("{rdn},{parent}")));
                        }
                    }
                    entry_reload.update(|n| *n += 1);
                    tree_reload.update(|n| *n += 1);
                }
                Err(e) => toast.error(e.to_string()),
            }
        }
    });

    view! {
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                entry.get().map(|res| match res {
                    Err(_) => view! { <p class="empty-note">"エントリの取得に失敗しました。"</p> }.into_any(),
                    Ok(None) => view! { <p class="empty-note">"エントリを選択してください。"</p> }.into_any(),
                    Ok(Some(e)) => {
                        let rows = e.attributes.iter().map(|(k, values)| {
                            let vals = values.join("\n");
                            view! {
                                <tr>
                                    <td class="attr-name">{k.clone()}</td>
                                    <td class="attr-value mono">{vals}</td>
                                </tr>
                            }
                        }).collect_view();
                        let entry_dn = e.dn.clone();
                        let can_move = !e.has_children;
                        let ou_options = move || ous.get().map(|res| match res {
                            Ok(list) => list.into_iter().map(|o: LdapOu| view! {
                                <option value=o.dn.clone()>{o.dn.clone()}</option>
                            }).collect_view().into_any(),
                            Err(_) => ().into_any(),
                        });
                        let do_move = {
                            let entry_dn = entry_dn.clone();
                            move |_| {
                                let parent = target_parent.get();
                                if parent.trim().is_empty() {
                                    toast.error("移動先の OU を選択してください。");
                                    return;
                                }
                                move_action.dispatch(MoveEntry { dn: entry_dn.clone(), new_parent: parent });
                            }
                        };
                        view! {
                            <div class="entry-detail">
                                <p><strong>"DN: "</strong><span class="mono">{e.dn.clone()}</span></p>
                                <p><strong>"objectClass: "</strong>{e.object_classes.join(", ")}</p>
                                <table class="data-table">
                                    <thead><tr><th>"属性"</th><th>"値"</th></tr></thead>
                                    <tbody>{rows}</tbody>
                                </table>
                                <div class="move-box">
                                    <span class="field-label">"OU を移動"</span>
                                    {if can_move {
                                        view! {
                                            <div class="move-row">
                                                <select class="input" on:change=move |ev| target_parent.set(event_target_value(&ev))>
                                                    <option value="">"— 移動先 OU —"</option>
                                                    {ou_options}
                                                </select>
                                                <button class="btn btn-secondary" prop:disabled=move || move_action.pending().get() on:click=do_move>"移動"</button>
                                            </div>
                                        }.into_any()
                                    } else {
                                        view! { <p class="field-hint">"子を持つエントリは移動できません。"</p> }.into_any()
                                    }}
                                </div>
                            </div>
                        }.into_any()
                    }
                })
            }}
        </Suspense>
    }
}
