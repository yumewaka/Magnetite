//! FSMO (operations-master) roles: view the five roles and their current holders
//! (`fSMORoleOwner`), and seize a role to this magnetite DC. Seizing is the
//! `ntdsutil` / `samba-tool fsmo seize` equivalent — for when the current holder is
//! permanently gone. Graceful transfer to a running peer is driven by the join flow's
//! DRS client and is not offered here.

use super::nav::AddcNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::addc::{list_fsmo_roles, FsmoRoleInfo, SeizeFsmoRole};
use leptos::prelude::*;

#[component]
pub fn FsmoPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let roles = Resource::new(move || reload.get(), |_| list_fsmo_roles());

    let seize = ServerAction::<SeizeFsmoRole>::new();
    Effect::new(move |_| {
        if let Some(result) = seize.value().get() {
            match result {
                Ok(()) => {
                    toast.success("ロールを奪取しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => toast.error(e.to_string()),
            }
        }
    });

    let confirm_open = RwSignal::new(false);
    let target = RwSignal::new(Option::<(String, String)>::None);
    Effect::new(move |_| {
        if !confirm_open.get() {
            target.set(None);
        }
    });
    let confirm_body = Signal::derive(move || {
        match target.get() {
        Some((_, label)) => format!(
            "「{label}」をこの DC に奪取します。現在の保持者が完全に停止している場合のみ実行してください。よろしいですか？"
        ),
        None => String::new(),
    }
    });
    let on_confirm = Callback::new(move |_| {
        if let Some((role, _)) = target.get() {
            seize.dispatch(SeizeFsmoRole { role });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "FSMO ロール".to_string())/>
        <AddcNav/>
        <p class="page-intro">
            "5 つの操作マスター（FSMO）ロールの現在の保持者を表示します。保持者が完全に"
            "失われた場合は、この magnetite DC にロールを「奪取」できます（"<code>"ntdsutil"</code>
            " / "<code>"samba-tool fsmo seize"</code>" 相当）。稼働中のピアへの通常の移管は"
            "「ドメイン参加/離脱」の DRS フローで行います。"
        </p>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                roles.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|r: FsmoRoleInfo| {
                            let role_key = r.role.clone();
                            let label = r.label.clone();
                            let held = r.held_locally;
                            let owner = r.owner.clone().unwrap_or_else(|| "（未設定）".to_string());
                            view! {
                                <tr>
                                    <td>{r.label.clone()}</td>
                                    <td class="mono">{owner}</td>
                                    <td>
                                        {if held {
                                            view! { <span class="badge badge-success">"このDC"</span> }.into_any()
                                        } else {
                                            view! { <span class="badge badge-unknown">"他のDC"</span> }.into_any()
                                        }}
                                    </td>
                                    <td class="row-actions">
                                        <button class="btn btn-danger btn-sm" prop:disabled=move || held || seize.pending().get()
                                            on:click=move |_| { target.set(Some((role_key.clone(), label.clone()))); confirm_open.set(true); }>"奪取"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr><th>"ロール"</th><th>"保持者 (fSMORoleOwner)"</th><th>"状態"</th><th>"操作"</th></tr></thead>
                                <tbody>{rows}</tbody>
                            </table>
                        }.into_any()
                    }
                })
            }}
        </Suspense>

        <ConfirmDialog
            title=Signal::derive(|| "ロール奪取の確認".to_string())
            body=confirm_body
            open=confirm_open
            on_confirm=on_confirm
        />
    }
}
