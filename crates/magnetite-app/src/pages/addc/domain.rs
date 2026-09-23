//! Domain join / leave: promote this host into an existing AD domain as a replica
//! DC (the full DRS-driven [`magnetite_addc::promote`] orchestration), or demote a
//! DC out of the domain (metadata cleanup via LDAP). Both actions are Admin-gated,
//! audited, and long-running — the form shows a pending state and reports the result.

use super::nav::AddcNav;
use crate::components::toast::use_toast;
use crate::components::ui::PageHeader;
use crate::server_fns::addc::{DomainJoinRequest, DomainLeaveRequest, JoinDomain, LeaveDomain};
use leptos::prelude::*;

/// A labelled text input bound to `sig`. `password` masks the field.
#[component]
fn Field(
    label: &'static str,
    #[prop(optional)] placeholder: &'static str,
    #[prop(optional)] password: bool,
    sig: RwSignal<String>,
) -> impl IntoView {
    view! {
        <label class="field">
            <span class="field-label">{label}</span>
            <input
                class="input"
                type=if password { "password" } else { "text" }
                placeholder=placeholder
                prop:value=move || sig.get()
                on:input=move |ev| sig.set(event_target_value(&ev))
            />
        </label>
    }
}

/// A labelled checkbox bound to `sig`.
#[component]
fn Check(label: &'static str, sig: RwSignal<bool>) -> impl IntoView {
    view! {
        <label class="field field-inline">
            <input
                type="checkbox"
                prop:checked=move || sig.get()
                on:change=move |ev| sig.set(event_target_checked(&ev))
            />
            <span>{label}</span>
        </label>
    }
}

/// A TLS-mode selector (`ldaps` / `starttls` / `plaintext`) bound to `sig`.
#[component]
fn TlsSelect(sig: RwSignal<String>) -> impl IntoView {
    view! {
        <label class="field">
            <span class="field-label">"LDAP 接続方式"</span>
            <select class="input" on:change=move |ev| sig.set(event_target_value(&ev))>
                <option value="ldaps" selected=move || sig.get() == "ldaps">"LDAPS (暗黙TLS, 636)"</option>
                <option value="starttls" selected=move || sig.get() == "starttls">"StartTLS"</option>
                <option value="plaintext" selected=move || sig.get() == "plaintext">"平文 (テスト用)"</option>
            </select>
        </label>
    }
}

#[component]
pub fn DomainJoinPage() -> impl IntoView {
    view! {
        <PageHeader title=Signal::derive(|| "ドメイン参加 / 離脱".to_string())/>
        <AddcNav/>
        <p class="page-intro">
            "既存の Active Directory ドメインにこのホストをレプリカ DC として参加させる、"
            "または DC をドメインから離脱（メタデータ削除）させます。管理者権限が必要で、"
            "操作は監査ログに記録されます。処理には時間がかかる場合があります。"
        </p>
        <div class="card-grid">
            <JoinCard/>
            <LeaveCard/>
        </div>
    }
}

#[component]
fn JoinCard() -> impl IntoView {
    let toast = use_toast();
    let source_host = RwSignal::new(String::new());
    let bind_dn = RwSignal::new(String::new());
    let bind_password = RwSignal::new(String::new());
    let tls_mode = RwSignal::new("ldaps".to_string());
    let dc_name = RwSignal::new(String::new());
    let realm = RwSignal::new(String::new());
    let kdc = RwSignal::new(String::new());
    let drs = RwSignal::new(String::new());
    let admin_user = RwSignal::new(String::new());
    let admin_pass = RwSignal::new(String::new());
    let source_spn = RwSignal::new(String::new());
    let ip = RwSignal::new(String::new());
    let skip_dns = RwSignal::new(false);
    let request_rid_pool = RwSignal::new(false);

    let action = ServerAction::<JoinDomain>::new();
    let error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = action.value().get() {
            match result {
                Ok(_) => {
                    error.set(None);
                    toast.success("ドメインに参加しました。");
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        }
    });
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        error.set(None);
        action.dispatch(JoinDomain {
            req: DomainJoinRequest {
                source_host: source_host.get(),
                bind_dn: bind_dn.get(),
                bind_password: bind_password.get(),
                tls_mode: tls_mode.get(),
                dc_name: dc_name.get(),
                realm: realm.get(),
                kdc: kdc.get(),
                drs: drs.get(),
                admin_user: admin_user.get(),
                admin_pass: admin_pass.get(),
                source_spn: source_spn.get(),
                ip: ip.get(),
                skip_dns: skip_dns.get(),
                request_rid_pool: request_rid_pool.get(),
            },
        });
    };

    view! {
        <form class="panel" on:submit=submit>
            <h2 class="panel-title">"ドメインに参加 (レプリカ DC 昇格)"</h2>
            <Field label="ソース DC LDAP (host:port)" placeholder="dc1.example.com:636" sig=source_host/>
            <TlsSelect sig=tls_mode/>
            <Field label="バインド DN / UPN" placeholder="Administrator@EXAMPLE.COM" sig=bind_dn/>
            <Field label="バインドパスワード" password=true sig=bind_password/>
            <Field label="この DC の名前" placeholder="MAGNETITE" sig=dc_name/>
            <Field label="レルム" placeholder="EXAMPLE.COM" sig=realm/>
            <Field label="この DC の IPv4" placeholder="192.0.2.20" sig=ip/>
            <Field label="ソース DC KDC (host:port)" placeholder="dc1.example.com:88" sig=kdc/>
            <Field label="ソース DC DRSUAPI (host:port)" placeholder="dc1.example.com:1025" sig=drs/>
            <Field label="DRS 用管理者名" placeholder="Administrator" sig=admin_user/>
            <Field label="DRS 用管理者パスワード" password=true sig=admin_pass/>
            <Field label="ソース DC の SPN" placeholder="ldap/dc1.example.com" sig=source_spn/>
            <Check label="DC ロケーター DNS を書き込まない (skip_dns)" sig=skip_dns/>
            <Check label="RID プールを要求する" sig=request_rid_pool/>
            {move || error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
            <div class="slideover-actions">
                <button type="submit" class="btn btn-primary" prop:disabled=move || action.pending().get()>
                    {move || if action.pending().get() { "参加中…" } else { "参加を実行" }}
                </button>
            </div>
            {move || action.value().get().and_then(|r| r.ok()).map(|res| view! {
                <div class="result-block">
                    <h3>"作成されたオブジェクト"</h3>
                    <ul class="mono result-list">
                        <li>"computer: "{res.computer_dn}</li>
                        <li>"server: "{res.server_dn}</li>
                        <li>"nTDSDSA: "{res.ntds_dn}</li>
                        <li>"nTDSDSA GUID: "{res.ntds_guid}</li>
                        <li>"connection: "{res.connection_dn}</li>
                        {res.dns_nodes.into_iter().map(|d| view! { <li>"dns: "{d}</li> }).collect_view()}
                        {res.rid_pool.map(|p| view! { <li>"RID pool: "{p}</li> })}
                    </ul>
                </div>
            })}
        </form>
    }
}

#[component]
fn LeaveCard() -> impl IntoView {
    let toast = use_toast();
    let source_host = RwSignal::new(String::new());
    let bind_dn = RwSignal::new(String::new());
    let bind_password = RwSignal::new(String::new());
    let tls_mode = RwSignal::new("ldaps".to_string());
    let dc_name = RwSignal::new(String::new());
    let skip_dns = RwSignal::new(false);

    let action = ServerAction::<LeaveDomain>::new();
    let error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = action.value().get() {
            match result {
                Ok(_) => {
                    error.set(None);
                    toast.success("ドメインから離脱しました。");
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        }
    });
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        error.set(None);
        action.dispatch(LeaveDomain {
            req: DomainLeaveRequest {
                source_host: source_host.get(),
                bind_dn: bind_dn.get(),
                bind_password: bind_password.get(),
                tls_mode: tls_mode.get(),
                dc_name: dc_name.get(),
                skip_dns: skip_dns.get(),
            },
        });
    };

    view! {
        <form class="panel" on:submit=submit>
            <h2 class="panel-title">"ドメインから離脱 (DC 削除)"</h2>
            <Field label="残存 DC の LDAP (host:port)" placeholder="dc1.example.com:636" sig=source_host/>
            <TlsSelect sig=tls_mode/>
            <Field label="バインド DN / UPN" placeholder="Administrator@EXAMPLE.COM" sig=bind_dn/>
            <Field label="バインドパスワード" password=true sig=bind_password/>
            <Field label="離脱する DC の名前" placeholder="MAGNETITE" sig=dc_name/>
            <Check label="DNS レコードを削除しない (skip_dns)" sig=skip_dns/>
            {move || error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
            <div class="slideover-actions">
                <button type="submit" class="btn btn-danger" prop:disabled=move || action.pending().get()>
                    {move || if action.pending().get() { "離脱中…" } else { "離脱を実行" }}
                </button>
            </div>
            {move || action.value().get().and_then(|r| r.ok()).map(|res| view! {
                <div class="result-block">
                    <h3>"削除したオブジェクト"</h3>
                    <ul class="mono result-list">
                        {res.removed.into_iter().map(|d| view! { <li>{d}</li> }).collect_view()}
                    </ul>
                    {(!res.errors.is_empty()).then(|| view! {
                        <>
                            <h3>"削除できなかったオブジェクト"</h3>
                            <ul class="mono result-list result-errors">
                                {res.errors.into_iter().map(|(dn, reason)| view! {
                                    <li>{dn}" — "{reason}</li>
                                }).collect_view()}
                            </ul>
                        </>
                    })}
                </div>
            })}
        </form>
    }
}
