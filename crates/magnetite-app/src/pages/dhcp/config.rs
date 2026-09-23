//! DHCP settings (S-DHCP-05). Magnetite owns the config in its DB, so this view
//! both shows and edits the values (save = Control/Admin, audited).

use super::nav::DhcpNav;
use crate::components::toast::use_toast;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::dhcp::{get_dhcp_config, SaveDhcpConfig};
use leptos::prelude::*;
use magnetite_core::domains::dhcp::model::DhcpConfig;

#[component]
pub fn ConfigPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let config = Resource::new(move || reload.get(), |_| get_dhcp_config());

    let v4 = RwSignal::new(true);
    let v6 = RwSignal::new(false);
    let default_lease = RwSignal::new(String::new());
    let max_lease = RwSignal::new(String::new());
    let authoritative = RwSignal::new(true);
    let domain = RwSignal::new(String::new());
    let dns = RwSignal::new(String::new());
    let loaded = RwSignal::new(false);

    // Populate the form once when the config resolves.
    Effect::new(move |_| {
        if let Some(Ok(c)) = config.get() {
            if !loaded.get() {
                v4.set(c.v4_enabled);
                v6.set(c.v6_enabled);
                default_lease.set(c.default_lease_secs.to_string());
                max_lease.set(c.max_lease_secs.map(|n| n.to_string()).unwrap_or_default());
                authoritative.set(c.authoritative);
                domain.set(c.default_domain_name.clone().unwrap_or_default());
                dns.set(c.default_dns_servers.join(", "));
                loaded.set(true);
            }
        }
    });

    let save = ServerAction::<SaveDhcpConfig>::new();
    let save_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = save.value().get() {
            match result {
                Ok(()) => {
                    save_error.set(None);
                    toast.success("設定を保存しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => save_error.set(Some(e.to_string())),
            }
        }
    });
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let dns_servers: Vec<String> = dns
            .get()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let cfg = DhcpConfig {
            v4_enabled: v4.get(),
            v6_enabled: v6.get(),
            default_lease_secs: default_lease.get().trim().parse::<u32>().unwrap_or(0),
            max_lease_secs: max_lease.get().trim().parse::<u32>().ok(),
            default_dns_servers: dns_servers,
            default_domain_name: {
                let d = domain.get();
                if d.trim().is_empty() {
                    None
                } else {
                    Some(d)
                }
            },
            authoritative: authoritative.get(),
        };
        save.dispatch(SaveDhcpConfig { config: cfg });
    };

    view! {
        <PageHeader title=Signal::derive(|| "DHCP 設定".to_string())>
            <button class="btn btn-secondary" on:click=move |_| reload.update(|n| *n += 1)>"更新"</button>
        </PageHeader>
        <DhcpNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                config.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(_) => view! {
                        <form class="config-form" on:submit=submit>
                            <label class="field field-inline">
                                <input type="checkbox" prop:checked=move || v4.get()
                                    on:change=move |ev| v4.set(event_target_checked(&ev))/>
                                <span>"IPv4 を有効化"</span>
                            </label>
                            <label class="field field-inline">
                                <input type="checkbox" prop:checked=move || v6.get()
                                    on:change=move |ev| v6.set(event_target_checked(&ev))/>
                                <span>"IPv6 を有効化"</span>
                            </label>
                            <label class="field">
                                <span class="field-label">"既定リース期間（秒）"</span>
                                <input class="input" type="number" prop:value=move || default_lease.get()
                                    on:input=move |ev| default_lease.set(event_target_value(&ev))/>
                            </label>
                            <label class="field">
                                <span class="field-label">"最大リース期間（秒・任意）"</span>
                                <input class="input" type="number" prop:value=move || max_lease.get()
                                    on:input=move |ev| max_lease.set(event_target_value(&ev))/>
                            </label>
                            <label class="field">
                                <span class="field-label">"既定ドメイン名"</span>
                                <input class="input" prop:value=move || domain.get()
                                    on:input=move |ev| domain.set(event_target_value(&ev))/>
                            </label>
                            <label class="field">
                                <span class="field-label">"既定 DNS サーバー（カンマ区切り）"</span>
                                <input class="input" prop:value=move || dns.get()
                                    on:input=move |ev| dns.set(event_target_value(&ev))/>
                            </label>
                            <label class="field field-inline">
                                <input type="checkbox" prop:checked=move || authoritative.get()
                                    on:change=move |ev| authoritative.set(event_target_checked(&ev))/>
                                <span>"権威サーバー (authoritative)"</span>
                            </label>
                            {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                            <div class="slideover-actions">
                                <button type="submit" class="btn btn-primary" prop:disabled=move || save.pending().get()>"保存"</button>
                            </div>
                        </form>
                    }.into_any(),
                })
            }}
        </Suspense>
    }
}
