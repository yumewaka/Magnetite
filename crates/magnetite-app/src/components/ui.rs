//! Standard UI kit primitives (10). These are the single source of truth for
//! how lists, states and badges look across every screen.

use leptos::prelude::*;
use magnetite_core::i18n::use_i18n;

/// Page header with a title and an optional actions area (10 §2.1).
#[component]
pub fn PageHeader(
    #[prop(into)] title: Signal<String>,
    #[prop(optional)] subtitle: Option<Signal<String>>,
    #[prop(optional)] children: Option<Children>,
) -> impl IntoView {
    view! {
        <header class="page-header">
            <div class="page-header-titles">
                <h1 class="page-title">{move || title.get()}</h1>
                {subtitle.map(|s| view! { <p class="page-subtitle">{move || s.get()}</p> })}
            </div>
            <div class="page-header-actions">
                {children.map(|c| c())}
            </div>
        </header>
    }
}

/// Health status badge — colour plus text label, never colour alone (06 §2).
#[component]
pub fn StatusBadge(#[prop(into)] health: Signal<String>) -> impl IntoView {
    let i18n = use_i18n();
    let class = move || match health.get().as_str() {
        "healthy" => "badge badge-success",
        "warning" => "badge badge-warning",
        "error" => "badge badge-danger",
        _ => "badge badge-unknown",
    };
    let label_key = move || match health.get().as_str() {
        "healthy" => "health.healthy",
        "warning" => "health.warning",
        "error" => "health.error",
        "disabled" => "health.disabled",
        _ => "health.unknown",
    };
    view! {
        <span class=class>
            <span class="badge-dot"></span>
            {move || i18n.t(label_key())}
        </span>
    }
}

/// Empty-state placeholder (10 §2.9). `message` is a localized string.
#[component]
pub fn EmptyState(#[prop(into)] message: Signal<String>) -> impl IntoView {
    view! {
        <div class="state-block empty-state">
            <p>{move || message.get()}</p>
        </div>
    }
}

/// Loading skeleton placeholder.
#[component]
pub fn LoadingState() -> impl IntoView {
    let i18n = use_i18n();
    view! {
        <div class="state-block loading-state" aria-busy="true">
            <div class="skeleton-row"></div>
            <div class="skeleton-row"></div>
            <div class="skeleton-row"></div>
            <span class="sr-only">{move || i18n.t("state.loading")}</span>
        </div>
    }
}

/// Error state with a retry button (10 §2.9).
#[component]
pub fn ErrorState(#[prop(into)] on_retry: Callback<()>) -> impl IntoView {
    let i18n = use_i18n();
    view! {
        <div class="state-block error-state" role="alert">
            <p>{move || i18n.t("state.error")}</p>
            <button class="btn btn-secondary" on:click=move |_| on_retry.run(())>
                {move || i18n.t("action.retry")}
            </button>
        </div>
    }
}
