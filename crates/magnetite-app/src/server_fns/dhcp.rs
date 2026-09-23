//! DHCP domain server functions (F-12 / S-DHCP): pools, reservations, leases
//! and config. Each write authorized (08_authz), validated (08_dhcp_logic §5)
//! and audited (F-04).

use crate::types::DhcpMetrics;
use leptos::prelude::*;
use magnetite_core::domains::dhcp::model::{DhcpConfig, Lease, Pool, Reservation};

#[cfg(feature = "ssr")]
async fn audit_dhcp(
    user: &magnetite_core::models::CurrentUser,
    action: magnetite_core::models::common::ActionKind,
    target_kind: &str,
    target_id: &str,
) {
    use crate::server_fns::auth::client_ip;
    use crate::state::AppState;
    let state = expect_context::<AppState>();
    let _ = state
        .db
        .append_audit(magnetite_core::models::NewAuditEntry {
            actor: user.subject.clone(),
            actor_role: user.role,
            domain: magnetite_core::domain::DomainKey::Dhcp,
            action,
            target_kind: target_kind.to_string(),
            target_id: target_id.to_string(),
            result: magnetite_core::models::common::OpResult::Success,
            ip: client_ip().await,
            detail: None,
        })
        .await;
}

/// DHCP dashboard metrics (S-DHCP-01).
#[server(GetDhcpMetrics, "/api")]
pub async fn get_dhcp_metrics() -> Result<DhcpMetrics, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let (pools, reservations, active) = state
        .db
        .dhcp_metrics()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(DhcpMetrics {
        pool_count: pools as u64,
        reservation_count: reservations as u64,
        active_lease_count: active as u64,
    })
}

// ---- Pools ----------------------------------------------------------------

/// List DHCP pools (S-DHCP-02).
#[server(ListPools, "/api")]
pub async fn list_pools() -> Result<Vec<Pool>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_pools()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Fetch one pool (for the reservation page header).
#[server(GetPool, "/api")]
pub async fn get_pool(id: String) -> Result<Option<Pool>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .get_pool(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create (id empty) or update a pool (S-DHCP-02). Validates ranges (AC-14).
#[server(SavePool, "/api")]
pub async fn save_pool(pool: Pool) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::dhcp::validate::check_pool;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_pool(&pool).map_err(ServerFnError::new)?;
    let state = expect_context::<AppState>();
    let is_create = pool.id.is_empty();
    let outcome = if is_create {
        state.db.create_pool(&pool).await.map(|p| p.id)
    } else {
        state.db.update_pool(&pool).await.map(|_| pool.id.clone())
    };
    match outcome {
        Ok(id) => {
            audit_dhcp(
                &user,
                if is_create {
                    ActionKind::Create
                } else {
                    ActionKind::Update
                },
                "pool",
                &id,
            )
            .await;
            Ok(())
        }
        Err(e) => Err(ServerFnError::new(e.to_string())),
    }
}

/// Active lease count for a pool (drives the delete confirmation).
#[server(CountPoolActiveLeases, "/api")]
pub async fn count_pool_active_leases(id: String) -> Result<u64, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .count_pool_active_leases(&id)
        .await
        .map(|n| n as u64)
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Delete a pool (S-DHCP-02).
#[server(DeletePool, "/api")]
pub async fn delete_pool(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_pool(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dhcp(&user, ActionKind::Delete, "pool", &id).await;
    Ok(())
}

// ---- Reservations ---------------------------------------------------------

/// List reservations for a pool (S-DHCP-03).
#[server(ListReservations, "/api")]
pub async fn list_reservations(pool_id: String) -> Result<Vec<Reservation>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_reservations(&pool_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a reservation (S-DHCP-03). Validates + normalizes the MAC.
#[server(CreateReservation, "/api")]
pub async fn create_reservation(reservation: Reservation) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::dhcp::validate::{check_reservation_fields, normalize_mac};
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let mut reservation = reservation;
    check_reservation_fields(&reservation.mac_address, &reservation.ip_address)
        .map_err(ServerFnError::new)?;
    reservation.mac_address =
        normalize_mac(&reservation.mac_address).unwrap_or(reservation.mac_address);
    let state = expect_context::<AppState>();
    let created = state
        .db
        .create_reservation(&reservation)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dhcp(&user, ActionKind::Create, "reservation", &created.id).await;
    Ok(())
}

/// Delete a reservation (S-DHCP-03).
#[server(DeleteReservation, "/api")]
pub async fn delete_reservation(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_reservation(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dhcp(&user, ActionKind::Delete, "reservation", &id).await;
    Ok(())
}

// ---- Leases ---------------------------------------------------------------

/// List leases, optionally filtered by pool (S-DHCP-04).
#[server(ListLeases, "/api")]
pub async fn list_leases(pool_id: Option<String>) -> Result<Vec<Lease>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_leases(pool_id.as_deref())
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Release a lease (S-DHCP-04). Only active/offered leases can be released.
#[server(ReleaseLease, "/api")]
pub async fn release_lease(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .release_lease(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dhcp(&user, ActionKind::Control, "lease", &id).await;
    Ok(())
}

// ---- Config ---------------------------------------------------------------

/// Fetch the DHCP config (S-DHCP-05).
#[server(GetDhcpConfig, "/api")]
pub async fn get_dhcp_config() -> Result<DhcpConfig, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .get_dhcp_config()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Save the DHCP config (S-DHCP-05). Control-class operation (Admin).
#[server(SaveDhcpConfig, "/api")]
pub async fn save_dhcp_config(config: DhcpConfig) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Control).await?;
    if config.default_lease_secs == 0 {
        return Err(ServerFnError::new("正の整数（秒）を入力してください。"));
    }
    let state = expect_context::<AppState>();
    state
        .db
        .save_dhcp_config(&config)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dhcp(&user, ActionKind::Control, "dhcp_config", "singleton").await;
    Ok(())
}
