//! Tier B multi-DC premise: two independent [`Db`] handles connected to ONE
//! networked SurrealDB (`ws://…`) see each other's writes — so a domain join
//! processed by DC1 is immediately visible to DC2, without any DRS replication.
//!
//! Gated on `MAGNETITE_TEST_DB_URL` (a running `ws://` server, e.g.
//! `surreal start --unauthenticated --bind 127.0.0.1:8000 memory`); when unset the
//! test is a no-op so the ordinary (hermetic) test run is unaffected.

use magnetite_db::Db;

#[tokio::test]
async fn two_handles_share_a_networked_store() {
    let Ok(url) = std::env::var("MAGNETITE_TEST_DB_URL") else {
        eprintln!("MAGNETITE_TEST_DB_URL unset — skipping networked shared-DB test");
        return;
    };

    // Two DC front-ends: independent connections to the same shared server.
    let dc1 = Db::connect_url(&url).await.expect("dc1 connect");
    let dc2 = Db::connect_url(&url).await.expect("dc2 connect");

    // DC1 provisions a machine account (as a domain join would over SAMR/LDAP).
    let name = "SHAREDDC$";
    dc1.upsert_ad_principal(name, 4242, "M@chinePw!42", "EXAMPLE.COM")
        .await
        .expect("dc1 create principal");

    // DC2, on the same store, immediately sees DC1's account — the whole point of
    // the shared-DB design (no per-DC replication, no split brain).
    let seen = dc2.list_ad_principals().await.expect("dc2 list principals");
    assert!(
        seen.iter()
            .any(|p| p.sam_account_name == name && p.rid == 4242),
        "DC2 must see DC1's account; saw {:?}",
        seen.iter()
            .map(|p| p.sam_account_name.as_str())
            .collect::<Vec<_>>()
    );

    // And the RID pool is shared: a block DC1 reserves is not handed out again to
    // DC2 (disjoint, climbing) — atomic allocation across front-ends.
    let b1 = dc1.reserve_rid_block(5000, 100).await.expect("dc1 reserve");
    let b2 = dc2.reserve_rid_block(5000, 100).await.expect("dc2 reserve");
    assert_ne!(
        b1, b2,
        "two front-ends reserved the SAME RID block base ({b1})"
    );
    assert!(
        b2 >= b1 + 100 || b1 >= b2 + 100,
        "RID blocks overlap: {b1} vs {b2}"
    );
}
