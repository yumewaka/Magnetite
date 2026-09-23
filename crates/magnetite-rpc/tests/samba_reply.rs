//! Decode a **real Samba** `IDL_DRSGetNCChanges` V6 reply captured off the wire
//! (Tier C C1 4b-3). The fixture is a single-object full-sync reply for
//! `DC=magtest,DC=local` (the NC head), pulled from the live Samba DC via impacket.
//! This pins our `DRS_MSG_GETCHGREPLY_V6` decoder to Samba's exact NDR layout —
//! non-null `pNC`, a 42-entry schema prefix table, and per-node parent-GUID /
//! metadata-vector deferrals that our own lenient server never emits.

use magnetite_rpc::parse_get_nc_changes_reply;

const SAMBA_1OBJ: &[u8] = include_bytes!("fixtures/samba_getncchanges_1obj.bin");
const SAMBA_3OBJ: &[u8] = include_bytes!("fixtures/samba_getncchanges_3obj.bin");

#[test]
fn decodes_a_real_samba_getncchanges_reply() {
    let changes = parse_get_nc_changes_reply(SAMBA_1OBJ).expect("real Samba V6 reply must decode");

    // The reply carries exactly the one requested object: the domain NC head.
    assert_eq!(changes.objects.len(), 1);
    let obj = &changes.objects[0];
    assert_eq!(obj.name, "DC=magtest,DC=local");
    // Samba sends a rich attribute set for the NC head.
    assert!(obj.attrs.len() >= 30, "attrs = {}", obj.attrs.len());

    // The source invocation id (the UTDV cursor key) is the reply header GUID.
    assert_ne!(changes.source_invocation_id, [0u8; 16]);
    // A single-object page of a larger NC reports more data to come.
    assert!(changes.more_data);
}

#[test]
fn decodes_a_multi_object_page_in_wire_order() {
    // A 3-object page exercises the REPLENTINFLIST linked list (depth-first, so
    // payloads unwind tail-first), per-node parent-GUID + metadata-vector deferrals,
    // and the 42-entry schema prefix table.
    let changes =
        parse_get_nc_changes_reply(SAMBA_3OBJ).expect("real Samba 3-object V6 reply must decode");
    let names: Vec<&str> = changes.objects.iter().map(|o| o.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "DC=magtest,DC=local",
            "CN=Users,DC=magtest,DC=local",
            "CN=Computers,DC=magtest,DC=local",
        ]
    );
    // Every object carries decoded attributes.
    assert!(changes.objects.iter().all(|o| !o.attrs.is_empty()));
}

#[test]
fn decodes_per_attribute_replication_metadata() {
    // Samba stamps every replicated attribute with a PROPERTY_META_DATA_EXT (version,
    // originating DSA/USN/time); the decoder zips it onto each attribute.
    let changes = parse_get_nc_changes_reply(SAMBA_3OBJ).expect("decode");
    let obj = &changes.objects[0]; // DC=magtest,DC=local (the NC head)
    assert!(
        obj.attrs.iter().all(|a| a.metadata.is_some()),
        "every attribute carries replication metadata"
    );
    let m = obj.attrs[0].metadata.expect("metadata present");
    assert!(m.version >= 1, "a real version");
    assert!(m.originating_usn > 0, "a real originating USN");
    // In a freshly provisioned single-DC domain, changes originate at the source DSA.
    assert_eq!(m.originating_dsa, changes.source_invocation_id);
}
