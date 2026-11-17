#[test]
fn reusable_observation_component_is_read_only_and_application_free() {
    let source = include_str!("../src/lib.rs");
    assert!(source.contains("ReadOnlyClient"));
    assert!(!source.contains("AuthorityClient"));
    assert!(!source.contains("AdminClient"));
    assert!(!source.contains("CommandV1::RevokeEpoch"));
    assert!(source.contains("NextPage"));
    assert!(source.contains("PreviousPage"));
    assert!(!source.contains("ratatui::run"));
    assert!(!source.contains("std::env::args"));
}

#[test]
fn reusable_control_calls_only_the_aegis_owned_guard() {
    let workspace = include_str!("../Cargo.toml");
    let cli = include_str!("../cli/Cargo.toml");
    let control = include_str!("../src/revoke_control.rs");
    assert!(workspace.contains("../aegis/crates/aegis-admin-command"));
    assert!(cli.contains("../../aegis/crates/aegis-admin-command"));
    assert!(cli.contains("../../aegis/applications/aegis-admin-session"));
    assert!(!workspace.contains("admin-session"));
    assert!(control.contains("aegis_admin_command::{RevokeEpoch, RevokeError, revoke_epoch}"));
    assert!(!control.contains("AdminClient"));
    assert!(!control.contains("CommandV1::RevokeEpoch"));
    assert!(control.contains("try_send(())"));
    assert!(!control.contains("while let"));
    assert!(include_str!("../cli/src/main.rs").contains("aegis_admin_session::run"));
    assert!(
        !std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("admin-command")
            .exists()
    );
}

#[test]
fn local_transport_is_owned_by_aegis_not_presentation() {
    let facade = include_str!("../local-client/src/lib.rs");
    let manifest = include_str!("../local-client/Cargo.toml");
    let readme = include_str!("../README.md");
    assert!(facade.contains("pub use aegis_local_client"));
    assert!(!facade.contains("UnixStream"));
    assert!(manifest.contains("aegis-local-client"));
    assert!(!manifest.contains("aegis-wire"));
    assert!(readme.contains("owner-maintained `aegis-local-client`"));
}
