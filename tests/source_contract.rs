#[test]
fn reusable_component_is_read_only_and_application_free() {
    let source = include_str!("../src/lib.rs");
    assert!(source.contains("ReadOnlyClient"));
    assert!(!source.contains("AuthorityClient"));
    assert!(!source.contains("AdminClient"));
    assert!(!source.contains("RevokeEpoch"));
    assert!(source.contains("NextPage"));
    assert!(source.contains("PreviousPage"));
    assert!(!source.contains("ratatui::run"));
    assert!(!source.contains("std::env::args"));
}

#[test]
fn authority_command_guards_are_owned_by_aegis_not_presentation() {
    let workspace = include_str!("../Cargo.toml");
    let cli = include_str!("../cli/Cargo.toml");
    assert!(!workspace.contains("admin-command"));
    assert!(cli.contains("../../aegis/crates/aegis-admin-command"));
    assert!(cli.contains("../../aegis/applications/aegis-admin-session"));
    assert!(!workspace.contains("admin-session"));
    assert!(include_str!("../cli/src/main.rs").contains("aegis_admin_session::run"));
    assert!(
        !std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("admin-command")
            .exists()
    );
}
