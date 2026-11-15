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
