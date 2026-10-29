//! Run locks: where an install's secret data home comes from.
use std::path::{Path, PathBuf};

use crate::run::resolve_secret_data;

fn profile() -> &'static Path {
    Path::new("/config/sourcetrait/srcert/profiles/quest.toml")
}

#[test]
fn the_flag_overrides_the_profile() {
    let home = resolve_secret_data(
        Some(PathBuf::from("/flag")),
        Some(PathBuf::from("/profile")),
        profile(),
    )
    .expect("resolves");
    assert_eq!(home, PathBuf::from("/flag"));
}

#[test]
fn the_profile_answers_without_the_flag() {
    let home = resolve_secret_data(None, Some(PathBuf::from("/profile")), profile())
        .expect("resolves");
    assert_eq!(home, PathBuf::from("/profile"));
}

#[test]
fn naming_neither_is_refused_with_the_profile_to_edit() {
    let error = resolve_secret_data(None, None, profile()).expect_err("neither is named");
    let text = error.to_string();
    assert!(text.contains("--secret-data"), "{text}");
    assert!(text.contains("quest.toml"), "{text}");
}
