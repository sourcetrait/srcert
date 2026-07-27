//! Profile locks: where a profile lands, and what a name may not do.
use crate::profile::{
    default_profile_path,
    install_profile,
    installed_profiles,
    load_profile,
    profile_exists,
    profile_path,
    validate_snake,
};

const QUEST: &str = r#"
name = "quest"
organization = "SourceTrait"
validity_days = 3650

[authority]
common_name = "SourceTrait Quest Local CA"

[entity]
common_name = "localhost"
subject_alt_names = ["127.0.0.1", "::1", "localhost"]
usages = ["server", "client"]
"#;

struct Scratch {
    root: std::path::PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("srcert_profile_{name}"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch root");
        Self { root }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn a_profile_lands_in_both_places() {
    let scratch = Scratch::new("both");
    let done = install_profile(&scratch.root, "quest", QUEST).expect("installs");

    assert!(done.written, "the live profile was absent");
    assert!(done.live.is_file());
    assert!(done.reference.is_file(), "the reference copy is written too");
    assert_eq!(done.live, profile_path(&scratch.root, "quest").unwrap());
    assert_eq!(
        done.reference,
        default_profile_path(&scratch.root, "quest").unwrap()
    );
    assert_ne!(done.live, done.reference);
}

#[test]
fn a_customised_profile_survives_reinstall_while_the_reference_refreshes() {
    let scratch = Scratch::new("customised");
    install_profile(&scratch.root, "quest", QUEST).expect("installs");

    let live = profile_path(&scratch.root, "quest").unwrap();
    let customised = QUEST.replace("3650", "30");
    std::fs::write(&live, &customised).expect("the user edits their profile");

    let again = install_profile(&scratch.root, "quest", QUEST).expect("reinstalls");
    assert!(!again.written, "an existing live profile is left alone");
    assert_eq!(
        std::fs::read_to_string(&live).unwrap(),
        customised,
        "the customisation survives"
    );
    assert_eq!(
        std::fs::read_to_string(&again.reference).unwrap(),
        QUEST,
        "the reference says what the application ships"
    );
    assert_eq!(
        load_profile(&scratch.root, "quest").unwrap().validity_days,
        30,
        "the LIVE profile is the one consumed"
    );
}

#[test]
fn an_unparsable_profile_is_refused_before_anything_is_written() {
    let scratch = Scratch::new("refused");
    assert!(install_profile(&scratch.root, "quest", "not = [valid").is_err());
    assert!(!profile_exists(&scratch.root, "quest").unwrap());
    assert!(!default_profile_path(&scratch.root, "quest").unwrap().is_file());
}

#[test]
fn a_missing_profile_names_itself_and_where_it_was_expected() {
    let scratch = Scratch::new("missing");
    let error = load_profile(&scratch.root, "quest").expect_err("no profile");
    let text = error.to_string();
    assert!(text.contains("quest"), "{text}");
    assert!(text.contains("srcert"), "{text}");
}

#[test]
fn a_name_cannot_climb_out_or_be_cleaned() {
    for hostile in ["..", "../elsewhere", "a/b", "", "Quest", "a b", "a.b"] {
        assert!(
            validate_snake(hostile).is_err(),
            "{hostile:?} must be refused as a profile name"
        );
    }
    assert!(validate_snake("quest").is_ok());
    assert!(validate_snake("grammar_two").is_ok());
}

#[test]
fn installed_profiles_lists_only_the_live_ones() {
    let scratch = Scratch::new("listing");
    assert!(installed_profiles(&scratch.root).unwrap().is_empty());

    install_profile(&scratch.root, "quest", QUEST).expect("installs");
    install_profile(&scratch.root, "grammar", &QUEST.replace("quest", "grammar"))
        .expect("installs");

    assert_eq!(
        installed_profiles(&scratch.root).unwrap(),
        vec![String::from("grammar"), String::from("quest")]
    );
}
