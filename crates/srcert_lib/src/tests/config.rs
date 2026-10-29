//! Config locks: the usages field, and what a profile must declare.
use crate::config::{CertGenConfig, EntityUsage};

fn parse(text: &str) -> crate::Result<CertGenConfig> {
    CertGenConfig::parse(text, std::path::Path::new("<test>"))
}

const BASE: &str = r#"
name = "quest"
organization = "SourceTrait"

[authority]
common_name = "SourceTrait Quest Local CA"

[entity]
common_name = "localhost"
subject_alt_names = ["127.0.0.1", "localhost"]
"#;

#[test]
fn a_profile_without_usages_means_server_alone() {
    let config = parse(BASE).expect("parses");
    assert_eq!(config.entity.usages, vec![EntityUsage::Server]);
    assert_eq!(config.validity_days, 3650, "the default is deliberate");
}

#[test]
fn a_profile_can_ask_for_a_leaf_that_is_also_a_client() {
    let text = format!("{BASE}usages = [\"server\", \"client\"]\n");
    let config = parse(&text).expect("parses");
    assert_eq!(
        config.entity.usages,
        vec![EntityUsage::Server, EntityUsage::Client]
    );
    assert_eq!(
        config.extended_key_usages().len(),
        2,
        "both usages reach the leaf"
    );
}

#[test]
fn a_repeated_usage_is_carried_once() {
    let text = format!("{BASE}usages = [\"client\", \"client\", \"server\"]\n");
    let config = parse(&text).expect("parses");
    assert_eq!(config.extended_key_usages().len(), 2);
}

#[test]
fn an_empty_usage_list_is_refused_rather_than_defaulted() {
    let text = format!("{BASE}usages = []\n");
    assert!(parse(&text).is_err());
}

#[test]
fn an_unknown_usage_is_refused() {
    let text = format!("{BASE}usages = [\"email\"]\n");
    assert!(parse(&text).is_err());
}

#[test]
fn an_unknown_field_is_refused_rather_than_ignored() {
    let text = format!("{BASE}colour = \"blue\"\n");
    assert!(parse(&text).is_err());
}

#[test]
fn a_profile_must_carry_at_least_one_san() {
    let text = BASE.replace(r#"["127.0.0.1", "localhost"]"#, "[]");
    assert!(parse(&text).is_err());
}

#[test]
fn a_profile_without_secret_data_names_none() {
    assert!(parse(BASE).expect("parses").secret_data.is_none());
}

#[test]
fn a_profile_may_name_its_secret_data_home() {
    let text = format!("secret_data = \"/srv/secret\"\n{BASE}");
    let config = parse(&text).expect("parses");
    assert_eq!(
        config.secret_data,
        Some(std::path::PathBuf::from("/srv/secret"))
    );
}

/// A home lookup is identity-derived, so the profile names the path whole.
#[test]
fn a_secret_data_that_is_not_absolute_is_refused() {
    for raw in ["secret", "~/secret", ""] {
        let text = format!("secret_data = \"{raw}\"\n{BASE}");
        assert!(parse(&text).is_err(), "{raw:?} must be refused");
    }
}
