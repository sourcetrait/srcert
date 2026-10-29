//! Run locks: where an install's secret data home comes from, and how the
//! generate verbs take their files.
use std::path::{Path, PathBuf};

use crate::run::{
    AuthorityFlags, Cli, Command, FileFlags, Generate, named_authority, named_files,
    resolve_secret_data,
};

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

#[test]
fn the_command_line_is_well_formed() {
    <Cli as clap::CommandFactory>::command().debug_assert();
}

#[test]
fn no_file_flag_is_the_dir_form() {
    assert!(named_files(FileFlags::default()).expect("resolves").is_none());
}

#[test]
fn the_four_file_flags_name_the_files() {
    let files = named_files(FileFlags {
        authority: AuthorityFlags {
            authority_cert: Some(PathBuf::from("/a/ca.pem")),
            authority_key: Some(PathBuf::from("/a/ca.key.pem")),
        },
        entity_cert: Some(PathBuf::from("/a/leaf.pem")),
        entity_key: Some(PathBuf::from("/a/leaf.key.pem")),
    })
    .expect("resolves")
    .expect("the file form");
    assert_eq!(files.authority_public, PathBuf::from("/a/ca.pem"));
    assert_eq!(files.authority_private, PathBuf::from("/a/ca.key.pem"));
    assert_eq!(files.entity_public, PathBuf::from("/a/leaf.pem"));
    assert_eq!(files.entity_private, PathBuf::from("/a/leaf.key.pem"));
}

#[test]
fn a_part_of_the_file_flags_is_refused() {
    let error = named_files(FileFlags {
        entity_cert: Some(PathBuf::from("/a/leaf.pem")),
        ..FileFlags::default()
    })
    .expect_err("one of four");
    let text = error.to_string();
    assert!(text.contains("--entity-key"), "{text}");
}

#[test]
fn one_authority_flag_alone_is_refused() {
    let error = named_authority(AuthorityFlags {
        authority_key: Some(PathBuf::from("/a/ca.key.pem")),
        ..AuthorityFlags::default()
    })
    .expect_err("one of two");
    let text = error.to_string();
    assert!(text.contains("--authority-cert"), "{text}");
}

#[test]
fn generate_entity_takes_its_files_by_flag_and_no_dirs() {
    let cli = <Cli as clap::Parser>::try_parse_from([
        "srcert",
        "generate",
        "entity",
        "grammar",
        "--authority-cert",
        "ca.pem",
        "--authority-key",
        "ca.key.pem",
        "--entity-cert",
        "leaf.pem",
        "--entity-key",
        "leaf.key.pem",
    ])
    .expect("parses");
    match cli.command {
        Command::Generate {
            what:
                Generate::Entity {
                    authority_dir,
                    out_dir,
                    files,
                    ..
                },
        } => {
            assert!(authority_dir.is_none() && out_dir.is_none(), "no dirs");
            assert_eq!(files.entity_key, Some(PathBuf::from("leaf.key.pem")));
        }
        _ => panic!("generate entity"),
    }
}

#[test]
fn generate_authority_takes_its_two_files_by_flag() {
    let cli = <Cli as clap::Parser>::try_parse_from([
        "srcert",
        "generate",
        "authority",
        "grammar",
        "--authority-cert",
        "ca.pem",
        "--authority-key",
        "ca.key.pem",
    ])
    .expect("parses");
    match cli.command {
        Command::Generate {
            what: Generate::Authority { dir, files, .. },
        } => {
            assert!(dir.is_none(), "no dir");
            assert_eq!(files.authority_cert, Some(PathBuf::from("ca.pem")));
        }
        _ => panic!("generate authority"),
    }
}

#[test]
fn generate_all_takes_its_dir() {
    let cli = <Cli as clap::Parser>::try_parse_from(["srcert", "generate", "all", "grammar", "out"])
        .expect("parses");
    match cli.command {
        Command::Generate {
            what: Generate::All { profile, dir, .. },
        } => {
            assert_eq!(profile, "grammar");
            assert_eq!(dir, Some(PathBuf::from("out")));
        }
        _ => panic!("generate all"),
    }
}

#[test]
fn the_flat_generate_verbs_are_gone() {
    for argv in [
        ["srcert", "generate-entity", "grammar", "a", "b"].as_slice(),
        ["srcert", "generate", "grammar", "out"].as_slice(),
    ] {
        assert!(
            <Cli as clap::Parser>::try_parse_from(argv.iter().copied()).is_err(),
            "{argv:?}"
        );
    }
}
