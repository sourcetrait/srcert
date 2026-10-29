//! Generate locks: an entity minted under an existing authority, and the files
//! named whole in place of the dirs.
use std::os::unix::fs::PermissionsExt;

use crate::config::CertGenConfig;
use crate::generate::{
    AuthorityFiles, CertFiles, EntityFiles, certs_dir, generate, generate_authority,
    generate_authority_files, generate_entity, generate_entity_files, generate_files,
};

const NAME: &str = "grammar";

const PROFILE: &str = r#"
name = "grammar"
organization = "SourceTrait"
validity_days = 3650

[authority]
common_name = "SourceTrait Grammar Local CA"

[entity]
common_name = "localhost"
subject_alt_names = ["127.0.0.1", "::1", "localhost"]
usages = ["server", "client"]
"#;

fn config() -> CertGenConfig {
    CertGenConfig::parse(PROFILE, std::path::Path::new("<test>")).expect("parses")
}

struct Scratch {
    root: std::path::PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("srcert_generate_{name}"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch root");
        Self { root }
    }

    fn sub(&self, name: &str) -> std::path::PathBuf {
        self.root.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn an_entity_is_minted_under_an_existing_authority() {
    let scratch = Scratch::new("under_authority");
    let auth = scratch.sub("authority");
    let host = scratch.sub("host");

    generate(&config(), &auth).expect("mint the authority + first entity");
    let entity = generate_entity(&config(), &auth, &host).expect("mint an entity under it");

    assert!(entity.exist(), "both entity files are written");
    let cert = std::fs::read_to_string(&entity.entity_public).unwrap();
    let key = std::fs::read_to_string(&entity.entity_private).unwrap();
    assert!(cert.contains("BEGIN CERTIFICATE"), "the entity cert is PEM");
    assert!(key.contains("PRIVATE KEY"), "the entity key is PEM");
}

/// A host bundle carries only the leaf; the CA private stays with the authority.
#[test]
fn generate_entity_writes_only_the_entity() {
    let scratch = Scratch::new("entity_only");
    let auth = scratch.sub("authority");
    let host = scratch.sub("host");
    generate(&config(), &auth).expect("authority");
    generate_entity(&config(), &auth, &host).expect("entity");

    let host_certs = certs_dir(&host);
    let names: Vec<String> = std::fs::read_dir(&host_certs)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 2, "only the two entity files, got {names:?}");

    let ca = CertFiles::new(&host_certs, NAME);
    assert!(!ca.authority_private.exists(), "no CA private in a host bundle");
    assert!(!ca.authority_public.exists(), "no CA public in a host bundle");
}

#[test]
fn generate_entity_refuses_an_existing_output() {
    let scratch = Scratch::new("collision");
    let auth = scratch.sub("authority");
    let host = scratch.sub("host");
    generate(&config(), &auth).expect("authority");
    generate_entity(&config(), &auth, &host).expect("first entity");
    assert!(
        generate_entity(&config(), &auth, &host).is_err(),
        "a second mint into the same dir is refused",
    );
}

#[test]
fn generate_entity_refuses_a_missing_authority() {
    let scratch = Scratch::new("no_authority");
    let auth = scratch.sub("authority");
    let host = scratch.sub("host");
    assert!(
        generate_entity(&config(), &auth, &host).is_err(),
        "no authority to sign under is refused",
    );
}

#[test]
fn an_authority_alone_signs_an_entity_minted_after() {
    let scratch = Scratch::new("authority_alone");
    let auth = scratch.sub("authority");
    let host = scratch.sub("host");
    let authority = generate_authority(&config(), &auth).expect("the authority alone");

    assert!(authority.exist(), "both authority files are written");
    let names: Vec<String> = std::fs::read_dir(certs_dir(&auth))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 2, "the authority alone, got {names:?}");
    let entity = generate_entity(&config(), &auth, &host).expect("an entity under it");
    assert!(entity.exist(), "the entity is minted under the authority alone");
}

#[test]
fn an_authority_minted_into_named_files_signs_an_entity_beside_it() {
    let scratch = Scratch::new("authority_files");
    let dir = scratch.sub("shared");
    let authority = generate_authority_files(
        &config(),
        AuthorityFiles {
            authority_private: dir.join("example.authority.key.pem"),
            authority_public: dir.join("example.authority.pem"),
        },
    )
    .expect("the authority into named files");
    assert_eq!(mode(&authority.authority_private), 0o600, "the CA key is private");

    let entity = EntityFiles {
        entity_private: dir.join("example-one.entity.key.pem"),
        entity_public: dir.join("example-one.entity.pem"),
    };
    let entity = generate_entity_files(&config(), &authority, entity).expect("an entity");
    assert!(entity.exist(), "the entity is minted beside its authority");
}

/// The four files named whole, under a parent the run makes.
fn named(dir: &std::path::Path) -> CertFiles {
    CertFiles {
        authority_private: dir.join("example.authority.key.pem"),
        authority_public: dir.join("example.authority.pem"),
        entity_private: dir.join("example-one.entity.key.pem"),
        entity_public: dir.join("example-one.entity.pem"),
    }
}

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn generate_files_writes_the_four_files_named() {
    let scratch = Scratch::new("files");
    let dir = scratch.sub("new").join("deeper");
    let files = generate_files(&config(), named(&dir)).expect("mint into named files");

    assert!(files.exist(), "all four files are written");
    assert_eq!(mode(&files.authority_private), 0o600, "the CA key is private");
    assert_eq!(mode(&files.entity_private), 0o600, "the leaf key is private");
    assert_eq!(mode(&dir), 0o700, "a parent the run makes is private");
    let cert = std::fs::read_to_string(&files.entity_public).unwrap();
    assert!(cert.contains("BEGIN CERTIFICATE"), "the entity cert is PEM");
}

#[test]
fn an_entity_is_minted_into_named_files_under_a_named_authority() {
    let scratch = Scratch::new("entity_files");
    let shared = scratch.sub("shared");
    let first = generate_files(&config(), named(&shared)).expect("the authority");
    let authority = AuthorityFiles {
        authority_private: first.authority_private.clone(),
        authority_public: first.authority_public.clone(),
    };
    let second = EntityFiles {
        entity_private: shared.join("example-two.entity.key.pem"),
        entity_public: shared.join("example-two.entity.pem"),
    };
    let entity =
        generate_entity_files(&config(), &authority, second).expect("an entity beside the first");

    assert!(entity.exist(), "both entity files are written");
    assert_eq!(mode(&entity.entity_private), 0o600, "the leaf key is private");
    let names: Vec<String> = std::fs::read_dir(&shared)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 6, "the authority, two entities, nothing more: {names:?}");
}

#[test]
fn a_named_output_that_exists_is_refused_and_nothing_is_written() {
    let scratch = Scratch::new("files_collision");
    let dir = scratch.sub("certs");
    let files = named(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(&files.entity_public, "kept").unwrap();

    let error = generate_files(&config(), files.clone()).expect_err("an output exists");
    assert!(error.to_string().contains("already exists"), "{error}");
    assert_eq!(std::fs::read_to_string(&files.entity_public).unwrap(), "kept");
    assert!(!files.authority_private.exists(), "nothing else is written");
}

#[test]
fn a_file_named_twice_is_refused() {
    let scratch = Scratch::new("files_twice");
    let dir = scratch.sub("certs");
    let mut files = named(&dir);
    files.entity_public = files.entity_private.clone();
    let error = generate_files(&config(), files).expect_err("one file named twice");
    assert!(error.to_string().contains("named twice"), "{error}");
}

#[test]
fn a_named_authority_that_is_missing_is_refused() {
    let scratch = Scratch::new("files_no_authority");
    let dir = scratch.sub("certs");
    let authority = AuthorityFiles {
        authority_private: dir.join("absent.authority.key.pem"),
        authority_public: dir.join("absent.authority.pem"),
    };
    let entity = EntityFiles {
        entity_private: dir.join("example.entity.key.pem"),
        entity_public: dir.join("example.entity.pem"),
    };
    let error = generate_entity_files(&config(), &authority, entity).expect_err("no authority");
    assert!(error.to_string().contains("does not exist"), "{error}");
    assert!(!dir.exists(), "nothing is made");
}
