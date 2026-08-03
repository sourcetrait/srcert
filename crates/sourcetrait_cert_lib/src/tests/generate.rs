//! Generate locks: an entity minted under an existing authority.
use crate::config::CertGenConfig;
use crate::generate::{CertFiles, certs_dir, generate, generate_entity};

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
