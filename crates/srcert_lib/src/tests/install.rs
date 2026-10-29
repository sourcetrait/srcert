//! Install locks: what presence means, and what it will not answer.
use crate::install::check_exists;

const NAME: &str = "quest";

/// The four filenames an install places, in the order `CertFiles` holds
/// them.
fn artifacts() -> [String; 4] {
    [
        format!("authority_{NAME}.key.pem"),
        format!("authority_{NAME}.pem"),
        format!("entity_{NAME}.key.pem"),
        format!("entity_{NAME}.pem"),
    ]
}

struct Scratch {
    root: std::path::PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("srcert_install_{name}"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch root");
        Self { root }
    }

    /// Stand in for an install, optionally leaving one artifact out.
    fn place(&self, omit: Option<&str>) {
        let dir = crate::generate::secret_certs_dir(&self.root, NAME);
        std::fs::create_dir_all(&dir).expect("secret certs dir");
        for file in artifacts() {
            if omit == Some(file.as_str()) {
                continue;
            }
            std::fs::write(dir.join(&file), "placed").expect("artifact");
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn a_never_minted_profile_reads_absent() {
    let scratch = Scratch::new("absent");
    assert!(!check_exists(&scratch.root, NAME));
}

#[test]
fn a_complete_install_reads_present() {
    let scratch = Scratch::new("present");
    scratch.place(None);
    assert!(check_exists(&scratch.root, NAME));
}

/// Every artifact is load-bearing at a handshake, so a partial tree must
/// not read as ready to serve.
#[test]
fn any_one_artifact_missing_reads_absent() {
    for omit in artifacts() {
        let scratch = Scratch::new(&omit.replace('.', "_"));
        scratch.place(Some(&omit));
        assert!(
            !check_exists(&scratch.root, NAME),
            "{omit} missing must read absent"
        );
    }
}

/// The filenames carry the profile name, so the answer is per profile
/// rather than per secret data home.
#[test]
fn another_profiles_material_does_not_answer_for_this_one() {
    let scratch = Scratch::new("other");
    scratch.place(None);
    assert!(!check_exists(&scratch.root, "grammar"));
}
