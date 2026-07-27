use crate::*;

use crate::store::{TrustTarget, kind_of_target};

/// Where the secret data home came from; it decides if we may create it.
pub enum SecretData<'a> {
    FromEnv(&'a Path),
    Explicit(&'a Path),
}

impl<'a> SecretData<'a> {
    pub fn path(&self) -> &'a Path {
        match self {
            Self::FromEnv(p) | Self::Explicit(p) => p,
        }
    }
}

pub struct InstallPlan<'a> {
    /// The dir `generate` was given; its artifacts are in `<dir>/certs`.
    pub cert_dir: &'a Path,
    pub name: &'a str,
    pub target: &'a TrustTarget,
    /// The secret DATA home; keys land in `<it>/sourcetrait/<name>/certs`.
    pub secret_data: SecretData<'a>,
}

pub struct Installed {
    /// Where the CA ended up: a file, or the keychain that ingested it.
    pub trusted_at: PathBuf,
    pub secrets: Vec<PathBuf>,
    pub staging: Staging,
}

/// Every check, before anything is done and before anything is asked.
pub fn preflight(plan: &InstallPlan<'_>) -> Result<()> {
    let source_dir = crate::generate::certs_dir(plan.cert_dir);
    let files = CertFiles::new(&source_dir, plan.name);
    if !files.exist() {
        return Err(CertError::UnrecognizedCertSources {
            path: source_dir.display().to_string(),
            name: plan.name.to_string(),
        });
    }

    if let TrustTarget::Dir { dir, .. } = plan.target {
        require_existing_dir(dir, "trust dir")?;
    }

    if let SecretData::Explicit(path) = &plan.secret_data {
        let parent = path
            .parent()
            .ok_or_else(|| CertError::msg("--secret-data has no parent directory"))?;
        require_existing_dir(parent, "secret data parent")?;
    }

    let secret_dir = crate::generate::secret_certs_dir(plan.secret_data.path(), plan.name);
    if secret_dir.exists() {
        return Err(CertError::CertsDirExists {
            path: secret_dir.display().to_string(),
        });
    }
    Ok(())
}

/// Whether a profile's four installed artifacts are all present.
pub fn check_exists(secret_data: &Path, name: &str) -> bool {
    let secret_dir = crate::generate::secret_certs_dir(secret_data, name);
    CertFiles::new(&secret_dir, name).exist()
}

/// Place the key material, then make the system trust the CA.
pub fn install(plan: &InstallPlan<'_>) -> Result<Installed> {
    preflight(plan)?;

    let source_dir = crate::generate::certs_dir(plan.cert_dir);
    let files = CertFiles::new(&source_dir, plan.name);
    let secret_dir = crate::generate::secret_certs_dir(plan.secret_data.path(), plan.name);

    let created = create_private_chain(&secret_dir)?;
    let mut secrets = Vec::new();
    for source in [
        &files.authority_private,
        &files.authority_public,
        &files.entity_private,
        &files.entity_public,
    ] {
        let name = source
            .file_name()
            .ok_or_else(|| CertError::msg("a cert artifact has no file name"))?;
        let dest = secret_dir.join(name);
        if let Err(e) = copy(source, &dest).and_then(|()| restrict_file(&dest)) {
            rollback(&created);
            return Err(e);
        }
        secrets.push(dest);
    }

    let trusted_at = match trust_ca(plan.target, &files.authority_public, plan.name) {
        Ok(p) => p,
        Err(e) => {
            rollback(&created);
            return Err(e);
        }
    };

    let staging = consume_staging(&source_dir, &files);

    Ok(Installed {
        trusted_at,
        secrets,
        staging,
    })
}

/// What became of the staging dir.
pub enum Staging {
    Removed(PathBuf),
    /// Left in place, with the reason. The install still succeeded.
    Kept { path: PathBuf, reason: String },
}

/// Remove staging, but ONLY if it holds exactly what we put there.
pub fn consume_staging(dir: &Path, files: &CertFiles) -> Staging {
    let expected: Vec<String> = files
        .all()
        .iter()
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            return Staging::Kept {
                path: dir.to_path_buf(),
                reason: format!("cannot read it: {e}"),
            };
        }
    };
    let mut unexpected = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !expected.contains(&name) {
            unexpected.push(name);
        }
    }
    if !unexpected.is_empty() {
        unexpected.sort();
        return Staging::Kept {
            path: dir.to_path_buf(),
            reason: format!("it holds files we did not create: {}", unexpected.join(", ")),
        };
    }

    for path in files.all() {
        if let Err(e) = fs::remove_file(path) {
            return Staging::Kept {
                path: dir.to_path_buf(),
                reason: format!("cannot remove {}: {e}", path.display()),
            };
        }
    }
    match fs::remove_dir(dir) {
        Ok(()) => Staging::Removed(dir.to_path_buf()),
        Err(e) => Staging::Kept {
            path: dir.to_path_buf(),
            reason: format!("cannot remove the emptied dir: {e}"),
        },
    }
}

/// Create every missing level down to `target` at 0700, newest last.
fn create_private_chain(target: &Path) -> Result<Vec<PathBuf>> {
    use std::os::unix::fs::PermissionsExt;

    let mut missing = Vec::new();
    let mut cursor = Some(target);
    while let Some(path) = cursor {
        if path.exists() {
            break;
        }
        missing.push(path.to_path_buf());
        cursor = path.parent();
    }
    missing.reverse();

    let mut created = Vec::new();
    for path in missing {
        if let Err(e) = fs::create_dir(&path) {
            rollback(&created);
            return Err(CertError::io(format!("creating {}", path.display()), e));
        }
        created.push(path.clone());

        let mut perms = match fs::metadata(&path) {
            Ok(m) => m.permissions(),
            Err(e) => {
                rollback(&created);
                return Err(CertError::io(format!("stat {}", path.display()), e));
            }
        };
        perms.set_mode(0o700);
        if let Err(e) = fs::set_permissions(&path, perms) {
            rollback(&created);
            return Err(CertError::io(format!("chmod 700 {}", path.display()), e));
        }
    }
    Ok(created)
}

/// go-rwx on a file we placed in the secret tree.
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .map_err(|e| CertError::io(format!("stat {}", path.display()), e))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
        .map_err(|e| CertError::io(format!("chmod 600 {}", path.display()), e))
}

/// Remove what we created, deepest first, best-effort.
fn rollback(created: &[PathBuf]) {
    for path in created.iter().rev() {
        let _ = fs::remove_dir_all(path);
    }
}

fn require_existing_dir(path: &Path, what: &str) -> Result<()> {
    if !path.exists() {
        return Err(CertError::MissingDir {
            what: what.to_string(),
            path: path.display().to_string(),
        });
    }
    if !path.is_dir() {
        return Err(CertError::NotADir {
            what: what.to_string(),
            path: path.display().to_string(),
        });
    }
    Ok(())
}

/// Copy, creating NOTHING; a directory is made deliberately or not here.
fn copy(from: &Path, to: &Path) -> Result<()> {
    fs::copy(from, to).map_err(|e| {
        CertError::io(format!("copying {} to {}", from.display(), to.display()), e)
    })?;
    Ok(())
}

/// The vendor-prefixed filename we drop into a shared trust directory.
pub fn trust_file_name(name: &str, extension: &str) -> String {
    format!("{}_{name}.{extension}", profile::SOURCETRAIT)
}

/// Make the system trust our CA, returning where it landed.
fn trust_ca(target: &TrustTarget, authority_public: &Path, name: &str) -> Result<PathBuf> {
    let _ = kind_of_target(target);
    match target {
        TrustTarget::Dir {
            dir,
            extension,
            update_command,
        } => {
            let placed = dir.join(trust_file_name(name, extension));
            let src = authority_public.to_string_lossy().into_owned();
            let dst = placed.to_string_lossy().into_owned();
            run_privileged("cp", &[&src, &dst])?;
            if let Err(e) = run_privileged(update_command, &[]) {
                let _ = run_privileged("rm", &["-f", &dst]);
                return Err(e);
            }
            Ok(placed)
        }
        TrustTarget::Keychain { program, keychain } => {
            let cert = authority_public.to_string_lossy().into_owned();
            let key = keychain.to_string_lossy().into_owned();
            run_privileged(
                program,
                &["add-trusted-cert", "-d", "-r", "trustRoot", "-k", &key, &cert],
            )?;
            Ok(keychain.clone())
        }
    }
}

/// Run one command that needs root, elevating only if we are not root.
fn run_privileged(command: &str, args: &[&str]) -> Result<()> {
    if nix::unistd::Uid::effective().is_root() {
        return run(command, args);
    }
    let mut argv = vec![command];
    argv.extend_from_slice(args);
    let status = process::Command::new("sudo")
        .args(&argv)
        .status()
        .map_err(|e| CertError::io("running sudo".to_string(), e))?;
    if !status.success() {
        return Err(CertError::Command {
            command: format!("sudo {command}"),
            status: status.to_string(),
            stderr: String::new(),
        });
    }
    Ok(())
}

fn run(command: &str, args: &[&str]) -> Result<()> {
    let output = process::Command::new(command)
        .args(args)
        .output()
        .map_err(|e| CertError::io(format!("running {command}"), e))?;
    if !output.status.success() {
        return Err(CertError::Command {
            command: command.to_string(),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(())
}
