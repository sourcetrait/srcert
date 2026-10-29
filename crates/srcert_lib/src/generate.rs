use crate::*;

/// The four artifacts a generate run emits, all into ONE directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertFileKind {
    AuthorityPrivate,
    AuthorityPublic,
    EntityPrivate,
    EntityPublic,
}

impl CertFileKind {
    pub(crate) fn filepath(&self, dir: &Path, name: &str) -> PathBuf {
        match self {
            Self::AuthorityPrivate => dir.join(format!("authority_{name}.key.pem")),
            Self::AuthorityPublic => dir.join(format!("authority_{name}.pem")),
            Self::EntityPrivate => dir.join(format!("entity_{name}.key.pem")),
            Self::EntityPublic => dir.join(format!("entity_{name}.pem")),
        }
    }
}

/// The `certs` leaf we own under any directory a caller names.
pub fn certs_dir(dir: &Path) -> PathBuf {
    dir.join("certs")
}

/// The install destination: `<secret_data>/sourcetrait/<name>/certs`.
pub fn secret_certs_dir(secret_data: &Path, name: &str) -> PathBuf {
    secret_data
        .join(profile::SOURCETRAIT)
        .join(name)
        .join("certs")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertFiles {
    pub authority_private: PathBuf,
    pub authority_public: PathBuf,
    pub entity_private: PathBuf,
    pub entity_public: PathBuf,
}

impl CertFiles {
    pub fn new(certs_dir: &Path, cert_name: &str) -> Self {
        Self {
            authority_private: CertFileKind::AuthorityPrivate.filepath(certs_dir, cert_name),
            authority_public: CertFileKind::AuthorityPublic.filepath(certs_dir, cert_name),
            entity_private: CertFileKind::EntityPrivate.filepath(certs_dir, cert_name),
            entity_public: CertFileKind::EntityPublic.filepath(certs_dir, cert_name),
        }
    }

    pub fn exist(&self) -> bool {
        self.authority_private.exists()
            && self.authority_public.exists()
            && self.entity_private.exists()
            && self.entity_public.exists()
    }

    pub fn all(&self) -> [&PathBuf; 4] {
        [
            &self.authority_private,
            &self.authority_public,
            &self.entity_private,
            &self.entity_public,
        ]
    }

    /// Takes the four serialized PEMs rather than the live values.
    fn write(
        &self,
        authority_key_pem: &str,
        authority_cert_pem: &str,
        entity_key_pem: &str,
        entity_cert_pem: &str,
    ) -> Result<()> {
        write_new(&self.authority_private, authority_key_pem, true)?;
        write_new(&self.authority_public, authority_cert_pem, false)?;
        write_new(&self.entity_private, entity_key_pem, true)?;
        write_new(&self.entity_public, entity_cert_pem, false)
    }
}

/// Write a file that must not exist yet; a private key is 0600 from its creation.
fn write_new(path: &Path, contents: &str, private: bool) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    if private {
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut file| file.write_all(contents.as_bytes()))
        .map_err(|e| CertError::io(format!("writing {}", path.display()), e))
}

/// Mint a self-signed CA and a leaf it signs, into `<dir>/certs`.
pub fn generate(config: &CertGenConfig, dir: &Path) -> Result<CertFiles> {
    let out_dir = certs_dir(dir);
    if out_dir.exists() {
        return Err(CertError::CertsDirExists {
            path: out_dir.display().to_string(),
        });
    }
    let files = CertFiles::new(&out_dir, &config.name);

    create_staging_dir(&out_dir)?;

    let [authority_key, authority_cert, entity_key, entity_cert] = mint(config)?;
    files.write(&authority_key, &authority_cert, &entity_key, &entity_cert)?;
    Ok(files)
}

/// Mint a self-signed CA and a leaf it signs, into the four files named.
pub fn generate_files(config: &CertGenConfig, files: CertFiles) -> Result<CertFiles> {
    check_outputs(&files.all())?;
    let [authority_key, authority_cert, entity_key, entity_cert] = mint(config)?;
    make_parents(&files.all())?;
    files.write(&authority_key, &authority_cert, &entity_key, &entity_cert)?;
    Ok(files)
}

/// Mint a self-signed CA alone, into `<dir>/certs`.
pub fn generate_authority(config: &CertGenConfig, dir: &Path) -> Result<AuthorityFiles> {
    let out_dir = certs_dir(dir);
    if out_dir.exists() {
        return Err(CertError::CertsDirExists {
            path: out_dir.display().to_string(),
        });
    }
    let files = AuthorityFiles::new(&out_dir, &config.name);

    create_staging_dir(&out_dir)?;

    let [authority_key, authority_cert] = mint_authority(config)?;
    files.write(&authority_key, &authority_cert)?;
    Ok(files)
}

/// Mint a self-signed CA alone, into the two files named.
pub fn generate_authority_files(
    config: &CertGenConfig,
    files: AuthorityFiles,
) -> Result<AuthorityFiles> {
    check_outputs(&files.all())?;
    let [authority_key, authority_cert] = mint_authority(config)?;
    make_parents(&files.all())?;
    files.write(&authority_key, &authority_cert)?;
    Ok(files)
}

/// A fresh self-signed CA as PEMs: its key, then its cert.
fn mint_authority(config: &CertGenConfig) -> Result<[String; 2]> {
    let (not_before, not_after) = validity_window(config.validity_days);
    let authority_keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| CertError::rcgen("generating the authority keypair", e))?;
    let issuer = rcgen::CertifiedIssuer::self_signed(
        authority_params(config, not_before, not_after),
        &authority_keypair,
    )
    .map_err(|e| CertError::rcgen("self-signing the authority certificate", e))?;
    Ok([authority_keypair.serialize_pem(), issuer.pem()])
}

/// A fresh CA and its leaf as PEMs: CA key, CA cert, leaf key, leaf cert.
fn mint(config: &CertGenConfig) -> Result<[String; 4]> {
    let (not_before, not_after) = validity_window(config.validity_days);

    let authority_keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| CertError::rcgen("generating the authority keypair", e))?;

    let issuer = rcgen::CertifiedIssuer::self_signed(
        authority_params(config, not_before, not_after),
        &authority_keypair,
    )
    .map_err(|e| CertError::rcgen("self-signing the authority certificate", e))?;

    let entity_keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| CertError::rcgen("generating the entity keypair", e))?;

    let entity_params = leaf_params(config, not_before, not_after)?;

    let entity_cert = entity_params
        .signed_by(&entity_keypair, &issuer)
        .map_err(|e| CertError::rcgen("signing the entity certificate", e))?;

    Ok([
        authority_keypair.serialize_pem(),
        issuer.pem(),
        entity_keypair.serialize_pem(),
        entity_cert.pem(),
    ])
}

/// The not-before and not-after pair, measured from now.
fn validity_window(days: i64) -> (time::OffsetDateTime, time::OffsetDateTime) {
    let now = time::OffsetDateTime::now_utc();
    (now, now + time::Duration::days(days))
}

/// Created 0700 explicitly; it holds CA private key material.
fn create_staging_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if !dir.exists() {
        fs::create_dir_all(dir)
            .map_err(|e| CertError::io(format!("creating {}", dir.display()), e))?;
    }
    let mut perms = fs::metadata(dir)
        .map_err(|e| CertError::io(format!("stat {}", dir.display()), e))?
        .permissions();
    perms.set_mode(0o700);
    fs::set_permissions(dir, perms)
        .map_err(|e| CertError::io(format!("chmod 700 {}", dir.display()), e))
}

/// Refuse an output that already exists, or one file named twice.
fn check_outputs(paths: &[&PathBuf]) -> Result<()> {
    for (index, path) in paths.iter().enumerate() {
        if path.exists() {
            return Err(CertError::FileExists {
                path: path.display().to_string(),
            });
        }
        if paths[..index].contains(path) {
            return Err(CertError::msg(format!("{} is named twice", path.display())));
        }
    }
    Ok(())
}

/// Make each output's missing parent 0700; an existing one is left as it is.
fn make_parents(paths: &[&PathBuf]) -> Result<()> {
    for path in paths {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            create_staging_dir(parent)?;
        }
    }
    Ok(())
}

/// The authority's certificate params from a profile.
fn authority_params(
    config: &CertGenConfig,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages.extend([
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
    ]);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, config.authority.common_name.as_str());
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, config.organization.as_str());
    params.not_before = not_before;
    params.not_after = not_after;
    params
}

/// The leaf's certificate params from a profile.
fn leaf_params(
    config: &CertGenConfig,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> Result<rcgen::CertificateParams> {
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::NoCa;
    params.use_authority_key_identifier_extension = true;
    params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .extend(config.extended_key_usages());
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, config.entity.common_name.as_str());
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, config.organization.as_str());
    params.subject_alt_names = config.subject_alt_names()?;
    params.not_before = not_before;
    params.not_after = not_after;
    Ok(params)
}

/// The authority an entity is minted under: its key and its certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityFiles {
    pub authority_private: PathBuf,
    pub authority_public: PathBuf,
}

impl AuthorityFiles {
    pub fn new(certs_dir: &Path, cert_name: &str) -> Self {
        Self {
            authority_private: CertFileKind::AuthorityPrivate.filepath(certs_dir, cert_name),
            authority_public: CertFileKind::AuthorityPublic.filepath(certs_dir, cert_name),
        }
    }

    pub fn exist(&self) -> bool {
        self.authority_private.exists() && self.authority_public.exists()
    }

    pub fn all(&self) -> [&PathBuf; 2] {
        [&self.authority_private, &self.authority_public]
    }

    /// Takes the two serialized PEMs, mirroring `CertFiles::write`.
    fn write(&self, authority_key_pem: &str, authority_cert_pem: &str) -> Result<()> {
        write_new(&self.authority_private, authority_key_pem, true)?;
        write_new(&self.authority_public, authority_cert_pem, false)
    }
}

/// The two artifacts a `generate_entity` run emits, into ONE directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityFiles {
    pub entity_private: PathBuf,
    pub entity_public: PathBuf,
}

impl EntityFiles {
    pub fn new(certs_dir: &Path, cert_name: &str) -> Self {
        Self {
            entity_private: CertFileKind::EntityPrivate.filepath(certs_dir, cert_name),
            entity_public: CertFileKind::EntityPublic.filepath(certs_dir, cert_name),
        }
    }

    pub fn exist(&self) -> bool {
        self.entity_private.exists() && self.entity_public.exists()
    }

    pub fn all(&self) -> [&PathBuf; 2] {
        [&self.entity_private, &self.entity_public]
    }

    /// Takes the two serialized PEMs, mirroring `CertFiles::write`.
    fn write(&self, entity_key_pem: &str, entity_cert_pem: &str) -> Result<()> {
        write_new(&self.entity_private, entity_key_pem, true)?;
        write_new(&self.entity_public, entity_cert_pem, false)
    }
}

/// Mint a fresh entity under an EXISTING authority, into `<out_dir>/certs`.
pub fn generate_entity(
    config: &CertGenConfig,
    authority_dir: &Path,
    out_dir: &Path,
) -> Result<EntityFiles> {
    let auth_certs = certs_dir(authority_dir);
    let authority = AuthorityFiles::new(&auth_certs, &config.name);
    if !authority.exist() {
        return Err(CertError::UnrecognizedCertSources {
            path: auth_certs.display().to_string(),
            name: config.name.clone(),
        });
    }

    let out_certs = certs_dir(out_dir);
    if out_certs.exists() {
        return Err(CertError::CertsDirExists {
            path: out_certs.display().to_string(),
        });
    }
    let files = EntityFiles::new(&out_certs, &config.name);

    let [entity_key, entity_cert] = mint_entity(config, &authority)?;
    create_staging_dir(&out_certs)?;
    files.write(&entity_key, &entity_cert)?;
    Ok(files)
}

/// Mint a fresh entity under the authority named, into the two files named.
pub fn generate_entity_files(
    config: &CertGenConfig,
    authority: &AuthorityFiles,
    files: EntityFiles,
) -> Result<EntityFiles> {
    for path in [&authority.authority_private, &authority.authority_public] {
        if !path.is_file() {
            return Err(CertError::MissingFile {
                what: String::from("the authority's"),
                path: path.display().to_string(),
            });
        }
    }
    check_outputs(&files.all())?;
    let [entity_key, entity_cert] = mint_entity(config, authority)?;
    make_parents(&files.all())?;
    files.write(&entity_key, &entity_cert)?;
    Ok(files)
}

/// A fresh leaf signed by the authority read from `authority`: its key, its cert.
fn mint_entity(config: &CertGenConfig, authority: &AuthorityFiles) -> Result<[String; 2]> {
    let ca_key_pem = fs::read_to_string(&authority.authority_private).map_err(|e| {
        CertError::io(format!("reading {}", authority.authority_private.display()), e)
    })?;
    let ca_cert_pem = fs::read_to_string(&authority.authority_public).map_err(|e| {
        CertError::io(format!("reading {}", authority.authority_public.display()), e)
    })?;
    let ca_key = rcgen::KeyPair::from_pem(&ca_key_pem)
        .map_err(|e| CertError::rcgen("loading the authority key", e))?;
    let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key)
        .map_err(|e| CertError::rcgen("loading the authority certificate", e))?;

    let (not_before, not_after) = validity_window(config.validity_days);
    let entity_keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| CertError::rcgen("generating the entity keypair", e))?;
    let entity_params = leaf_params(config, not_before, not_after)?;
    let entity_cert = entity_params
        .signed_by(&entity_keypair, &issuer)
        .map_err(|e| CertError::rcgen("signing the entity certificate", e))?;
    Ok([entity_keypair.serialize_pem(), entity_cert.pem()])
}
