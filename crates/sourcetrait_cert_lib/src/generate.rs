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
        for (path, contents) in [
            (&self.authority_private, authority_key_pem),
            (&self.authority_public, authority_cert_pem),
            (&self.entity_private, entity_key_pem),
            (&self.entity_public, entity_cert_pem),
        ] {
            fs::write(path, contents)
                .map_err(|e| CertError::io(format!("writing {}", path.display()), e))?;
        }
        restrict(&self.authority_private)?;
        restrict(&self.entity_private)?;
        Ok(())
    }
}

/// Private keys go 0600, beneath the staging directory's own 0700.
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .map_err(|e| CertError::io(format!("stat {}", path.display()), e))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
        .map_err(|e| CertError::io(format!("chmod 600 {}", path.display()), e))
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

    let (not_before, not_after) = validity_window(config.validity_days);

    let authority_keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| CertError::rcgen("generating the authority keypair", e))?;

    let mut authority_params = rcgen::CertificateParams::default();
    authority_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    authority_params.key_usages.extend([
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
    ]);
    authority_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, config.authority.common_name.as_str());
    authority_params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, config.organization.as_str());
    authority_params.not_before = not_before;
    authority_params.not_after = not_after;

    let issuer = rcgen::CertifiedIssuer::self_signed(authority_params, &authority_keypair)
        .map_err(|e| CertError::rcgen("self-signing the authority certificate", e))?;

    let entity_keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| CertError::rcgen("generating the entity keypair", e))?;

    let entity_params = leaf_params(config, not_before, not_after)?;

    let entity_cert = entity_params
        .signed_by(&entity_keypair, &issuer)
        .map_err(|e| CertError::rcgen("signing the entity certificate", e))?;

    files.write(
        &authority_keypair.serialize_pem(),
        &issuer.pem(),
        &entity_keypair.serialize_pem(),
        &entity_cert.pem(),
    )?;
    Ok(files)
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
        fs::write(&self.entity_private, entity_key_pem)
            .map_err(|e| CertError::io(format!("writing {}", self.entity_private.display()), e))?;
        fs::write(&self.entity_public, entity_cert_pem)
            .map_err(|e| CertError::io(format!("writing {}", self.entity_public.display()), e))?;
        restrict(&self.entity_private)?;
        Ok(())
    }
}

/// Mint a fresh entity under an EXISTING authority, into `<out_dir>/certs`.
pub fn generate_entity(
    config: &CertGenConfig,
    authority_dir: &Path,
    out_dir: &Path,
) -> Result<EntityFiles> {
    let auth_certs = certs_dir(authority_dir);
    let auth = CertFiles::new(&auth_certs, &config.name);
    if !auth.authority_private.exists() || !auth.authority_public.exists() {
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

    let ca_key_pem = fs::read_to_string(&auth.authority_private)
        .map_err(|e| CertError::io(format!("reading {}", auth.authority_private.display()), e))?;
    let ca_cert_pem = fs::read_to_string(&auth.authority_public)
        .map_err(|e| CertError::io(format!("reading {}", auth.authority_public.display()), e))?;
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

    create_staging_dir(&out_certs)?;
    files.write(&entity_keypair.serialize_pem(), &entity_cert.pem())?;
    Ok(files)
}
