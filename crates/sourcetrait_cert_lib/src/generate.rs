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

    let mut entity_params = rcgen::CertificateParams::default();
    entity_params.is_ca = rcgen::IsCa::NoCa;
    entity_params.use_authority_key_identifier_extension = true;
    entity_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    entity_params
        .extended_key_usages
        .extend(config.extended_key_usages());
    entity_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, config.entity.common_name.as_str());
    entity_params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, config.organization.as_str());
    entity_params.subject_alt_names = config.subject_alt_names()?;
    entity_params.not_before = not_before;
    entity_params.not_after = not_after;

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
