use crate::*;

/// The human-authored parameters for `generate`, read from a profile.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertGenConfig {
    /// Filename stem and install segment; also the profile's own name.
    pub name: String,
    /// Organization (O) on both the authority and the leaf.
    pub organization: String,
    /// Lifetime in days from generation, set rather than inherited.
    #[serde(default = "default_validity_days")]
    pub validity_days: i64,
    /// The secret DATA home, absolute; keys land in `sourcetrait/<name>/certs`.
    #[serde(default)]
    pub secret_data: Option<PathBuf>,
    pub authority: AuthorityConfig,
    pub entity: EntityConfig,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfig {
    /// Common name (CN) of the CA certificate.
    pub common_name: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityConfig {
    /// Common name (CN) of the served leaf certificate.
    pub common_name: String,
    /// Every name the leaf answers to; an IP becomes an iPAddress name.
    pub subject_alt_names: Vec<String>,
    /// What the leaf may be presented as. Absent means server alone.
    #[serde(default = "default_usages")]
    pub usages: Vec<EntityUsage>,
}

/// An extended key usage a leaf carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityUsage {
    Server,
    Client,
}

impl EntityUsage {
    fn purpose(&self) -> rcgen::ExtendedKeyUsagePurpose {
        match self {
            Self::Server => rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            Self::Client => rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        }
    }
}

fn default_validity_days() -> i64 {
    3650
}

fn default_usages() -> Vec<EntityUsage> {
    vec![EntityUsage::Server]
}

impl CertGenConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).map_err(|source| CertError::ConfigRead {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&text, path)
    }

    /// Parse and validate profile text without touching a filesystem.
    pub fn parse(text: &str, path: &Path) -> Result<Self> {
        let config: Self = toml::from_str(text).map_err(|source| CertError::ConfigParse {
            path: path.display().to_string(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(CertError::msg("`name` must not be empty"));
        }
        if self.entity.subject_alt_names.is_empty() {
            return Err(CertError::msg("`entity.subject_alt_names` must not be empty"));
        }
        if self.entity.usages.is_empty() {
            return Err(CertError::msg(
                "`entity.usages` must name at least one of `server` or `client`",
            ));
        }
        if self.validity_days <= 0 {
            return Err(CertError::msg("`validity_days` must be positive"));
        }
        if let Some(path) = &self.secret_data
            && !path.is_absolute()
        {
            return Err(CertError::msg(format!(
                "`secret_data` must be an absolute path: {}",
                path.display()
            )));
        }
        Ok(())
    }

    /// The leaf's usages, deduplicated in the order they were declared.
    pub(crate) fn extended_key_usages(&self) -> Vec<rcgen::ExtendedKeyUsagePurpose> {
        let mut seen: Vec<EntityUsage> = Vec::new();
        for usage in &self.entity.usages {
            if !seen.contains(usage) {
                seen.push(*usage);
            }
        }
        seen.iter().map(EntityUsage::purpose).collect()
    }

    /// Parse each alternative name into its certificate-library form.
    pub(crate) fn subject_alt_names(&self) -> Result<Vec<rcgen::SanType>> {
        self.entity
            .subject_alt_names
            .iter()
            .map(|raw| {
                let value = raw.trim();
                if value.is_empty() {
                    return Err(CertError::InvalidSan {
                        value: raw.clone(),
                        reason: "empty".to_string(),
                    });
                }
                if let Ok(ip) = value.parse::<IpAddr>() {
                    return Ok(rcgen::SanType::IpAddress(ip));
                }
                let ia5 = rcgen::string::Ia5String::try_from(value.to_string()).map_err(|_| {
                    CertError::InvalidSan {
                        value: raw.clone(),
                        reason: "a dNSName must be ASCII".to_string(),
                    }
                })?;
                Ok(rcgen::SanType::DnsName(ia5))
            })
            .collect()
    }
}
