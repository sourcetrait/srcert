use crate::*;

/// The human-authored parameters for `generate`, read from a profile.
///
/// It carries NO paths and NO key material, and both omissions are
/// deliberate. Paths are arguments so that none of them is derived from
/// the INVOKING IDENTITY: an XDG or `$HOME` lookup under `sudo` resolves
/// to ROOT's and would quietly write root-owned files into the wrong
/// place. Passing a path is fine, since sudo resolves what it is given;
/// it is the identity-derived lookup that is banned. The only secret this
/// tool handles is the key it mints, which goes exactly where it is told.
/// That leaves a profile ordinary CONFIG - safe to commit, safe to
/// hand-edit, nothing to protect.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertGenConfig {
    /// Filename stem and application segment: `authority_<name>.pem`, and
    /// the `<secret_data>/sourcetrait/<name>/certs` install destination.
    pub name: String,
    /// Organization (O) on both the authority and the leaf.
    pub organization: String,
    /// Lifetime in days from generation. Set deliberately rather than
    /// inheriting rcgen's default, which is not a decision we want made
    /// for us.
    #[serde(default = "default_validity_days")]
    pub validity_days: i64,
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
    /// Every name the leaf must answer to. An entry that parses as an IP
    /// address becomes an iPAddress SAN, anything else a dNSName.
    ///
    /// This is the list that decides whether `wss://localhost:<port>`
    /// verifies: hostname verification reads SANs, not the CN, so an
    /// IP-only list fails a `localhost` URL even though the socket is the
    /// same. Ports are NOT in certificates, so one leaf covers every
    /// local port.
    pub subject_alt_names: Vec<String>,
    /// What the leaf may be presented AS. Defaults to server alone, which
    /// is what a profile written before this field existed meant.
    #[serde(default = "default_usages")]
    pub usages: Vec<EntityUsage>,
}

/// An extended key usage a leaf carries.
///
/// A leaf without `Client` cannot be presented as a client certificate,
/// so a mutual-TLS deployment that reuses a server-only leaf fails at
/// handshake with an error that names neither the profile nor this field.
/// Declaring it is what makes that a configuration decision rather than a
/// discovery.
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

    /// Split out from `load` so the schema is testable without a
    /// filesystem, and so a profile can be validated before it is written.
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
        Ok(())
    }

    /// The extended key usages the leaf carries, deduplicated in the
    /// order the profile declared them.
    pub(crate) fn extended_key_usages(&self) -> Vec<rcgen::ExtendedKeyUsagePurpose> {
        let mut seen: Vec<EntityUsage> = Vec::new();
        for usage in &self.entity.usages {
            if !seen.contains(usage) {
                seen.push(*usage);
            }
        }
        seen.iter().map(EntityUsage::purpose).collect()
    }

    /// Parse each SAN into its rcgen form. An entry that parses as an IP
    /// address is an iPAddress SAN; everything else is a dNSName, which
    /// rcgen requires to be IA5 (ASCII) - a non-ASCII name is rejected
    /// here rather than deeper in rcgen.
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
