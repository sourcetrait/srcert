pub mod config;
pub(crate) mod error;
pub mod generate;
pub mod install;
pub mod profile;
pub mod store;
pub mod verify;

pub(crate) use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    process,
};

pub(crate) use crate::config::CertGenConfig;

pub use crate::config::{AuthorityConfig, EntityConfig, EntityUsage};
pub use crate::error::{CertError, Result};
pub use crate::generate::{
    CertFiles,
    EntityFiles,
    certs_dir,
    generate,
    generate_entity,
    secret_certs_dir,
};
pub use crate::install::{
    InstallPlan,
    Installed,
    SecretData,
    Staging,
    check_exists,
    install,
    preflight,
};
pub use crate::profile::{
    ProfileInstall,
    config_home,
    default_profile_path,
    install_profile,
    installed_profiles,
    load_profile,
    profile_exists,
    profile_path,
    profiles_dir,
};
pub use crate::store::{TrustSource, TrustTarget, resolve_source, resolve_target};
pub use crate::verify::{VerifyPlan, Verified, verify};

#[cfg(test)]
mod tests {
    mod config;
    mod generate;
    mod install;
    mod profile;
}
