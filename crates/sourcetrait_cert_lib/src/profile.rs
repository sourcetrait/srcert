use crate::*;

/// The vendor segment under a configuration home.
pub const SOURCETRAIT: &str = "sourcetrait";
/// This tool's segment; the binary is `srcert`.
pub const SRCERT: &str = "srcert";
/// The leaf holding one file per named profile.
pub const PROFILES: &str = "profiles";
/// The reference copy's segment; never consumed, only written.
pub const DEFAULT: &str = "default";
/// The extension a profile file carries.
pub const PROFILE_EXTENSION: &str = "toml";

const CONFIG_HOME_ENV: &str = "XDG_CONFIG_HOME";

/// Where the profiles this tool READS live.
pub fn profiles_dir(config_home: &Path) -> PathBuf {
    config_home
        .join(SOURCETRAIT)
        .join(SRCERT)
        .join(PROFILES)
}

/// Where the shipped reference copies live.
///
/// Nothing reads these. They exist so a user who has customised their
/// profile can see what the application originally shipped, and restore
/// from it.
pub fn default_profiles_dir(config_home: &Path) -> PathBuf {
    config_home
        .join(SOURCETRAIT)
        .join(SRCERT)
        .join(DEFAULT)
        .join(PROFILES)
}

/// The configuration home from the environment.
///
/// Unlike the path arguments this tool takes, an environment lookup is
/// identity-derived. It is safe here only because `srcert` is never run
/// elevated: it runs unprivileged and elevates the few standard commands
/// that touch the trust store. A caller that might be elevated passes a
/// path instead.
pub fn config_home() -> Result<PathBuf> {
    match std::env::var(CONFIG_HOME_ENV) {
        Ok(value) if !value.is_empty() => Ok(PathBuf::from(value)),
        _ => Err(CertError::msg(format!(
            "set ${CONFIG_HOME_ENV} or pass a configuration home"
        ))),
    }
}

/// The file one named profile is read from.
pub fn profile_path(config_home: &Path, snake: &str) -> Result<PathBuf> {
    validate_snake(snake)?;
    Ok(profiles_dir(config_home).join(format!("{snake}.{PROFILE_EXTENSION}")))
}

/// The reference copy of one named profile. Never read by this tool.
pub fn default_profile_path(config_home: &Path, snake: &str) -> Result<PathBuf> {
    validate_snake(snake)?;
    Ok(default_profiles_dir(config_home).join(format!("{snake}.{PROFILE_EXTENSION}")))
}

/// Whether a named profile is already installed.
pub fn profile_exists(config_home: &Path, snake: &str) -> Result<bool> {
    Ok(profile_path(config_home, snake)?.is_file())
}

/// What `install_profile` did with the live profile, and where the
/// reference copy landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileInstall {
    pub live: PathBuf,
    /// True when the live profile was written; false when one was already
    /// there and was left alone.
    pub written: bool,
    pub reference: PathBuf,
}

/// Install a named profile in both places, leaving a live one alone.
///
/// This is the entry point another project calls at startup: it ships the
/// profile it wants as text, asks for it to be placed, and if it had to
/// write one, tells its user to run `srcert` against that name.
///
/// The two copies have different rules on purpose. The LIVE profile is
/// written only when absent, because the user is meant to customise it
/// and an install must never overwrite that. The REFERENCE copy is
/// rewritten every time, because its whole job is to say what the
/// application currently ships - a stale reference is worse than none,
/// since it is what a customised profile gets diffed against. Nothing
/// reads the reference, so refreshing it cannot break a deployment.
///
/// The text is PARSED before either write, so a caller cannot install a
/// profile that `srcert` will then refuse to read.
pub fn install_profile(config_home: &Path, snake: &str, text: &str) -> Result<ProfileInstall> {
    let live = profile_path(config_home, snake)?;
    let reference = default_profile_path(config_home, snake)?;
    let _ = CertGenConfig::parse(text, &live)?;

    write_into(&reference, text)?;

    if live.is_file() {
        return Ok(ProfileInstall {
            live,
            written: false,
            reference,
        });
    }
    write_into(&live, text)?;
    Ok(ProfileInstall {
        live,
        written: true,
        reference,
    })
}

fn write_into(path: &Path, text: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)
            .map_err(|e| CertError::io(format!("creating {}", dir.display()), e))?;
    }
    fs::write(path, text).map_err(|e| CertError::io(format!("writing {}", path.display()), e))
}

/// Read a named profile.
pub fn load_profile(config_home: &Path, snake: &str) -> Result<CertGenConfig> {
    let path = profile_path(config_home, snake)?;
    if !path.is_file() {
        return Err(CertError::MissingProfile {
            name: snake.to_string(),
            path: path.display().to_string(),
        });
    }
    CertGenConfig::load(&path)
}

/// Every installed profile name, sorted.
pub fn installed_profiles(config_home: &Path) -> Result<Vec<String>> {
    let dir = profiles_dir(config_home);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(&dir)
        .map_err(|e| CertError::io(format!("reading {}", dir.display()), e))?;
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension()?.to_str()? != PROFILE_EXTENSION {
                return None;
            }
            Some(path.file_stem()?.to_str()?.to_string())
        })
        .collect();
    names.sort();
    Ok(names)
}

/// A profile name decides a filename, so it is a plain snake or nothing.
///
/// It is refused rather than sanitised: a cleaned name would address a
/// different profile than the one asked for, which is worse than an error.
pub fn validate_snake(snake: &str) -> Result<()> {
    let ok = !snake.is_empty()
        && snake
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if ok {
        return Ok(());
    }
    Err(CertError::InvalidProfileName {
        name: snake.to_string(),
    })
}
