use std::path::{Path, PathBuf};

use sourcetrait_cert_lib as lib_cert;

/// Default for `--secret-data`. sudo's env reset strips it, so an
/// elevated run needs `sudo -E` or the explicit flag.
const SECRET_DATA_ENV: &str = "XDGX_SECRET_DATA_HOME";

/// Every command names the profile it acts against, first.
///
/// There is no built-in fallback profile, and that is the point of the
/// tool: what a certificate says is a per-application decision, so a run
/// that did not name one would be minting something nobody chose.
#[derive(clap::Parser)]
#[command(
    name = "srcert",
    version,
    about = "Local TLS certificate authority, driven by named profiles"
)]
struct Cli {
    /// The profile to act against, as installed under
    /// `$XDG_CONFIG_HOME/sourcetrait/srcert/profiles`.
    profile: String,
    /// Override the configuration home the profile is read from.
    #[arg(long, global = true)]
    config_home: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Mint a local CA and the leaf it signs. Unprivileged.
    Generate {
        /// Directory to write into; the artifacts land in its `certs`
        /// subdir, which must not already exist.
        dir: PathBuf,
    },
    /// Place the key material and make the system trust the CA.
    Install {
        /// The dir passed to `generate`.
        dir: PathBuf,
        /// The secret DATA home; key material lands in its
        /// `sourcetrait/<name>/certs` subdir.
        #[arg(long)]
        secret_data: Option<PathBuf>,
        /// Override the detected trust store with a directory-model dir.
        #[arg(long)]
        trust_dir: Option<PathBuf>,
        #[arg(long)]
        update_command: Option<String>,
    },
    /// Confirm the CA is trusted and the keys are readable. Run
    /// UNPRIVILEGED.
    Verify {
        #[arg(long)]
        secret_data: Option<PathBuf>,
        /// The CA cert to look for. Defaults to the installed copy.
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        #[arg(long)]
        bundle: Option<PathBuf>,
    },
    /// Print the profile as it will be used, and where it was read from.
    Show,
}

pub fn run() -> lib_cert::Result<()> {
    let cli = <Cli as clap::Parser>::parse();
    let config_home = match cli.config_home {
        Some(path) => path,
        None => lib_cert::config_home()?,
    };
    let profile = &cli.profile;

    match cli.command {
        Command::Show => cmd_show(&config_home, profile),
        Command::Generate { dir } => {
            let config = lib_cert::load_profile(&config_home, profile)?;
            let files = lib_cert::generate(&config, &dir)?;
            for path in files.all() {
                println!("{}", path.display());
            }
            Ok(())
        }
        Command::Install {
            dir,
            secret_data,
            trust_dir,
            update_command,
        } => {
            let config = lib_cert::load_profile(&config_home, profile)?;
            let (secret_path, from_env) = resolve_secret_data(secret_data)?;
            cmd_install(
                &dir,
                &config.name,
                &secret_path,
                from_env,
                trust_dir.as_deref(),
                update_command.as_deref(),
            )
        }
        Command::Verify {
            secret_data,
            ca_cert,
            bundle,
        } => {
            let config = lib_cert::load_profile(&config_home, profile)?;
            let (secret_path, _) = resolve_secret_data(secret_data)?;
            cmd_verify(
                &secret_path,
                &config.name,
                ca_cert.as_deref(),
                bundle.as_deref(),
            )
        }
    }
}

/// The path plus where it came from: an explicit flag must already exist,
/// the env default is ours to create.
fn resolve_secret_data(explicit: Option<PathBuf>) -> lib_cert::Result<(PathBuf, bool)> {
    if let Some(path) = explicit {
        return Ok((path, false));
    }
    match std::env::var(SECRET_DATA_ENV) {
        Ok(v) if !v.is_empty() => Ok((PathBuf::from(v), true)),
        _ => Err(lib_cert::CertError::Msg {
            message: format!("pass --secret-data or set ${SECRET_DATA_ENV}"),
        }),
    }
}

fn cmd_show(config_home: &Path, profile: &str) -> lib_cert::Result<()> {
    let path = lib_cert::profile_path(config_home, profile)?;
    let config = lib_cert::load_profile(config_home, profile)?;
    println!("profile: {}", path.display());
    println!("name: {}", config.name);
    println!("organization: {}", config.organization);
    println!("validity_days: {}", config.validity_days);
    println!("authority: {}", config.authority.common_name);
    println!("entity: {}", config.entity.common_name);
    println!("subject_alt_names: {}", config.entity.subject_alt_names.join(", "));
    let usages: Vec<&str> = config
        .entity
        .usages
        .iter()
        .map(|usage| match usage {
            lib_cert::EntityUsage::Server => "server",
            lib_cert::EntityUsage::Client => "client",
        })
        .collect();
    println!("usages: {}", usages.join(", "));
    Ok(())
}

fn cmd_install(
    dir: &Path,
    name: &str,
    secret_data: &Path,
    secret_data_from_env: bool,
    trust_dir: Option<&Path>,
    update_command: Option<&str>,
) -> lib_cert::Result<()> {
    let (target, detected) = lib_cert::resolve_target(trust_dir, update_command)?;
    match detected {
        Some(id) => eprintln!("srcert: trust store {id}"),
        None => eprintln!("srcert: trust store from arguments"),
    }
    let secret = if secret_data_from_env {
        lib_cert::SecretData::FromEnv(secret_data)
    } else {
        lib_cert::SecretData::Explicit(secret_data)
    };
    let installed = lib_cert::install(&lib_cert::InstallPlan {
        cert_dir: dir,
        name,
        target: &target,
        secret_data: secret,
    })?;
    println!("{}", installed.trusted_at.display());
    for path in &installed.secrets {
        println!("{}", path.display());
    }
    match installed.staging {
        lib_cert::Staging::Removed(path) => {
            eprintln!("srcert: removed staging {}", path.display());
        }
        lib_cert::Staging::Kept { path, reason } => {
            eprintln!(
                "srcert: staging {} still holds a CA private key - {reason}",
                path.display(),
            );
        }
    }
    Ok(())
}

fn cmd_verify(
    secret_data: &Path,
    name: &str,
    ca_cert: Option<&Path>,
    bundle: Option<&Path>,
) -> lib_cert::Result<()> {
    let source = lib_cert::resolve_source(bundle)?;
    let verified = lib_cert::verify(&lib_cert::VerifyPlan {
        secret_data,
        name,
        source: &source,
        ca_cert,
    })?;
    for path in &verified.keys_read {
        println!("key readable: {}", path.display());
    }
    if !verified.ca_trusted {
        return Err(lib_cert::CertError::Msg {
            message: format!("CA is not trusted in {}", verified.trust_source),
        });
    }
    println!("ca trusted: {}", verified.trust_source);
    Ok(())
}
