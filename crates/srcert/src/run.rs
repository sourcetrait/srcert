use std::path::{Path, PathBuf};

use srcert_lib as lib_cert;

use crate::style;

/// Every command names the profile it acts against.
#[derive(clap::Parser)]
#[command(
    name = "srcert",
    version,
    about = "Local TLS certificate authority, driven by named profiles"
)]
pub(crate) struct Cli {
    /// Override the configuration home the profile is read from.
    #[arg(long, global = true)]
    config_home: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(clap::Subcommand)]
pub(crate) enum Command {
    /// Mint an authority, an entity under one, or both. Unprivileged.
    Generate {
        #[command(subcommand)]
        what: Generate,
    },
    /// Place the key material and make the system trust the CA.
    Install {
        /// The profile to act against, by name, as installed.
        profile: String,
        /// The dir passed to `generate`.
        dir: PathBuf,
        /// Overrides the profile's `secret_data`, the secret DATA home.
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
        /// The profile to act against, by name, as installed.
        profile: String,
        /// Overrides the profile's `secret_data`, the secret DATA home.
        #[arg(long)]
        secret_data: Option<PathBuf>,
        /// The CA cert to look for. Defaults to the installed copy.
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        #[arg(long)]
        bundle: Option<PathBuf>,
    },
    /// Print the profile as it will be used, and where it was read from.
    Show {
        /// The profile to act against, by name, as installed.
        profile: String,
    },
}

/// What `generate` mints, each in a dir form or with its files by name.
#[derive(clap::Subcommand)]
pub(crate) enum Generate {
    /// Mint a local CA and the leaf it signs. Unprivileged.
    All {
        /// The profile to act against, by name, as installed.
        profile: String,
        /// Where to write; artifacts land in a `certs` subdirectory.
        dir: Option<PathBuf>,
        #[command(flatten)]
        files: FileFlags,
    },
    /// Mint a local CA alone. Unprivileged.
    Authority {
        /// The profile to act against, by name, as installed.
        profile: String,
        /// Where to write; the authority lands in a `certs` subdirectory.
        dir: Option<PathBuf>,
        #[command(flatten)]
        files: AuthorityFlags,
    },
    /// Mint an entity under an existing authority. Unprivileged.
    Entity {
        /// The profile to act against, by name, as installed.
        profile: String,
        /// The dir holding the existing authority (its `certs` subdir).
        authority_dir: Option<PathBuf>,
        /// Where to write the entity; lands in a `certs` subdirectory.
        out_dir: Option<PathBuf>,
        #[command(flatten)]
        files: FileFlags,
    },
}

/// The authority's two files by name, in place of a dir.
#[derive(clap::Args, Debug, Default)]
pub(crate) struct AuthorityFlags {
    /// The authority's certificate, by name.
    #[arg(long)]
    pub authority_cert: Option<PathBuf>,
    /// The authority's private key, by name.
    #[arg(long)]
    pub authority_key: Option<PathBuf>,
}

/// The authority's and the entity's four files by name, in place of the dirs.
#[derive(clap::Args, Debug, Default)]
pub(crate) struct FileFlags {
    #[command(flatten)]
    pub authority: AuthorityFlags,
    /// The entity's certificate, by name.
    #[arg(long)]
    pub entity_cert: Option<PathBuf>,
    /// The entity's private key, by name.
    #[arg(long)]
    pub entity_key: Option<PathBuf>,
}

/// The file form's flags for an authority alone.
const AUTHORITY_FLAGS: &str = "--authority-cert and --authority-key";

/// The file form's flags for an authority and an entity.
const FOUR_FLAGS: &str = "--authority-cert, --authority-key, --entity-cert, and --entity-key";

/// The authority's two files named, neither named, or one alone refused.
pub(crate) fn named_authority(
    flags: AuthorityFlags,
) -> lib_cert::Result<Option<lib_cert::AuthorityFiles>> {
    match (flags.authority_cert, flags.authority_key) {
        (None, None) => Ok(None),
        (Some(authority_public), Some(authority_private)) => Ok(Some(lib_cert::AuthorityFiles {
            authority_private,
            authority_public,
        })),
        _ => Err(part_refusal(AUTHORITY_FLAGS)),
    }
}

/// The four files named whole, none named, or a part refused.
pub(crate) fn named_files(flags: FileFlags) -> lib_cert::Result<Option<lib_cert::CertFiles>> {
    let authority = named_authority(flags.authority).map_err(|_| part_refusal(FOUR_FLAGS))?;
    match (authority, flags.entity_cert, flags.entity_key) {
        (None, None, None) => Ok(None),
        (Some(authority), Some(entity_public), Some(entity_private)) => {
            Ok(Some(lib_cert::CertFiles {
                authority_private: authority.authority_private,
                authority_public: authority.authority_public,
                entity_private,
                entity_public,
            }))
        }
        _ => Err(part_refusal(FOUR_FLAGS)),
    }
}

/// A part of the file form refused; `flags` names the whole of it.
fn part_refusal(flags: &str) -> lib_cert::CertError {
    lib_cert::CertError::Msg {
        message: format!("name all of {flags}, or none"),
    }
}

/// The dir form beside the file form, or neither, refused; `flags` names the file form.
fn form_refusal(dirs: bool, flags: &str) -> lib_cert::CertError {
    lib_cert::CertError::Msg {
        message: if dirs {
            format!("give the dirs or {flags}, not both")
        } else {
            format!("give the dirs, or {flags}")
        },
    }
}

/// A failure plus what was being attempted, for the reported line.
pub struct Failed {
    what: &'static str,
    cause: Box<lib_cert::CertError>,
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unable to {}: {}", self.what, self.cause)
    }
}

/// Render a failure; a cause with a shape of its own is given it.
pub fn report(failed: &Failed) {
    if let lib_cert::CertError::UnrecognizedCertSources { path, name } = failed.cause.as_ref() {
        style::fail_detail(
            &format!(
                "Unrecognized layout for certificate sources: {}",
                style::attention(Path::new(path))
            ),
            &[format!("Missing {} files", style::attention_named(name))],
        );
        return;
    }
    style::line(style::Kind::Fail, &failed.to_string());
}

/// Names the attempt at the only place that knows which verb ran.
fn failing(what: &'static str) -> impl FnOnce(lib_cert::CertError) -> Failed {
    move |cause| Failed {
        what,
        cause: Box::new(cause),
    }
}

pub fn run() -> Result<(), Failed> {
    let cli = <Cli as clap::Parser>::parse();
    let config_home = match cli.config_home {
        Some(path) => path,
        None => lib_cert::config_home().map_err(failing("resolve the configuration home"))?,
    };
    match cli.command {
        Command::Show { profile } => {
            cmd_show(&config_home, &profile).map_err(failing("read the profile"))
        }
        Command::Generate { what } => generate(&config_home, what),
        Command::Install {
            profile,
            dir,
            secret_data,
            trust_dir,
            update_command,
        } => cmd_install(
            &config_home,
            &profile,
            &dir,
            secret_data,
            trust_dir.as_deref(),
            update_command.as_deref(),
        )
        .map_err(failing("install the certificates")),
        Command::Verify {
            profile,
            secret_data,
            ca_cert,
            bundle,
        } => cmd_verify(
            &config_home,
            &profile,
            secret_data,
            ca_cert.as_deref(),
            bundle.as_deref(),
        )
        .map_err(failing("verify the installation")),
    }
}

/// The generate verbs, each naming its attempt.
fn generate(config_home: &Path, what: Generate) -> Result<(), Failed> {
    match what {
        Generate::All {
            profile,
            dir,
            files,
        } => cmd_generate(config_home, &profile, dir.as_deref(), files)
            .map_err(failing("generate the certificates")),
        Generate::Authority {
            profile,
            dir,
            files,
        } => cmd_generate_authority(config_home, &profile, dir.as_deref(), files)
            .map_err(failing("generate the authority")),
        Generate::Entity {
            profile,
            authority_dir,
            out_dir,
            files,
        } => cmd_generate_entity(
            config_home,
            &profile,
            authority_dir.as_deref(),
            out_dir.as_deref(),
            files,
        )
        .map_err(failing("generate the entity")),
    }
}

/// `--secret-data`, else the profile's own; a run naming neither is refused.
pub(crate) fn resolve_secret_data(
    explicit: Option<PathBuf>,
    profiled: Option<PathBuf>,
    profile_path: &Path,
) -> lib_cert::Result<PathBuf> {
    explicit.or(profiled).ok_or_else(|| lib_cert::CertError::Msg {
        message: format!(
            "pass --secret-data or set `secret_data` in {}",
            profile_path.display()
        ),
    })
}

fn cmd_show(config_home: &Path, profile: &str) -> lib_cert::Result<()> {
    let path = lib_cert::profile_path(config_home, profile)?;
    let config = lib_cert::load_profile(config_home, profile)?;
    let usages: Vec<&str> = config
        .entity
        .usages
        .iter()
        .map(|usage| match usage {
            lib_cert::EntityUsage::Server => "server",
            lib_cert::EntityUsage::Client => "client",
        })
        .collect();
    style::report(
        style::Kind::Info,
        &format!("Profile {}:", style::resource(&path)),
        &[
            format!("name: {}", config.name),
            format!("organization: {}", config.organization),
            format!("validity_days: {}", config.validity_days),
            format!(
                "secret_data: {}",
                config
                    .secret_data
                    .as_deref()
                    .map_or_else(|| String::from("unset"), |p| p.display().to_string())
            ),
            format!("authority: {}", config.authority.common_name),
            format!("entity: {}", config.entity.common_name),
            format!(
                "subject_alt_names: {}",
                config.entity.subject_alt_names.join(", ")
            ),
            format!("usages: {}", usages.join(", ")),
        ],
    );
    Ok(())
}

fn cmd_generate(
    config_home: &Path,
    profile: &str,
    dir: Option<&Path>,
    flags: FileFlags,
) -> lib_cert::Result<()> {
    let config = lib_cert::load_profile(config_home, profile)?;
    let files = match (dir, named_files(flags)?) {
        (Some(dir), None) => lib_cert::generate(&config, dir)?,
        (None, Some(files)) => lib_cert::generate_files(&config, files)?,
        (dir, _) => return Err(form_refusal(dir.is_some(), FOUR_FLAGS)),
    };
    let items: Vec<String> = files.all().iter().map(|p| style::pretty_path(p)).collect();
    style::report(style::Kind::Done, "Generated:", &items);
    Ok(())
}

fn cmd_generate_authority(
    config_home: &Path,
    profile: &str,
    dir: Option<&Path>,
    flags: AuthorityFlags,
) -> lib_cert::Result<()> {
    let config = lib_cert::load_profile(config_home, profile)?;
    let files = match (dir, named_authority(flags)?) {
        (Some(dir), None) => lib_cert::generate_authority(&config, dir)?,
        (None, Some(files)) => lib_cert::generate_authority_files(&config, files)?,
        (dir, _) => return Err(form_refusal(dir.is_some(), AUTHORITY_FLAGS)),
    };
    let items: Vec<String> = files.all().iter().map(|p| style::pretty_path(p)).collect();
    style::report(style::Kind::Done, "Generated authority:", &items);
    Ok(())
}

fn cmd_generate_entity(
    config_home: &Path,
    profile: &str,
    authority_dir: Option<&Path>,
    out_dir: Option<&Path>,
    flags: FileFlags,
) -> lib_cert::Result<()> {
    let config = lib_cert::load_profile(config_home, profile)?;
    let files = match (authority_dir, out_dir, named_files(flags)?) {
        (Some(authority_dir), Some(out_dir), None) => {
            lib_cert::generate_entity(&config, authority_dir, out_dir)?
        }
        (None, None, Some(files)) => {
            let authority = lib_cert::AuthorityFiles {
                authority_private: files.authority_private,
                authority_public: files.authority_public,
            };
            let entity = lib_cert::EntityFiles {
                entity_private: files.entity_private,
                entity_public: files.entity_public,
            };
            lib_cert::generate_entity_files(&config, &authority, entity)?
        }
        (Some(_), None, None) => {
            return Err(lib_cert::CertError::Msg {
                message: String::from("give the out dir beside the authority dir"),
            });
        }
        (authority_dir, out_dir, _) => {
            return Err(form_refusal(
                authority_dir.is_some() || out_dir.is_some(),
                FOUR_FLAGS,
            ));
        }
    };
    let items: Vec<String> = files.all().iter().map(|p| style::pretty_path(p)).collect();
    style::report(style::Kind::Done, "Generated entity:", &items);
    Ok(())
}

fn cmd_install(
    config_home: &Path,
    profile: &str,
    dir: &Path,
    secret_data: Option<PathBuf>,
    trust_dir: Option<&Path>,
    update_command: Option<&str>,
) -> lib_cert::Result<()> {
    let path = lib_cert::profile_path(config_home, profile)?;
    let config = lib_cert::load_profile(config_home, profile)?;
    let secret_home = resolve_secret_data(secret_data, config.secret_data.clone(), &path)?;
    let (target, detected) = lib_cert::resolve_target(trust_dir, update_command)?;

    let plan = lib_cert::InstallPlan {
        cert_dir: dir,
        name: &config.name,
        target: &target,
        secret_data: &secret_home,
    };

    lib_cert::preflight(&plan)?;

    match detected {
        Some(id) => style::line(
            style::Kind::Info,
            &format!("Trust store {}", style::named(id)),
        ),
        None => style::line(style::Kind::Info, "Trust store from arguments"),
    }

    if !style::confirm("Ready to install as super-user?") {
        return Err(lib_cert::CertError::Msg {
            message: String::from("declined at the super-user prompt"),
        });
    }

    let installed = lib_cert::install(&plan)?;

    let mut items = vec![style::pretty_path(&installed.trusted_at)];
    items.extend(installed.secrets.iter().map(|p| style::pretty_path(p)));
    style::report(style::Kind::Done, "Installed:", &items);

    match installed.staging {
        lib_cert::Staging::Removed(path) => style::line(
            style::Kind::Info,
            &format!("Removed staging {}", style::resource(&path)),
        ),
        lib_cert::Staging::Kept { path, reason } => style::line(
            style::Kind::Ask,
            &format!(
                "Staging {} still holds a CA private key - {reason}",
                style::resource(&path)
            ),
        ),
    }
    Ok(())
}

fn cmd_verify(
    config_home: &Path,
    profile: &str,
    secret_data: Option<PathBuf>,
    ca_cert: Option<&Path>,
    bundle: Option<&Path>,
) -> lib_cert::Result<()> {
    let path = lib_cert::profile_path(config_home, profile)?;
    let config = lib_cert::load_profile(config_home, profile)?;
    let secret_home = resolve_secret_data(secret_data, config.secret_data.clone(), &path)?;
    let source = lib_cert::resolve_source(bundle)?;
    let verified = lib_cert::verify(&lib_cert::VerifyPlan {
        secret_data: &secret_home,
        name: &config.name,
        source: &source,
        ca_cert,
    })?;
    let items: Vec<String> = verified
        .keys_read
        .iter()
        .map(|p| style::pretty_path(p))
        .collect();
    style::report(style::Kind::Info, "Keys readable:", &items);

    if !verified.ca_trusted {
        return Err(lib_cert::CertError::Msg {
            message: format!("the CA is not trusted in {}", verified.trust_source),
        });
    }
    style::line(
        style::Kind::Done,
        &format!("CA trusted in {}", style::named(&verified.trust_source)),
    );
    Ok(())
}
