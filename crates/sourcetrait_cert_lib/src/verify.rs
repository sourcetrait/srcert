use crate::*;

use crate::store::TrustSource;

pub struct VerifyPlan<'a> {
    /// The secret DATA home holding `sourcetrait/<name>/certs`.
    pub secret_data: &'a Path,
    pub name: &'a str,
    pub source: &'a TrustSource,
    /// The CA cert to look for; defaults to the installed copy.
    pub ca_cert: Option<&'a Path>,
}

pub struct Verified {
    pub keys_read: Vec<PathBuf>,
    pub trust_source: String,
    pub ca_trusted: bool,
}

/// Is the CA trusted, and can the INVOKING user read both private keys?
pub fn verify(plan: &VerifyPlan<'_>) -> Result<Verified> {
    let secret_dir = crate::generate::secret_certs_dir(plan.secret_data, plan.name);

    let mut keys_read = Vec::new();
    for key_name in [
        format!("authority_{}.key.pem", plan.name),
        format!("entity_{}.key.pem", plan.name),
    ] {
        let path = secret_dir.join(&key_name);
        let text = fs::read_to_string(&path)
            .map_err(|e| CertError::io(format!("reading {}", path.display()), e))?;
        if !text.contains("PRIVATE KEY") {
            return Err(CertError::msg(format!(
                "{} is not a PEM private key",
                path.display(),
            )));
        }
        keys_read.push(path);
    }

    let ca_path = plan
        .ca_cert
        .map(Path::to_path_buf)
        .unwrap_or_else(|| secret_dir.join(format!("authority_{}.pem", plan.name)));
    let ca = fs::read_to_string(&ca_path)
        .map_err(|e| CertError::io(format!("reading {}", ca_path.display()), e))?;

    let (trust_source, trusted_set) = read_trusted_set(plan.source)?;

    Ok(Verified {
        keys_read,
        trust_source,
        ca_trusted: contains_cert(&trusted_set, &ca),
    })
}

/// Every trusted certificate as PEM text, plus where it came from.
fn read_trusted_set(source: &TrustSource) -> Result<(String, String)> {
    match source {
        TrustSource::Bundle(path) => {
            let text = fs::read_to_string(path)
                .map_err(|e| CertError::io(format!("reading {}", path.display()), e))?;
            Ok((path.display().to_string(), text))
        }
        TrustSource::Keychain { program, keychain } => {
            let key = keychain.to_string_lossy().into_owned();
            let output = process::Command::new(program)
                .args(["find-certificate", "-a", "-p", &key])
                .output()
                .map_err(|e| CertError::io(format!("running {program}"), e))?;
            if !output.status.success() {
                return Err(CertError::Command {
                    command: format!("{program} find-certificate"),
                    status: output.status.to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
                });
            }
            Ok((
                keychain.display().to_string(),
                String::from_utf8_lossy(&output.stdout).into_owned(),
            ))
        }
    }
}

/// Compared on the base64 body, with all whitespace stripped.
pub fn contains_cert(trusted_set: &str, cert_pem: &str) -> bool {
    let body = pem_body(cert_pem);
    if body.is_empty() {
        return false;
    }
    strip_whitespace(trusted_set).contains(&body)
}

pub fn pem_body(pem: &str) -> String {
    let inner: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    strip_whitespace(&inner)
}

fn strip_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}
