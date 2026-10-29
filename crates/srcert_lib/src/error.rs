pub type Result<T> = std::result::Result<T, CertError>;

/// Failures generating, installing or verifying a local CA and its leaf.
#[derive(Debug, snafu::Snafu)]
pub enum CertError {
    #[snafu(display("{context}: {source}"))]
    Io {
        context: String,
        source: std::io::Error,
    },

    #[snafu(display("{context}: {source}"))]
    Rcgen {
        context: String,
        source: rcgen::Error,
    },

    #[snafu(display("reading config {path}: {source}"))]
    ConfigRead {
        path: String,
        source: std::io::Error,
    },

    #[snafu(display("parsing config {path}: {source}"))]
    ConfigParse {
        path: String,
        source: toml::de::Error,
    },

    #[snafu(display(
        "no profile named {name:?}; expected {path}. Install one first - a \
         consuming application places its own on a first start"
    ))]
    MissingProfile { name: String, path: String },

    #[snafu(display(
        "invalid profile name {name:?}: a profile name is lowercase ascii, digits \
         and underscores"
    ))]
    InvalidProfileName { name: String },

    #[snafu(display("invalid subject_alt_names entry {value:?}: {reason}"))]
    InvalidSan { value: String, reason: String },

    #[snafu(display("{path} already exists"))]
    CertsDirExists { path: String },

    #[snafu(display("{what} {path} does not exist"))]
    MissingDir { what: String, path: String },

    #[snafu(display("{what} {path} is not a directory"))]
    NotADir { what: String, path: String },

    #[snafu(display(
        "unrecognized layout for certificate sources: {path}; missing \
         {name} files"
    ))]
    UnrecognizedCertSources { path: String, name: String },

    #[snafu(display("`{command}` failed ({status}): {stderr}"))]
    Command {
        command: String,
        status: String,
        stderr: String,
    },

    #[snafu(display("{message}"))]
    Msg { message: String },
}

impl CertError {
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    pub(crate) fn rcgen(context: impl Into<String>, source: rcgen::Error) -> Self {
        Self::Rcgen {
            context: context.into(),
            source,
        }
    }

    pub(crate) fn msg(message: impl Into<String>) -> Self {
        Self::Msg {
            message: message.into(),
        }
    }
}
