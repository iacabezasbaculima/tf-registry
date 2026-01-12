/// Errors that can occur while configuring, building, or operating the [`crate::Registry`].
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("gitHub authentication is required (either token or app credentials)")]
    MissingAuth,

    #[error("gpg signing key details are required")]
    MissingGPGSigningKey,

    #[error("github client initialization failed: {0}")]
    GitHubInit(#[from] octocrab::Error),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("invalid asset filename: {0}")]
    InvalidAssetFilename(String),

    #[error("invalid asset version: {0}")]
    InvalidAssetVersion(String),
}
