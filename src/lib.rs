//! A Terraform Provider Registry implementation backed by GitHub Releases.
//!
//! This crate provides a complete implementation of the [Terraform Provider Registry Protocol](https://developer.hashicorp.com/terraform/internals/provider-registry-protocol),
//! allowing you to host Terraform provider packages using GitHub Releases as the storage backend.
//!
//! # Features
//!
//! - **GitHub Authentication**: Supports both Personal Access Tokens and GitHub App authentication.
//! - **GPG Signing**: Provider package verification using GPG signatures.
//! - **Standard Protocol**: Full compliance with Terraform's Provider Registry Protocol.
//! - **Flexible Configuration**: Builder pattern for easy setup and customization.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use tf_registry::{Registry, EncodingKey};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Build the registry with Personal Access Token
//!     let registry = Registry::builder()
//!         .github_token("ghp_your_github_token")
//!         .gpg_signing_key(
//!             "ABCD1234EFGH5678".to_string(),
//!             EncodingKey::Pem("-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----".to_string())
//!         )
//!         .build()
//!         .await?;
//!
//!     // Create an Axum router
//!     let app = registry.create_router();
//!
//!     // Start the server
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:9000").await?;
//!     axum::serve(listener, app).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # GitHub App Authentication
//!
//! For production deployments, GitHub App authentication is recommended:
//!
//! ```rust,no_run
//! use tf_registry::{Registry, EncodingKey};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let registry = Registry::builder()
//!     .github_app(
//!         123456, // Your GitHub App ID
//!         EncodingKey::Base64("base64_encoded_private_key".to_string())
//!     )
//!     .gpg_signing_key(
//!         "ABCD1234EFGH5678".to_string(),
//!         EncodingKey::Pem(std::env::var("GPG_PUBLIC_KEY")?)
//!     )
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Custom Configuration
//!
//! ```rust,no_run
//! # use tf_registry::{Registry, EncodingKey};
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let registry = Registry::builder()
//!     .github_token("ghp_token")
//!     .gpg_signing_key("KEY_ID".to_string(), EncodingKey::Pem("...".to_string()))
//!     .providers_api_base_url("/custom/terraform/providers/v1/")
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! # GitHub Release Requirements
//!
//! For the registry to work correctly, your GitHub releases must include:
//!
//! 1. **Provider packages**: `terraform-provider-{name}_{version}_{os}_{arch}.zip`
//! 2. **Checksums file**: `terraform-provider-{name}_{version}_SHA256SUMS`
//! 3. **Signature file**: `terraform-provider-{name}_{version}_SHA256SUMS.sig`
//! 4. **Registry manifest**: A `terraform-registry-manifest.json` file in the repository root
//!
//! # Example Terraform Usage
//!
//! Once your registry is running, configure Terraform to use it:
//!
//! ```hcl
//! terraform {
//!   required_providers {
//!     myprovider = {
//!       source  = "registry.example.com/myorg/myprovider"
//!       version = "1.0.0"
//!     }
//!   }
//! }
//! ```

pub use error::RegistryError;

mod error;
mod handlers;
mod models;

use axum::{Router, routing::get};
use base64::prelude::*;
use octocrab::Octocrab;
use octocrab::models::AppId;
use octocrab::service::middleware::base_uri::BaseUriLayer;
use octocrab::service::middleware::extra_headers::ExtraHeadersLayer;
use secrecy::SecretString;
use std::fmt;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::{
    DefaultMakeSpan, DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, TraceLayer,
};
use tracing::Level;

/// Default base URL path for the Terraform Provider Registry API endpoints.
///
/// This follows the Terraform Provider Registry Protocol specification.
const PROVIDERS_API_BASE_URL: &str = "/terraform/providers/v1/";

// ============================================================================
// Registry (Main Public Struct)
// ============================================================================

/// The main Terraform Provider Registry.
///
/// This struct represents a configured Terraform Provider Registry that serves
/// provider packages from GitHub Releases. It implements the complete
/// [Terraform Provider Registry Protocol](https://developer.hashicorp.com/terraform/internals/provider-registry-protocol).
///
/// # Creating a Registry
///
/// Use the [`Registry::builder()`] method to create a new registry:
///
/// ```rust,no_run
/// # use tf_registry::{Registry, EncodingKey};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let registry = Registry::builder()
///     .github_token("ghp_your_token")
///     .gpg_signing_key(
///         "KEY_ID".to_string(),
///         EncodingKey::Pem("public_key".to_string())
///     )
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// # Creating a Router
///
/// Once built, create an Axum router with [`create_router()`](Registry::create_router):
///
/// ```rust,no_run
/// # use tf_registry::Registry;
/// # async fn example(registry: Registry) {
/// let app = registry.create_router();
/// # }
/// ```
pub struct Registry {
    state: Arc<AppState>,
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry")
            .field("state", &self.state)
            .finish()
    }
}

impl Registry {
    /// Creates a new [`RegistryBuilder`] for configuring a Registry.
    ///
    /// This is the recommended way to create a new Registry instance.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use tf_registry::{Registry, EncodingKey};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let registry = Registry::builder()
    ///     .github_token("ghp_token")
    ///     .gpg_signing_key("KEY_ID".to_string(), EncodingKey::Pem("...".to_string()))
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> RegistryBuilder {
        RegistryBuilder::default()
    }

    /// Creates an Axum [`Router`] configured with this Registry's routes and state.
    ///
    /// The router includes the following endpoints:
    ///
    /// - `/.well-known/terraform.json` - Service discovery
    /// - `/{base_url}/{namespace}/{type}/versions` - List available provider versions
    /// - `/{base_url}/{namespace}/{type}/{version}/download/{os}/{arch}` - Download provider package
    ///
    /// # Tracing
    ///
    /// The router includes HTTP tracing middleware that logs all requests and responses
    /// at the `DEBUG` level, including headers.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use tf_registry::Registry;
    /// # async fn example(registry: Registry) -> Result<(), Box<dyn std::error::Error>> {
    /// let app = registry.create_router();
    ///
    /// let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    /// axum::serve(listener, app).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn create_router(&self) -> Router {
        let middleware = ServiceBuilder::new().layer(
            TraceLayer::new_for_http()
                .make_span_with(
                    DefaultMakeSpan::new()
                        .include_headers(true)
                        .level(Level::DEBUG),
                )
                .on_request(DefaultOnRequest::new().level(Level::DEBUG))
                .on_response(
                    DefaultOnResponse::new()
                        .include_headers(true)
                        .level(Level::DEBUG),
                )
                .on_failure(DefaultOnFailure::new()),
        );

        // See more https://developer.hashicorp.com/terraform/internals/provider-registry-protocol
        let providers_api = Router::new()
            .route(
                "/{namespace}/{provider_type}/versions",
                get(handlers::list_versions),
            )
            .route(
                "/{namespace}/{provider_type}/{version}/download/{os}/{arch}",
                get(handlers::find_provider_package),
            );

        Router::new()
            .route("/.well-known/terraform.json", get(handlers::discovery))
            .nest(&self.state.providers_api_base_url, providers_api)
            .layer(middleware)
            .with_state(self.state.clone())
    }
}

// ============================================================================
// Internal AppState
// ============================================================================

/// Internal application state shared across handlers.
/// This struct contains the configuration and clients needed by the registry
/// handlers.
#[derive(Debug)]
struct AppState {
    /// Main GitHub API client
    github: Octocrab,
    /// Custom GitHub API client configured to not follow redirects.
    ///
    /// This client is specifically used for downloading release assets,
    /// where we need to extract the pre-signed download URL from the
    /// Location header instead of following the redirect.
    no_redirect_github: Octocrab,
    /// The uppercase hexadecimal-formatted ID of the GPG key.
    gpg_key_id: String,
    /// The ASCII-armored GPG public key.
    ///
    /// This is the full PEM-encoded public key block used to verify
    /// provider package signatures.
    gpg_public_key: String,
    /// Base URL path for the providers API routes.
    ///
    /// Default: "/terraform/providers/v1/"
    providers_api_base_url: String,
}

// ============================================================================
// RegistryBuilder
// ============================================================================

/// A builder for configuring and creating a [`Registry`].
///
/// This builder uses the builder pattern to allow flexible configuration
/// of the registry before creation. All configuration is validated when
/// [`build()`](RegistryBuilder::build) is called.
///
/// # Required Configuration
///
/// - GitHub authentication (via [`github_token()`](RegistryBuilder::github_token) or [`github_app()`](RegistryBuilder::github_app))
/// - GPG signing key (via [`gpg_signing_key()`](RegistryBuilder::gpg_signing_key))
///
/// # Optional Configuration
///
/// - Custom providers API base URL via [`providers_api_base_url()`](RegistryBuilder::providers_api_base_url)
/// - Custom GitHub base URI via [`github_base_uri()`](RegistryBuilder::github_base_uri) (mainly for testing)
///
/// # Examples
///
/// ## Basic configuration with Personal Access Token
///
/// ```rust,no_run
/// # use tf_registry::{Registry, EncodingKey};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let registry = Registry::builder()
///     .github_token("ghp_your_token_here")
///     .gpg_signing_key(
///         "ABCD1234EFGH5678".to_string(),
///         EncodingKey::Pem(std::env::var("GPG_PUBLIC_KEY")?)
///     )
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Configuration with GitHub App
///
/// ```rust,no_run
/// # use tf_registry::{Registry, EncodingKey};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let registry = Registry::builder()
///     .github_app(
///         123456,
///         EncodingKey::Base64(std::env::var("GITHUB_APP_PRIVATE_KEY")?)
///     )
///     .gpg_signing_key(
///         "ABCD1234".to_string(),
///         EncodingKey::Base64(std::env::var("GPG_PUBLIC_KEY")?)
///     )
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Custom providers API URL
///
/// ```rust,no_run
/// # use tf_registry::{Registry, EncodingKey};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let registry = Registry::builder()
///     .github_token("ghp_token")
///     .gpg_signing_key("KEY".to_string(), EncodingKey::Pem("...".to_string()))
///     .providers_api_base_url("/custom/api/v1/")
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct RegistryBuilder {
    base_uri: Option<String>,
    auth: Option<GitHubAuth>,
    gpg: Option<GPGSigningKey>,
    providers_api_base_url: Option<String>,
}

impl RegistryBuilder {
    /// Sets the base URL path for the providers API routes.
    ///
    /// The URL will be automatically normalized to ensure it starts and ends with '/'.
    ///
    /// # Default
    ///
    /// If not set, defaults to `"/terraform/providers/v1/"`.
    ///
    /// # Arguments
    ///
    /// * `url` - The base URL path.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use tf_registry::Registry;
    /// # fn example() {
    /// // All of these are equivalent:
    /// Registry::builder().providers_api_base_url("/custom/api/v1/");
    /// Registry::builder().providers_api_base_url("custom/api/v1");
    /// Registry::builder().providers_api_base_url("/custom/api/v1");
    /// # }
    /// ```
    pub fn providers_api_base_url(mut self, url: impl Into<String>) -> Self {
        self.providers_api_base_url = Some(url.into());
        self
    }

    /// Sets the base URI for the GitHub API client.
    ///
    /// This is primarily used for testing with mock GitHub API servers.
    /// In production, you typically don't need to set this.
    ///
    /// # Arguments
    ///
    /// * `base_uri` - The base URI (e.g., "http://localhost:9000" for testing)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use tf_registry::Registry;
    /// # fn example() {
    /// // For integration testing
    /// let builder = Registry::builder()
    ///     .github_base_uri("http://localhost:9000".to_string());
    /// # }
    /// ```
    pub fn github_base_uri(mut self, base_uri: String) -> Self {
        self.base_uri = Some(base_uri);
        self
    }

    /// Configures GitHub authentication using a Personal Access Token.
    ///
    /// # Requirements
    ///
    /// The token must have the following permissions:
    /// - `repo` scope (to access releases and repository contents)
    ///
    /// # Arguments
    ///
    /// * `token` - GitHub Personal Access Token (typically starts with "ghp_")
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use tf_registry::Registry;
    /// # fn example() {
    /// let builder = Registry::builder()
    ///     .github_token("ghp_your_token_here");
    /// # }
    /// ```
    ///
    /// # Security Note
    ///
    /// Never hardcode tokens in your source code. Use environment variables:
    ///
    /// ```rust,no_run
    /// # use tf_registry::Registry;
    /// # fn example() -> Result<(), std::env::VarError> {
    /// let builder = Registry::builder()
    ///     .github_token(std::env::var("GITHUB_TOKEN")?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn github_token(mut self, token: impl Into<String>) -> Self {
        self.auth = Some(GitHubAuth::PersonalToken(token.into()));
        self
    }

    /// Configures GitHub authentication using a GitHub App.
    ///
    /// This method is recommended for production deployments as it provides
    /// better security and higher rate limits than Personal Access Tokens.
    ///
    /// # Requirements
    ///
    /// The GitHub App must:
    /// - Be installed in the organization/account hosting the providers
    /// - Have `Contents: Read` permission
    /// - Have `Metadata: Read` permission
    ///
    /// # Assumptions
    ///
    /// This implementation assumes the GitHub App is installed in only one location
    /// (organization or account) and automatically uses the first installation found.
    ///
    /// # Arguments
    ///
    /// * `app_id` - The GitHub App ID (found in app settings)
    /// * `private_key` - The app's private key, either PEM or base64-encoded
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use tf_registry::{Registry, EncodingKey};
    /// # fn example() -> Result<(), std::env::VarError> {
    /// // Using PEM format
    /// let builder = Registry::builder()
    ///     .github_app(
    ///         123456,
    ///         EncodingKey::Pem(std::env::var("GITHUB_APP_PRIVATE_KEY")?)
    ///     );
    ///
    /// // Using base64-encoded format
    /// let builder = Registry::builder()
    ///     .github_app(
    ///         123456,
    ///         EncodingKey::Base64(std::env::var("GITHUB_APP_PRIVATE_KEY_B64")?)
    ///     );
    /// # Ok(())
    /// # }
    /// ```
    pub fn github_app(mut self, app_id: u64, private_key: EncodingKey) -> Self {
        self.auth = Some(GitHubAuth::App {
            app_id,
            private_key,
        });
        self
    }

    /// Sets the GPG signing key used to verify provider packages.
    ///
    /// This information is returned to Terraform clients so they can verify
    /// the authenticity of downloaded provider packages.
    ///
    /// # Arguments
    ///
    /// * `key_id` - The uppercase hexadecimal GPG key ID (e.g., "ABCD1234EFGH5678")
    /// * `public_key` - The ASCII-armored public key, either PEM or base64-encoded
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use tf_registry::{Registry, EncodingKey};
    /// # fn example() -> Result<(), std::env::VarError> {
    /// // Using PEM format (ASCII-armored)
    /// let builder = Registry::builder()
    ///     .gpg_signing_key(
    ///         "ABCD1234EFGH5678".to_string(),
    ///         EncodingKey::Pem(
    ///             "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----".to_string()
    ///         )
    ///     );
    ///
    /// // Using base64-encoded format
    /// let builder = Registry::builder()
    ///     .gpg_signing_key(
    ///         "ABCD1234EFGH5678".to_string(),
    ///         EncodingKey::Base64(std::env::var("GPG_PUBLIC_KEY_B64")?)
    ///     );
    /// # Ok(())
    /// # }
    /// ```
    pub fn gpg_signing_key(mut self, key_id: String, public_key: EncodingKey) -> Self {
        self.gpg = Some(GPGSigningKey { key_id, public_key });
        self
    }

    /// Builds the Registry with the configured settings.
    ///
    /// This method validates all configuration and creates the necessary GitHub
    /// API clients. It will return an error if required configuration is missing
    /// or invalid.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] errors, for example, GitHub authentication is not configured.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use tf_registry::{Registry, EncodingKey};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let registry = Registry::builder()
    ///     .github_token("ghp_token")
    ///     .gpg_signing_key("KEY_ID".to_string(), EncodingKey::Pem("...".to_string()))
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn build(self) -> Result<Registry, RegistryError> {
        // Destructure self to take ownership of all fields
        let Self {
            providers_api_base_url,
            base_uri,
            auth,
            gpg,
        } = self;

        // Validate required fields
        let auth = auth.ok_or(RegistryError::MissingAuth)?;
        let gpg = gpg.ok_or(RegistryError::MissingGPGSigningKey)?;

        let providers_api_base_url = Self::normalize_providers_api_url(providers_api_base_url)?;

        // Create GitHub client based on auth configuration
        let github = Self::create_octocrab_client(base_uri.clone(), &auth).await?;

        // Create custom client for asset downloads
        let no_redirect_github =
            Self::create_no_redirect_octocrab_client(base_uri.clone(), &auth).await?;

        // Create the state
        let state = AppState {
            github,
            no_redirect_github,
            providers_api_base_url,
            gpg_key_id: gpg.key_id.clone(),
            gpg_public_key: gpg.get_public_key()?,
        };

        Ok(Registry {
            state: Arc::new(state),
        })
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Creates the main Octocrab client with configured GitHub authentication.
    ///
    /// For GitHub App authentication, this automatically retrieves an installation
    /// token by selecting the first installation found.
    async fn create_octocrab_client(
        base_uri: Option<String>,
        auth: &GitHubAuth,
    ) -> Result<Octocrab, RegistryError> {
        match auth {
            GitHubAuth::PersonalToken(token) => {
                if let Some(val) = base_uri {
                    Octocrab::builder()
                        .base_uri(val)?
                        .personal_token(token.clone())
                        .build()
                        .map_err(RegistryError::GitHubInit)
                } else {
                    Octocrab::builder()
                        .personal_token(token.clone())
                        .build()
                        .map_err(RegistryError::GitHubInit)
                }
            }
            GitHubAuth::App { app_id, .. } => {
                let private_key = auth.get_private_key()?;
                let jwt = jsonwebtoken::EncodingKey::from_rsa_pem(&private_key).unwrap();

                let client = match base_uri {
                    Some(val) => octocrab::Octocrab::builder()
                        .base_uri(val)?
                        .app(AppId(*app_id), jwt)
                        .build()?,
                    None => octocrab::Octocrab::builder()
                        .app(AppId(*app_id), jwt)
                        .build()?,
                };

                let installations = client
                    .apps()
                    .installations()
                    .send()
                    .await
                    .unwrap()
                    .take_items();

                let (client, _) = client
                    .installation_and_token(installations[0].id)
                    .await
                    .unwrap();

                Ok(client)
            }
        }
    }

    /// Creates a custom Octocrab client configured for asset downloads.
    ///
    /// This client differs from the main client in that it:
    /// - Accepts `application/octet-stream` responses
    /// - Does not follow HTTP redirects (needed to extract Location headers)
    ///
    /// This is necessary because GitHub release asset downloads return a 302 redirect
    /// to a pre-signed download URL, and we need to extract that URL rather than follow it.
    async fn create_no_redirect_octocrab_client(
        base_uri: Option<String>,
        auth: &GitHubAuth,
    ) -> Result<Octocrab, RegistryError> {
        // Disable .https_only() during tests until: https://github.com/LukeMathWalker/wiremock-rs/issues/58 is resolved.
        // Alternatively we can use conditional compilation to only enable this feature in tests,
        // but it becomes rather ugly with integration tests.
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .unwrap()
            .https_or_http()
            .enable_http1()
            .build();

        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(connector);

        let parsed_uri: http::Uri = base_uri
            .unwrap_or_else(|| "https://api.github.com".to_string())
            .parse()
            .map_err(|_| RegistryError::InvalidConfig("invalid base URI".into()))?;

        let client = tower::ServiceBuilder::new()
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(
                        DefaultMakeSpan::new()
                            .include_headers(true)
                            .level(Level::DEBUG),
                    )
                    .on_request(DefaultOnRequest::new().level(Level::DEBUG))
                    .on_response(
                        DefaultOnResponse::new()
                            .include_headers(true)
                            .level(Level::DEBUG),
                    )
                    .on_failure(DefaultOnFailure::new()),
            )
            .service(client);

        let header_map = Arc::new(vec![
            (
                http::header::USER_AGENT,
                "no-redirect-octocrab".parse().unwrap(),
            ),
            (
                http::header::ACCEPT,
                "application/octet-stream".parse().unwrap(),
            ),
        ]);

        match auth {
            GitHubAuth::PersonalToken(token) => {
                let client = octocrab::OctocrabBuilder::new_empty()
                    .with_service(client)
                    .with_layer(&BaseUriLayer::new(parsed_uri))
                    .with_layer(&ExtraHeadersLayer::new(header_map))
                    .with_auth(octocrab::AuthState::AccessToken {
                        token: SecretString::from(token.as_str()),
                    })
                    .build()
                    .unwrap();

                Ok(client)
            }
            GitHubAuth::App { app_id, .. } => {
                let private_key = auth.get_private_key()?;
                let jwt = jsonwebtoken::EncodingKey::from_rsa_pem(&private_key).unwrap();

                let _client = Octocrab::builder()
                    .app(AppId(*app_id), jwt.clone())
                    .build()?;

                let installations = _client
                    .apps()
                    .installations()
                    .send()
                    .await
                    .map_err(RegistryError::GitHubInit)?
                    .take_items();

                let (_, token) = _client
                    .installation_and_token(installations.first().unwrap().id)
                    .await
                    .map_err(RegistryError::GitHubInit)?;

                let custom_client = octocrab::OctocrabBuilder::new_empty()
                    .with_service(client)
                    .with_layer(&BaseUriLayer::new(parsed_uri.clone()))
                    .with_layer(&ExtraHeadersLayer::new(header_map))
                    .with_auth(octocrab::AuthState::AccessToken { token })
                    .build()
                    .unwrap();

                Ok(custom_client)
            }
        }
    }

    /// Validates and normalizes the providers API base URL.
    ///
    /// Ensures the URL:
    /// - Is not empty
    /// - Starts with '/'
    /// - Ends with '/'
    fn normalize_providers_api_url(url: Option<String>) -> Result<String, RegistryError> {
        let url = url.unwrap_or_else(|| PROVIDERS_API_BASE_URL.to_string());

        if url.is_empty() {
            return Err(RegistryError::InvalidConfig(
                "providers API base URL cannot be empty".into(),
            ));
        }

        let url = if !url.starts_with('/') {
            format!("/{}", url)
        } else {
            url
        };

        let url = if !url.ends_with('/') {
            format!("{}/", url)
        } else {
            url
        };

        Ok(url)
    }
}

// ============================================================================
// Authentication Configuration
// ============================================================================

/// Encoding key types
#[derive(Debug, Clone)]
pub enum EncodingKey {
    Pem(String),
    Base64(String),
}

/// GitHub authentication methods supported by the registry
#[derive(Debug, Clone)]
enum GitHubAuth {
    /// Personal Access Token authentication
    PersonalToken(String),

    /// GitHub App authentication.
    ///
    /// It auto-selects the first installation to obtain an access token
    /// therefore assumming the GitHub app is only installed in the GitHub org
    /// where the provider package is located.
    App {
        app_id: u64,
        private_key: EncodingKey,
    },
}

impl GitHubAuth {
    /// Get the private key, converting from PEM or base64 if necessary
    fn get_private_key(&self) -> Result<Vec<u8>, RegistryError> {
        match self {
            GitHubAuth::PersonalToken(_) => {
                Err(RegistryError::InvalidConfig("not a GitHub App auth".into()))
            }
            GitHubAuth::App { private_key, .. } => match private_key {
                EncodingKey::Pem(val) => Ok(val.clone().into_bytes()),
                EncodingKey::Base64(val) => Ok(BASE64_STANDARD.decode(val).unwrap()),
            },
        }
    }
}

// We assume that a GitHub organisation uses the same GPG key to sign all providers
// for example, using org-wide GitHub secrets. Therefore, support only one GPG key.
#[derive(Clone)]
struct GPGSigningKey {
    key_id: String,
    public_key: EncodingKey,
}

impl GPGSigningKey {
    ///Get the GPG public key from PEM or base64 string
    fn get_public_key(&self) -> Result<String, RegistryError> {
        let GPGSigningKey { public_key, .. } = self;
        match public_key {
            EncodingKey::Pem(val) if val.is_empty() => Err(RegistryError::InvalidConfig(
                "pem gpg public key cannot be empty".into(),
            )),
            EncodingKey::Base64(val) if val.is_empty() => Err(RegistryError::InvalidConfig(
                "base64 gpg public key cannot be empty".into(),
            )),
            EncodingKey::Pem(val) => Ok(val.clone()),
            EncodingKey::Base64(val) => {
                let decoded = BASE64_STANDARD.decode(val.trim()).map_err(|_| {
                    RegistryError::InvalidConfig("invalid base64 gpg public key".into())
                })?;
                let result = String::from_utf8(decoded).map_err(|_| {
                    RegistryError::InvalidConfig("invalid decoded base64 gpg public key".into())
                })?;
                Ok(result)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // EncodingKey Tests
    // ========================================================================

    #[test]
    fn test_encoding_key_pem() {
        let key = EncodingKey::Pem("test-pem-key".to_string());
        match key {
            EncodingKey::Pem(s) => assert_eq!(s, "test-pem-key"),
            _ => panic!("Expected Pem variant"),
        }
    }

    #[test]
    fn test_encoding_key_base64() {
        let key = EncodingKey::Base64("dGVzdC1iYXNlNjQta2V5".to_string());
        match key {
            EncodingKey::Base64(s) => assert_eq!(s, "dGVzdC1iYXNlNjQta2V5"),
            _ => panic!("Expected Base64 variant"),
        }
    }

    // ========================================================================
    // GitHubAuth Tests
    // ========================================================================

    #[test]
    fn test_github_auth_personal_token() {
        let auth = GitHubAuth::PersonalToken("ghp_test123".to_string());
        match auth {
            GitHubAuth::PersonalToken(token) => assert_eq!(token, "ghp_test123"),
            _ => panic!("Expected PersonalToken variant"),
        }
    }

    #[test]
    fn test_github_auth_app() {
        let auth = GitHubAuth::App {
            app_id: 12345,
            private_key: EncodingKey::Pem("test-key".to_string()),
        };
        match auth {
            GitHubAuth::App { app_id, .. } => assert_eq!(app_id, 12345),
            _ => panic!("Expected App variant"),
        }
    }

    #[test]
    fn test_github_auth_get_private_key_pem() {
        let auth = GitHubAuth::App {
            app_id: 12345,
            private_key: EncodingKey::Pem("test-private-key".to_string()),
        };

        let key = auth.get_private_key().unwrap();
        assert_eq!(key, "test-private-key".as_bytes());
    }

    #[test]
    fn test_github_auth_get_private_key_base64() {
        let original = "test-private-key";
        let encoded = BASE64_STANDARD.encode(original);

        let auth = GitHubAuth::App {
            app_id: 12345,
            private_key: EncodingKey::Base64(encoded),
        };

        let key = auth.get_private_key().unwrap();
        assert_eq!(key, original.as_bytes());
    }

    #[test]
    fn test_github_auth_get_private_key_personal_token_error() {
        let auth = GitHubAuth::PersonalToken("token".to_string());
        let result = auth.get_private_key();

        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::InvalidConfig(msg) => assert_eq!(msg, "not a GitHub App auth"),
            _ => panic!("Expected InvalidConfig error"),
        }
    }

    // ========================================================================
    // GPGSigningKey Tests
    // ========================================================================

    #[test]
    fn test_gpg_signing_key_get_public_key_pem() {
        let gpg = GPGSigningKey {
            key_id: "ABCD1234".to_string(),
            public_key: EncodingKey::Pem("-----BEGIN PGP PUBLIC KEY BLOCK-----".to_string()),
        };

        let key = gpg.get_public_key().unwrap();
        assert_eq!(key, "-----BEGIN PGP PUBLIC KEY BLOCK-----");
    }

    #[test]
    fn test_gpg_signing_key_get_public_key_base64() {
        let original =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----";
        let encoded = BASE64_STANDARD.encode(original);

        let gpg = GPGSigningKey {
            key_id: "ABCD1234".to_string(),
            public_key: EncodingKey::Base64(encoded),
        };

        let key = gpg.get_public_key().unwrap();
        assert_eq!(key, original);
    }

    #[test]
    fn test_gpg_signing_key_empty_pem_error() {
        let gpg = GPGSigningKey {
            key_id: "ABCD1234".to_string(),
            public_key: EncodingKey::Pem("".to_string()),
        };

        let result = gpg.get_public_key();
        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::InvalidConfig(msg) => {
                assert_eq!(msg, "pem gpg public key cannot be empty")
            }
            _ => panic!("Expected InvalidConfig error"),
        }
    }

    #[test]
    fn test_gpg_signing_key_empty_base64_error() {
        let gpg = GPGSigningKey {
            key_id: "ABCD1234".to_string(),
            public_key: EncodingKey::Base64("".to_string()),
        };

        let result = gpg.get_public_key();
        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::InvalidConfig(msg) => {
                assert_eq!(msg, "base64 gpg public key cannot be empty")
            }
            _ => panic!("Expected InvalidConfig error"),
        }
    }

    #[test]
    fn test_gpg_signing_key_invalid_base64() {
        let gpg = GPGSigningKey {
            key_id: "ABCD1234".to_string(),
            public_key: EncodingKey::Base64("not-valid-base64!@#$".to_string()),
        };

        let result = gpg.get_public_key();
        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::InvalidConfig(msg) => {
                assert_eq!(msg, "invalid base64 gpg public key")
            }
            _ => panic!("Expected InvalidConfig error"),
        }
    }

    #[test]
    fn test_gpg_signing_key_base64_with_whitespace() {
        let original = "test-key";
        let encoded = format!("  {}  ", BASE64_STANDARD.encode(original));

        let gpg = GPGSigningKey {
            key_id: "ABCD1234".to_string(),
            public_key: EncodingKey::Base64(encoded),
        };

        let key = gpg.get_public_key().unwrap();
        assert_eq!(key, original);
    }

    // ========================================================================
    // RegistryBuilder Tests
    // ========================================================================

    #[test]
    fn test_registry_builder_default() {
        let builder = RegistryBuilder::default();
        assert!(builder.auth.is_none());
        assert!(builder.gpg.is_none());
    }

    #[test]
    fn test_registry_builder_new() {
        let builder = Registry::builder();
        assert!(builder.auth.is_none());
        assert!(builder.gpg.is_none());
    }

    #[test]
    fn test_registry_builder_github_base_uri() {
        let builder = Registry::builder().github_base_uri("http://localhost:9000".to_string());

        assert!(builder.base_uri.is_some());
        let val = builder.base_uri.unwrap();
        assert_eq!(val, "http://localhost:9000")
    }

    #[test]
    fn test_registry_builder_github_token() {
        let builder = Registry::builder().github_token("ghp_test123");

        assert!(builder.auth.is_some());
        match builder.auth.unwrap() {
            GitHubAuth::PersonalToken(token) => assert_eq!(token, "ghp_test123"),
            _ => panic!("Expected PersonalToken"),
        }
    }

    #[test]
    fn test_registry_builder_github_app() {
        let builder =
            Registry::builder().github_app(12345, EncodingKey::Pem("test-key".to_string()));

        assert!(builder.auth.is_some());
        match builder.auth.unwrap() {
            GitHubAuth::App { app_id, .. } => assert_eq!(app_id, 12345),
            _ => panic!("Expected App"),
        }
    }

    #[test]
    fn test_registry_builder_gpg_signing_key() {
        let builder = Registry::builder().gpg_signing_key(
            "ABCD1234".to_string(),
            EncodingKey::Pem("test-public-key".to_string()),
        );

        assert!(builder.gpg.is_some());
        let gpg = builder.gpg.unwrap();
        assert_eq!(gpg.key_id, "ABCD1234");
    }

    #[test]
    fn test_registry_builder_chaining() {
        let builder = Registry::builder()
            .github_token("ghp_test123")
            .gpg_signing_key(
                "ABCD1234".to_string(),
                EncodingKey::Pem("test-key".to_string()),
            );

        assert!(builder.auth.is_some());
        assert!(builder.gpg.is_some());
    }

    #[tokio::test]
    async fn test_registry_builder_github_base_uri_missing() {
        let builder = Registry::builder()
            .github_token("ghp_test123")
            .gpg_signing_key(
                "ABCD1234".to_string(),
                EncodingKey::Pem("test-key".to_string()),
            );
        assert!(builder.base_uri.is_none());
        let result = builder.build().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_registry_builder_build_missing_auth() {
        let builder = Registry::builder().gpg_signing_key(
            "ABCD1234".to_string(),
            EncodingKey::Pem("test-key".to_string()),
        );

        let result = builder.build().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::MissingAuth => {}
            _ => panic!("Expected MissingAuth error"),
        }
    }

    #[tokio::test]
    async fn test_registry_builder_build_missing_gpg() {
        let builder = Registry::builder().github_token("ghp_test123");

        let result = builder.build().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::MissingGPGSigningKey => {}
            _ => panic!("Expected MissingGPGSigningKey error"),
        }
    }

    #[test]
    fn test_normalize_providers_api_url_default() {
        let result = RegistryBuilder::normalize_providers_api_url(None).unwrap();
        assert_eq!(result, PROVIDERS_API_BASE_URL);
    }

    #[test]
    fn test_normalize_providers_api_url_with_slashes() {
        let result =
            RegistryBuilder::normalize_providers_api_url(Some("/custom/api/".to_string())).unwrap();
        assert_eq!(result, "/custom/api/");
    }

    #[test]
    fn test_normalize_providers_api_url_missing_leading_slash() {
        let result =
            RegistryBuilder::normalize_providers_api_url(Some("custom/api/".to_string())).unwrap();
        assert_eq!(result, "/custom/api/");
    }

    #[test]
    fn test_normalize_providers_api_url_missing_trailing_slash() {
        let result =
            RegistryBuilder::normalize_providers_api_url(Some("/custom/api".to_string())).unwrap();
        assert_eq!(result, "/custom/api/");
    }

    #[test]
    fn test_normalize_providers_api_url_missing_both_slashes() {
        let result =
            RegistryBuilder::normalize_providers_api_url(Some("custom/api".to_string())).unwrap();
        assert_eq!(result, "/custom/api/");
    }

    #[test]
    fn test_normalize_providers_api_url_empty_error() {
        let result = RegistryBuilder::normalize_providers_api_url(Some("".to_string()));
        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::InvalidConfig(msg) => {
                assert!(msg.contains("cannot be empty"));
            }
            _ => panic!("Expected InvalidConfig error"),
        }
    }

    #[tokio::test]
    async fn test_registry_builder_with_custom_providers_url() {
        let builder = Registry::builder()
            .github_token("ghp_test123")
            .gpg_signing_key(
                "ABCD1234".to_string(),
                EncodingKey::Pem("test-key".to_string()),
            )
            .providers_api_base_url("/custom/providers/v2/");

        assert!(builder.providers_api_base_url.is_some());
        let result = builder.build().await;
        assert!(result.is_ok());
    }
}
