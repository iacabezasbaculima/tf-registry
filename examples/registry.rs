use tf_registry::{EncodingKey, Registry, RegistryBuilder};

/// Example: run tf-registry, auto-selecting GitHub authentication from environment variables.
///
/// Authentication (GH_TOKEN takes priority if both are set):
///   GH_TOKEN               - GitHub Personal Access Token (PAT)
///   GH_APP_ID                  - GitHub App ID (numeric)
///   GH_APP_PRIVATE_KEY_BASE64  - Base64-encoded PEM private key for the GitHub App
///
/// Required environment variables:
///   GPG_KEY_ID             - GPG key ID used to sign provider release artifacts
///   GPG_PUBLIC_KEY_BASE64  - Base64-encoded GPG public key
///
/// Optional environment variables:
///   PORT                   - Port to listen on (default: 9000)
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let gpg_key_id = std::env::var("GPG_KEY_ID")?;
    let gpg_public_key_base64 = std::env::var("GPG_PUBLIC_KEY_BASE64")?;

    let builder: RegistryBuilder = match std::env::var("GH_TOKEN") {
        Ok(token) => {
            tracing::info!("using GitHub Personal Access Token authentication");
            Registry::builder().github_token(token)
        }
        Err(_) => {
            let app_id = std::env::var("GH_APP_ID")
                .map_err(|_| "set GH_TOKEN or GH_APP_ID + GH_APP_PRIVATE_KEY_BASE64")?
                .parse::<u64>()?;
            let private_key_base64 = std::env::var("GH_APP_PRIVATE_KEY_BASE64")
                .map_err(|_| "GH_APP_PRIVATE_KEY_BASE64 is required when using GitHub App auth")?;
            tracing::info!("using GitHub App authentication (app_id={app_id})");
            Registry::builder().github_app(app_id, EncodingKey::Base64(private_key_base64))
        }
    };

    let registry = builder
        .gpg_signing_key(gpg_key_id, EncodingKey::Base64(gpg_public_key_base64))
        .build()
        .await?;

    let app = registry.create_router();

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "9000".to_string())
        .parse::<u16>()?;

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    println!("Listening on http://{addr}");
    println!();
    println!("Service discovery:");
    println!("  curl http://localhost:{port}/.well-known/terraform.json");
    println!();
    println!("Provider registry:");
    println!(
        "  curl http://localhost:{port}/terraform/providers/v1/<namespace>/<provider>/versions"
    );
    println!(
        "  curl http://localhost:{port}/terraform/providers/v1/<namespace>/<provider>/<version>/download/<os>/<arch>"
    );
    println!();
    println!("Module registry:");
    println!(
        "  curl http://localhost:{port}/terraform/modules/v1/<namespace>/<name>/<system>/versions"
    );
    println!(
        "  curl http://localhost:{port}/terraform/modules/v1/<namespace>/<name>/<system>/<version>/download"
    );

    axum::serve(listener, app).await?;

    Ok(())
}
