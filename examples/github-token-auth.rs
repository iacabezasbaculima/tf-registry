use tf_registry::Registry;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let token = std::env::var("GITHUB_TOKEN")?;
    let gpg_key_id = std::env::var("GPG_KEY_ID")?;
    let gpg_public_key_base64 = std::env::var("GPG_PUBLIC_KEY_BASE64")?;

    let registry = Registry::builder()
        .github_token(token)
        .gpg_signing_key(
            gpg_key_id,
            tf_registry::EncodingKey::Base64(gpg_public_key_base64),
        )
        .build()
        .await?;

    let app = registry.create_router();

    // Start server
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "9000".to_string())
        .parse::<u16>()?;

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    println!("Listening on http://{}", addr);
    println!("Example usage:");
    println!("curl http://localhost:9000/well-known/terraform.json");
    println!("curl http://localhost:9000/<providers uri>/<namespace>/<provider_type>/versions");
    println!(
        "curl http://localhost:9000/<providers uri>/<namespace>/<provider_type>/<version>/download/<os>/<arch>"
    );

    axum::serve(listener, app).await?;

    Ok(())
}
