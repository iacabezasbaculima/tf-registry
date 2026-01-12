use lambda_http::{Error, run, tracing};
use tf_registry::Registry;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

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

    run(app).await
}
