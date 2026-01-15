use ngrok::config::ForwarderBuilder;
use std::{fs, path::PathBuf};
use tempfile::tempdir;
use tf_registry::{EncodingKey, Registry};

const TESTDATA_DIR: &str = "./tests/e2e/testdata";

#[tokio::test]
async fn test_e2e_terraform_init_provider() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // 0. Check terraform binary is available
    let tf_bin = if cfg!(windows) {
        "terraform.exe"
    } else {
        "terraform"
    };
    which::which(tf_bin).map_err(
        |_| "terraform CLI binary not found in PATH. Please install Terraform to run E2E tests.",
    )?;

    // 1. Create tf-registry app
    let app_id = std::env::var("GH_APP_ID")?.parse::<u64>()?;
    let private_key_base64 = std::env::var("GH_APP_PRIVATE_KEY_BASE64")?;
    let gpg_key_id = std::env::var("GPG_KEY_ID")?;
    let gpg_public_key_base64 = std::env::var("GPG_PUBLIC_KEY_BASE64")?;

    let registry = Registry::builder()
        .github_app(app_id, EncodingKey::Base64(private_key_base64))
        .gpg_signing_key(
            gpg_key_id,
            tf_registry::EncodingKey::Base64(gpg_public_key_base64),
        )
        .build()
        .await?;

    let app = registry.create_router();

    // 2. Spawn the tf-registry server
    // On Windows, binding to 0.0.0.0 (all interfaces) sometimes causes issues when a loopback request is made via a tunnel.
    // E.g.: ngrok::tunnel_ext: error connecting to upstream error=The requested address is not valid in its context. (os error 10049)
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        tracing::info!("tf-registry listening on http://{}", addr);
        axum::serve(listener, app).await.unwrap();
    });

    // 3. Set up ngrok tunnel
    let session = ngrok::Session::builder()
        .authtoken_from_env()
        .connect()
        .await?;

    tracing::info!("connected to ngrok session");

    let domain = std::env::var("NGROK_DOMAIN")?;
    let _tunnel = session
        .http_endpoint()
        .domain(&domain)
        // This acts as the "client" forwarding to the local tf-registry server
        .listen_and_forward(url::Url::parse(&format!("http://{}", addr))?)
        .await?;

    tracing::info!("ngrok tunnel established");

    // 4. Copy .tf fixture to temporary work dir
    let td = tempdir()?;
    let td_path = td.path();

    tracing::info!("created temporary test directory: {:?}", td_path);

    // Replace ngrok domain
    // Use PathBuf to ensure the paths work on Windows systems where the separator is \
    let fixture_source = PathBuf::from(TESTDATA_DIR).join("provider.tf");
    let fixture_content = fs::read_to_string(&fixture_source)?;
    let replaced_fixture = fixture_content.replace("{{NGROK_DOMAIN}}", &domain);
    let fixture_dest = td_path.join("main.tf");
    fs::write(&fixture_dest, replaced_fixture)?;

    tracing::info!("copied .tf fixture to temporary working dir");

    let has_tf_files = fs::read_dir(td_path)?
        .filter_map(|entry| entry.ok())
        .any(|entry| entry.path().extension().is_some_and(|ext| ext == "tf"));

    if !has_tf_files {
        return Err("no .tf fixture files found in the working directory".into());
    }

    // 5. Run 'terraform version'
    let tf_version_status = tokio::process::Command::new(tf_bin)
        .arg("version")
        .env("TF_LOG", "INFO")
        .env("TF_IN_AUTOMATION", "true")
        .status()
        .await?;

    if !tf_version_status.success() {
        return Err(format!(
            "terraform version failed with status: {}",
            tf_version_status
        )
        .into());
    }

    // 6. Run 'terraform init'
    let tf_init_status = tokio::process::Command::new(tf_bin)
        .arg("init")
        .current_dir(td_path)
        .env("TF_LOG", "INFO")
        .env("TF_IN_AUTOMATION", "true")
        .status()
        .await?;

    if !tf_init_status.success() {
        return Err(format!("terraform init failed with status: {}", tf_init_status).into());
    }

    Ok(())
}
