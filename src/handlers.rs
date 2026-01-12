use crate::AppState;
use crate::error::RegistryError;
use crate::models::{
    AssetsInfo, GPGPublicKey, Platform, ProviderPackage, SigningKeys, TerraformRegistryManifest,
    Version, Versions,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use futures_util::StreamExt;
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

/// https://developer.hashicorp.com/terraform/internals/provider-registry-protocol#service-discovery
pub async fn discovery(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({"providers.v1": state.providers_api_base_url}))
}

#[derive(Deserialize)]
pub struct ParamsListVersions {
    namespace: String,
    provider_type: String,
}

/// https://developer.hashicorp.com/terraform/internals/provider-registry-protocol#list-available-versions
pub async fn list_versions(
    Path(ParamsListVersions {
        namespace,
        provider_type,
    }): Path<ParamsListVersions>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Versions>, (StatusCode, String)> {
    let provider = "terraform-provider-".to_string() + &provider_type;

    tracing::info!("listing versions for {}/{}", namespace, provider);

    let mut releases = state
        .github
        .repos(&namespace, &provider)
        .releases()
        .list()
        .per_page(100)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                format!("failed to list provider releases: {}", e),
            )
        })?;

    let mut versions = Versions { versions: vec![] };
    loop {
        for r in &releases {
            if r.assets.is_empty() {
                tracing::debug!("release {} has no assets, skipping", r.tag_name);
                continue;
            }

            let mut tf_registry_manifest = state
                .github
                .repos(&namespace, &provider)
                .get_content()
                .path("terraform-registry-manifest.json")
                .r#ref(r.tag_name.as_str())
                .send()
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("failed to fetch terraform registry manifest: {}", e),
                    )
                })?;

            let contents = tf_registry_manifest.take_items();
            let c = &contents[0];
            let decoded_content: TerraformRegistryManifest =
                serde_json::from_str(&c.decoded_content().unwrap()).unwrap();

            let assets_info = r
                .assets
                .iter()
                .filter_map(|a| match parse_asset_name(&a.name) {
                    Ok((os, arch, version)) => Some(AssetsInfo {
                        id: a.id.to_string(),
                        name: a.name.clone(),
                        version,
                        os,
                        arch,
                    }),
                    Err(e) => {
                        tracing::warn!("failed to parse asset name {}: {}", a.name, e);
                        None
                    }
                })
                .collect::<Vec<AssetsInfo>>();

            for asset in assets_info {
                versions.versions.push(Version {
                    version: asset.version,
                    platforms: vec![Platform {
                        os: asset.os,
                        arch: asset.arch,
                    }],
                    protocols: decoded_content.metadata.protocol_versions.clone(),
                });
            }
        }

        // Move to the next page
        releases = match state
            .github
            .get_page::<octocrab::models::repos::Release>(&releases.next)
            .await
            .unwrap()
        {
            Some(page) => page,
            None => break,
        };
    }

    if versions.versions.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("no releases found for provider: {}", provider),
        ));
    }

    Ok(Json(versions))
}

#[derive(Deserialize)]
pub struct ParamsFindProviderPackage {
    namespace: String,
    provider_type: String,
    version: String,
    os: String,
    arch: String,
}

/// https://developer.hashicorp.com/terraform/internals/provider-registry-protocol#find-a-provider-package
pub async fn find_provider_package(
    Path(ParamsFindProviderPackage {
        namespace,
        provider_type,
        version,
        os,
        arch,
    }): Path<ParamsFindProviderPackage>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ProviderPackage>, (StatusCode, String)> {
    tracing::info!(
        "finding provider package terraform-provider-{provider_type}_{version}_{os}_{arch}.zip"
    );

    let provider = "terraform-provider-".to_string() + &provider_type;

    let provider_release = state
        .github
        .repos(&namespace, &provider)
        .releases()
        .get_by_tag(&format!("v{}", version))
        .await
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                format!("provider release not found: {}", e),
            )
        })?;

    if provider_release.assets.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("no assets found for provider release: {}", version),
        ));
    }

    let mut tf_registry_manifest = state
        .github
        .repos(&namespace, &provider)
        .get_content()
        .path("terraform-registry-manifest.json")
        .r#ref(provider_release.tag_name.as_str())
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to fetch terraform registry manifest: {}", e),
            )
        })?;

    let contents = tf_registry_manifest.take_items();
    let c = &contents[0];
    let decoded_content: TerraformRegistryManifest =
        serde_json::from_str(&c.decoded_content().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to decode terraform manifest".to_string(),
        ))?)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to parse terraform manifest JSON: {}", e),
            )
        })?;

    let filename = format!("{}_{}_{}_{}.zip", provider, version, os, arch);
    let shasums_filename = format!("{}_{}_SHA256SUMS", provider, version);
    let shasums_sig_filename = format!("{}_{}_SHA256SUMS.sig", provider, version);

    let gpg_key_id = state.gpg_key_id.clone();
    let gpg_public_key = state.gpg_public_key.clone();

    let mut provider_package = ProviderPackage {
        protocols: decoded_content.metadata.protocol_versions,
        os: os.clone(),
        arch: arch.clone(),
        filename: filename.clone(),
        download_url: None,
        shasums_url: None,
        shasums_signature_url: None,
        shasum: None,
        signing_keys: SigningKeys {
            gpg_public_keys: vec![GPGPublicKey {
                key_id: gpg_key_id,
                ascii_armor: gpg_public_key,
            }],
        },
    };

    let assets_info = provider_release
        .assets
        .iter()
        .filter_map(|a| match parse_asset_name(&a.name) {
            Ok((os, arch, version)) => Some(AssetsInfo {
                id: a.id.to_string(),
                name: a.name.clone(),
                version,
                os,
                arch,
            }),
            Err(e) => {
                tracing::warn!("failed to parse asset name {}: {}", a.name, e);
                None
            }
        })
        .collect::<Vec<_>>();

    for asset in &assets_info {
        if asset.name == filename {
            provider_package.download_url =
                Some(get_release_asset(&state, &namespace, &provider, &asset.id).await?);
        } else if asset.name == shasums_filename {
            provider_package.shasums_url =
                Some(get_release_asset(&state, &namespace, &provider, &asset.id).await?);
            provider_package.shasum =
                Some(get_shasums(&state.github, &namespace, &provider, &asset.id, &filename).await?)
        } else if asset.name == shasums_sig_filename {
            provider_package.shasums_signature_url =
                Some(get_release_asset(&state, &namespace, &provider, &asset.id).await?);
        }
    }

    Ok(Json(provider_package))
}

/// Extract the `version`, `os` and `arch` values from a release asset name to build a `vec<AssetsInfo>`.
fn parse_asset_name(name: &str) -> Result<(String, String, String), RegistryError> {
    let pattern = r"^(?P<ProjectName>[^_]+)_(?P<Version>[^_]+)(?:_(?P<Os>[^_]+)_(?P<Arch>[^.]+)\.zip|_manifest\.json|_SHA256SUMS|_SHA256SUMS\.sig)$";
    let re = Regex::new(pattern).unwrap();

    if let Some(caps) = re.captures(name) {
        let version = caps
            .name("Version")
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let os = caps
            .name("Os")
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let arch = caps
            .name("Arch")
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        // Validate semantic versioning (x.y.z or x.y.z-prerelease)
        let semver_pattern = r"^\d+\.\d+\.\d+(?:-[a-zA-Z0-9\-.]+)?$";
        let semver_re = Regex::new(semver_pattern).unwrap();

        if !semver_re.is_match(&version) {
            return Err(RegistryError::InvalidAssetVersion(format!(
                "version '{}' in asset '{}' does not follow semantic versioning (x.y.z)",
                version, name
            )));
        }

        Ok((os, arch, version))
    } else {
        Err(RegistryError::InvalidAssetFilename(name.to_string()))
    }
}

/// Get the pre-signed download URL of a GitHub release asset.
async fn get_release_asset(
    state: &AppState,
    namespace: &str,
    provider: &str,
    asset_id_str: &str,
) -> Result<String, (StatusCode, String)> {
    let asset_id = asset_id_str.trim().parse::<u64>().map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            format!("invalid asset id '{}': {}", asset_id_str, e),
        )
    })?;

    let path = format!(
        "/repos/{}/{}/releases/assets/{}",
        namespace, provider, asset_id
    );

    let res = state
        .no_redirect_github
        ._get(path)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, format!("failed to get asset: {}", e)))?;

    // Expect a redirect (302) with Location header
    if let Some(location) = res.headers().get(http::header::LOCATION) {
        let download_url = location
            .to_str()
            .map_err(|e| {
                (
                    StatusCode::NOT_FOUND,
                    format!("invalid location header: {}", e),
                )
            })?
            .to_string();
        Ok(download_url)
    } else {
        Err((
            StatusCode::NOT_FOUND,
            "failed to find Location header".to_string(),
        ))
    }
}

/// Get the SHA256 checksum for the provider's zip archive as recorded in the shasums file.
async fn get_shasums(
    github_client: &octocrab::Octocrab,
    namespace: &str,
    provider: &str,
    asset_id: &str,
    filename: &str,
) -> Result<String, (StatusCode, String)> {
    let asset_id_num = asset_id.trim().parse::<u64>().map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            format!("invalid asset id '{}': {}", asset_id, e),
        )
    })?;

    let mut stream = github_client
        .repos(namespace, provider)
        .release_assets()
        .stream(asset_id_num)
        .await
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                format!("failed to create shasum file stream: {}", e),
            )
        })?;

    // 1. Create a buffer to hold the incoming bytes
    let mut body_bytes = Vec::new();

    while let Some(chunk) = stream.next().await {
        // Handle potential errors for each chunk in the stream
        let bytes = chunk.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read stream chunk: {}", e),
            )
        })?;
        body_bytes.extend_from_slice(&bytes);
    }

    // 2. Convert the accumulated bytes to a string
    let body_str = String::from_utf8_lossy(&body_bytes);

    // 3. Find shasum for file
    for line in body_str.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 2 && parts[1] == filename {
            return Ok(parts[0].to_string());
        }
    }

    Err((
        StatusCode::NOT_FOUND,
        format!(
            "shasum for {} not found in shasums file: {}",
            filename, body_str
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ========================================================================
    // parse_asset_name Tests
    // ========================================================================

    #[test]
    fn test_parse_asset_name_valid_zip() {
        let name = "terraform-provider-aws_1.2.3_linux_amd64.zip";
        let result = parse_asset_name(name);
        assert!(result.is_ok());

        let (os, arch, version) = result.unwrap();
        assert_eq!(os, "linux");
        assert_eq!(arch, "amd64");
        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn test_parse_asset_name_darwin_arm64() {
        let name = "terraform-provider-test_2.0.1_darwin_arm64.zip";
        let result = parse_asset_name(name);
        assert!(result.is_ok());

        let (os, arch, version) = result.unwrap();
        assert_eq!(os, "darwin");
        assert_eq!(arch, "arm64");
        assert_eq!(version, "2.0.1");
    }

    #[test]
    fn test_parse_asset_name_windows() {
        let name = "terraform-provider-azure_3.14.0_windows_amd64.zip";
        let result = parse_asset_name(name);
        assert!(result.is_ok());

        let (os, arch, version) = result.unwrap();
        assert_eq!(os, "windows");
        assert_eq!(arch, "amd64");
        assert_eq!(version, "3.14.0");
    }

    #[test]
    fn test_parse_asset_name_manifest_json() {
        let name = "terraform-provider-aws_1.2.3_manifest.json";
        let result = parse_asset_name(name);
        assert!(result.is_ok());

        let (os, arch, version) = result.unwrap();
        assert_eq!(os, "");
        assert_eq!(arch, "");
        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn test_parse_asset_name_sha256sums() {
        let name = "terraform-provider-aws_1.2.3_SHA256SUMS";
        let result = parse_asset_name(name);
        assert!(result.is_ok());

        let (os, arch, version) = result.unwrap();
        assert_eq!(os, "");
        assert_eq!(arch, "");
        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn test_parse_asset_name_sha256sums_sig() {
        let name = "terraform-provider-aws_1.2.3_SHA256SUMS.sig";
        let result = parse_asset_name(name);
        assert!(result.is_ok());

        let (os, arch, version) = result.unwrap();
        assert_eq!(os, "");
        assert_eq!(arch, "");
        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn test_parse_asset_name_invalid_format() {
        let name = "invalid-filename.txt";
        let result = parse_asset_name(name);
        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::InvalidAssetFilename(msg) => {
                assert!(msg.contains(name))
            }
            _ => panic!("wrong error type"),
        }
    }

    #[test]
    fn test_parse_asset_name_missing_extension() {
        let name = "terraform-provider-aws_1.2.3_linux_amd64";
        let result = parse_asset_name(name);
        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::InvalidAssetFilename(msg) => {
                assert!(msg.contains(name))
            }
            _ => panic!("wrong error type"),
        }
    }

    #[test]
    fn test_parse_asset_name_semver_with_prerelease() {
        let name = "terraform-provider-test_1.0.0-beta.1_linux_amd64.zip";
        let result = parse_asset_name(name);
        assert!(result.is_ok());

        let (os, arch, version) = result.unwrap();
        assert_eq!(os, "linux");
        assert_eq!(arch, "amd64");
        assert_eq!(version, "1.0.0-beta.1");
    }

    #[test]
    fn test_parse_asset_name_multiple_providers() {
        let names = vec![
            "terraform-provider-aws_1.2.3_linux_amd64.zip",
            "terraform-provider-gcp_2.0.0_darwin_arm64.zip",
            "terraform-provider-azure_3.1.0_windows_amd64.zip",
        ];

        for name in names {
            let result = parse_asset_name(name);
            assert!(result.is_ok());
            let (os, arch, version) = result.unwrap();
            assert!(!os.is_empty());
            assert!(!arch.is_empty());
            assert!(!version.is_empty());
        }
    }

    #[test]
    fn test_parse_asset_name_version_variations() {
        let test_cases = vec![
            ("terraform-provider-test_1.0.0_linux_amd64.zip", "1.0.0"),
            (
                "terraform-provider-test_10.20.30_linux_amd64.zip",
                "10.20.30",
            ),
            ("terraform-provider-test_0.1.0_linux_amd64.zip", "0.1.0"),
        ];

        for (name, expected_version) in test_cases {
            let result = parse_asset_name(name);
            assert!(result.is_ok());
            let (_, _, version) = result.unwrap();
            assert_eq!(version, expected_version);
        }
    }

    #[test]
    fn test_parse_asset_name_architecture_variations() {
        let architectures = vec!["amd64", "arm64", "arm", "386"];

        for arch_name in architectures {
            let name = format!("terraform-provider-test_1.0.0_linux_{}.zip", arch_name);
            let result = parse_asset_name(&name);
            assert!(result.is_ok());
            let (_, arch, _) = result.unwrap();
            assert_eq!(arch, arch_name);
        }
    }

    #[test]
    fn test_parse_asset_name_os_variations() {
        let operating_systems = vec!["linux", "darwin", "windows", "freebsd"];

        for os_name in operating_systems {
            let name = format!("terraform-provider-test_1.0.0_{}_amd64.zip", os_name);
            let result = parse_asset_name(&name);
            assert!(result.is_ok());
            let (os, _, _) = result.unwrap();
            assert_eq!(os, os_name);
        }
    }

    #[test]
    fn test_parse_asset_name_with_hyphens_in_provider() {
        let name = "terraform-provider-my-provider_1.0.0_linux_amd64.zip";
        let result = parse_asset_name(name);
        assert!(result.is_ok());
        let (os, arch, version) = result.unwrap();
        assert_eq!(os, "linux");
        assert_eq!(arch, "amd64");
        assert_eq!(version, "1.0.0");
    }

    #[test]
    fn test_parse_asset_name_case_sensitive() {
        // Terraform typically uses lowercase, but test uppercase variants
        let name = "terraform-provider-test_1.0.0_LINUX_AMD64.zip";
        let result = parse_asset_name(name);
        assert!(result.is_ok());
        let (os, arch, version) = result.unwrap();
        assert_eq!(os, "LINUX");
        assert_eq!(arch, "AMD64");
        assert_eq!(version, "1.0.0");
    }

    // ========================================================================
    // ParamsListVersions Tests
    // ========================================================================

    #[test]
    fn test_params_list_versions_deserialization() {
        let json = json!({
            "namespace": "hashicorp",
            "provider_type": "aws"
        });

        let params: ParamsListVersions = serde_json::from_value(json).unwrap();
        assert_eq!(params.namespace, "hashicorp");
        assert_eq!(params.provider_type, "aws");
    }

    // ========================================================================
    // ParamsFindProviderPackage Tests
    // ========================================================================

    #[test]
    fn test_params_find_provider_package_deserialization() {
        let json = json!({
            "namespace": "hashicorp",
            "provider_type": "aws",
            "version": "5.0.0",
            "os": "linux",
            "arch": "amd64"
        });

        let params: ParamsFindProviderPackage = serde_json::from_value(json).unwrap();
        assert_eq!(params.namespace, "hashicorp");
        assert_eq!(params.provider_type, "aws");
        assert_eq!(params.version, "5.0.0");
        assert_eq!(params.os, "linux");
        assert_eq!(params.arch, "amd64");
    }

    // ========================================================================
    // Edge Cases and Error Conditions
    // ========================================================================

    #[test]
    fn test_parse_asset_name_empty_string() {
        let result = parse_asset_name("");
        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::InvalidAssetFilename(msg) => {
                assert!(msg.contains(""))
            }
            _ => panic!("wrong error type"),
        }
    }

    #[test]
    fn test_parse_asset_name_special_characters() {
        let name = "terraform-provider-test_1.0.0_linux@amd64.zip";
        let result = parse_asset_name(name);
        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::InvalidAssetFilename(msg) => assert!(msg.contains(name)),
            _ => panic!("wrong error type"),
        }
    }

    #[test]
    fn test_parse_asset_name_regex_pattern_completeness() {
        // Test that the regex correctly handles all expected formats
        let test_cases = vec![
            ("terraform-provider-test_1.0.0_linux_amd64.zip", true),
            ("terraform-provider-test_1.0.0_manifest.json", false),
            ("terraform-provider-test_1.0.0_SHA256SUMS", false),
            ("terraform-provider-test_1.0.0_SHA256SUMS.sig", false),
        ];

        for (name, should_have_os_arch) in test_cases {
            let result = parse_asset_name(name);
            assert!(result.is_ok());
            let (os, arch, version) = result.unwrap();
            assert!(
                !version.is_empty(),
                "Version should always be parsed for valid names"
            );

            if should_have_os_arch {
                assert!(!os.is_empty(), "OS should be parsed for zip files");
                assert!(!arch.is_empty(), "Arch should be parsed for zip files");
            } else {
                assert!(os.is_empty(), "OS should be empty for non-zip files");
                assert!(arch.is_empty(), "Arch should be empty for non-zip files");
            }
        }
    }

    #[test]
    fn test_parse_asset_name_underscores_in_version() {
        // Versions should not contain underscores
        let name = "terraform-provider-test_1_0_0_linux_amd64.zip";
        let result = parse_asset_name(name);
        assert!(result.is_err());
        match result.unwrap_err() {
            RegistryError::InvalidAssetVersion(msg) => {
                assert!(msg.contains(name))
            }
            _ => panic!("wrong error type"),
        }
    }

    #[test]
    fn test_parse_asset_name_performance() {
        // Test that parsing is efficient for many files
        let names: Vec<String> = (0..1000)
            .map(|i| format!("terraform-provider-test_{}.0.0_linux_amd64.zip", i))
            .collect();

        for name in names {
            let result = parse_asset_name(&name);
            assert!(result.is_ok());
            let (os, arch, version) = result.unwrap();
            assert_eq!(os, "linux");
            assert_eq!(arch, "amd64");
            assert!(version.ends_with(".0.0"));
        }
    }
}
