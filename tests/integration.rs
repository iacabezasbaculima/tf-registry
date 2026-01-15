use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::prelude::*;
use serde_json::{Value, json};
use tf_registry::{EncodingKey, Registry};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

// ============================================================================
// Helper Functions
// ============================================================================

fn mock_gpg_public_key() -> String {
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
     mQENBGQxyz1234567890MOCK\n\
     -----END PGP PUBLIC KEY BLOCK-----"
        .to_string()
}

fn mock_terraform_manifest() -> Value {
    json!([{
        "name": "terraform-registry-manifest.json",
        "path": "terraform-registry-manifest.json",
        "sha": "fec2a5691e493a1941bd79b312b3925403a91aa6",
        "size": 83,
        "url": "https://api.github.com/repos/octo-org/terraform-provider-test/contents/terraform-registry-manifest.json?ref=v1.0.0",
        "html_url": "https://github.com/octo-org/terraform-provider-test/blob/main/terraform-registry-manifest.json",
        "git_url": "https://api.github.com/repos/octo-org/terraform-provider-test/git/blobs/fec2a5691e493a1941bd79b312b3925403a91aa6",
        "download_url": "https://raw.githubusercontent.com/octo-org/terraform-provider-test/v1.0.0/terraform-registry-manifest.json",
        "type": "file",
        "encoding": "base64",
        "content": base64::prelude::BASE64_STANDARD.encode(
            serde_json::to_string(&json!({
                "version": 1,
                "metadata": {
                    "protocol_versions": ["6.0"]
                }
            })).unwrap()
        ),
        "_links": {
          "self": "https://api.github.com/repos/octo-org/terraform-provider-test/contents/terraform-registry-manifest.json?ref=v1.0.0",
          "git": "https://api.github.com/repos/octo-org/terraform-provider-test/git/blobs/fec2a5691e493a1941bd79b312b3925403a91aa6",
          "html": "https://github.com/octo-org/terraform-provider-test/blob/v1.0.0/terraform-registry-manifest.json"
        }
    }])
}

fn mock_release_asset(id: u64, name: &str) -> Value {
    json!({
        "id": id,
        "node_id": "abcdef123",
        "name": name,
        "label": null,
        "content_type": "application/zip",
        "state": "uploaded",
        "size": 1024,
        "download_count": 0,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
        "url": format!("https://api.github.com/repos/octo-org/terraform-provider-test/releases/assets/{}", id),
        "browser_download_url": format!("https://github.com/octo-org/terraform-provider-test/releases/download/v1.0.0/{}", name),
        "author": {
            "login": "github-actions[bot]",
            "id": 41898282,
            "node_id": "MDM6Qm90NDE4OTgyODI=",
            "avatar_url": "https://avatars.githubusercontent.com/in/15368?v=4",
            "gravatar_id": "1",
            "url": "https://api.github.com/users/github-actions%5Bbot%5D",
            "html_url": "https://github.com/apps/github-actions",
            "followers_url": "https://api.github.com/users/github-actions%5Bbot%5D/followers",
            "following_url": "https://api.github.com/users/github-actions%5Bbot%5D/following{/other_user}",
            "gists_url": "https://api.github.com/users/github-actions%5Bbot%5D/gists{/gist_id}",
            "starred_url": "https://api.github.com/users/github-actions%5Bbot%5D/starred{/owner}{/repo}",
            "subscriptions_url": "https://api.github.com/users/github-actions%5Bbot%5D/subscriptions",
            "organizations_url": "https://api.github.com/users/github-actions%5Bbot%5D/orgs",
            "repos_url": "https://api.github.com/users/github-actions%5Bbot%5D/repos",
            "events_url": "https://api.github.com/users/github-actions%5Bbot%5D/events{/privacy}",
            "received_events_url": "https://api.github.com/users/github-actions%5Bbot%5D/received_events",
            "type": "Bot",
            "user_view_type": "public",
            "site_admin": false
        },
        "uploader": {
          "login": "github-actions[bot]",
          "id": 41898282,
          "node_id": "MDM6Qm90NDE4OTgyODI=",
          "avatar_url": "https://avatars.githubusercontent.com/in/15368?v=4",
          "gravatar_id": "1",
          "url": "https://api.github.com/users/github-actions%5Bbot%5D",
          "html_url": "https://github.com/apps/github-actions",
          "followers_url": "https://api.github.com/users/github-actions%5Bbot%5D/followers",
          "following_url": "https://api.github.com/users/github-actions%5Bbot%5D/following{/other_user}",
          "gists_url": "https://api.github.com/users/github-actions%5Bbot%5D/gists{/gist_id}",
          "starred_url": "https://api.github.com/users/github-actions%5Bbot%5D/starred{/owner}{/repo}",
          "subscriptions_url": "https://api.github.com/users/github-actions%5Bbot%5D/subscriptions",
          "organizations_url": "https://api.github.com/users/github-actions%5Bbot%5D/orgs",
          "repos_url": "https://api.github.com/users/github-actions%5Bbot%5D/repos",
          "events_url": "https://api.github.com/users/github-actions%5Bbot%5D/events{/privacy}",
          "received_events_url": "https://api.github.com/users/github-actions%5Bbot%5D/received_events",
          "type": "Bot",
          "user_view_type": "public",
          "site_admin": false
        }
    })
}

fn mock_release(tag_name: &str, assets: Vec<Value>) -> Value {
    json!({
        "id": 1,
        "node_id": "MDc6UmVsZWFzZTE=",
        "tag_name": tag_name,
        "target_commitish": "main",
        "name": format!("Release {}", tag_name),
        "body": "Test release",
        "draft": false,
        "prerelease": false,
        "created_at": "2024-01-01T00:00:00Z",
        "published_at": "2024-01-01T00:00:00Z",
        "url": format!("https://api.github.com/repos/octo-org/terraform-provider-test/releases/{}", tag_name),
        "html_url": format!("https://github.com/octo-org/terraform-provider-test/releases/tag/{}", tag_name),
        "assets_url": format!("https://api.github.com/repos/octo-org/terraform-provider-test/releases/1/assets"),
        "upload_url": "https://uploads.github.com/repos/octo-org/terraform-provider-test/releases/1/assets{?name,label}",
        "tarball_url": format!("https://api.github.com/repos/octo-org/terraform-provider-test/tarball/{}", tag_name),
        "zipball_url": format!("https://api.github.com/repos/octo-org/terraform-provider-test/zipball/{}", tag_name),
        "assets": assets,
        "author": {
            "login": "github-actions[bot]",
            "id": 41898282,
            "node_id": "MDM6Qm90NDE4OTgyODI=",
            "avatar_url": "https://avatars.githubusercontent.com/in/15368?v=4",
            "gravatar_id": "1",
            "url": "https://api.github.com/users/github-actions%5Bbot%5D",
            "html_url": "https://github.com/apps/github-actions",
            "followers_url": "https://api.github.com/users/github-actions%5Bbot%5D/followers",
            "following_url": "https://api.github.com/users/github-actions%5Bbot%5D/following{/other_user}",
            "gists_url": "https://api.github.com/users/github-actions%5Bbot%5D/gists{/gist_id}",
            "starred_url": "https://api.github.com/users/github-actions%5Bbot%5D/starred{/owner}{/repo}",
            "subscriptions_url": "https://api.github.com/users/github-actions%5Bbot%5D/subscriptions",
            "organizations_url": "https://api.github.com/users/github-actions%5Bbot%5D/orgs",
            "repos_url": "https://api.github.com/users/github-actions%5Bbot%5D/repos",
            "events_url": "https://api.github.com/users/github-actions%5Bbot%5D/events{/privacy}",
            "received_events_url": "https://api.github.com/users/github-actions%5Bbot%5D/received_events",
            "type": "Bot",
            "user_view_type": "public",
            "site_admin": false
        }
    })
}

// Create a paginated response with proper structure
// fn mock_paginated_releases(releases: Vec<Value>) -> Value {
//     json!(releases)
// }

async fn setup_test_registry(mock_server: &MockServer) -> Registry {
    Registry::builder()
        .github_base_uri(mock_server.uri())
        .github_token("ghp_test_token_123")
        .gpg_signing_key(
            "ABCD1234EFGH5678".to_string(),
            EncodingKey::Pem(mock_gpg_public_key()),
        )
        .build()
        .await
        .expect("Failed to build registry")
}

async fn setup_test_registry_with_custom_url(
    mock_server: &MockServer,
    providers_url: &str,
) -> Registry {
    Registry::builder()
        .github_base_uri(mock_server.uri())
        .github_token("ghp_test_token_123")
        .gpg_signing_key(
            "ABCD1234EFGH5678".to_string(),
            EncodingKey::Pem(mock_gpg_public_key()),
        )
        .providers_api_base_url(providers_url)
        .build()
        .await
        .expect("Failed to build registry")
}

// ============================================================================
// Discovery Endpoint Tests
// ============================================================================

#[tokio::test]
async fn test_discovery_default_url() {
    let mock_server = MockServer::start().await;
    let registry = setup_test_registry(&mock_server).await;
    let app = registry.create_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/terraform.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["providers.v1"], "/terraform/providers/v1/");
}

#[tokio::test]
async fn test_discovery_custom_url() {
    let mock_server = MockServer::start().await;
    let registry = setup_test_registry_with_custom_url(&mock_server, "/custom/api/v2/").await;
    let app = registry.create_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/terraform.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["providers.v1"], "/custom/api/v2/");
}

#[tokio::test]
async fn test_discovery_url_normalization() {
    let mock_server = MockServer::start().await;

    // Test URL without leading slash
    let registry = setup_test_registry_with_custom_url(&mock_server, "custom/api").await;
    let app = registry.create_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/terraform.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // Should be normalized to have leading and trailing slashes
    assert_eq!(json["providers.v1"], "/custom/api/");
}

// ============================================================================
// List Versions Endpoint Tests
// ============================================================================

#[tokio::test]
async fn test_list_versions_single_release() {
    let mock_server = MockServer::start().await;

    // Mock releases list endpoint with proper pagination structure
    Mock::given(method("GET"))
        .and(path("/repos/octo-org/terraform-provider-test/releases"))
        .and(query_param("per_page", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(vec![mock_release(
            "v1.0.0",
            vec![mock_release_asset(
                1,
                "terraform-provider-test_1.0.0_linux_amd64.zip",
            )],
        )]))
        .mount(&mock_server)
        .await;

    // Mock terraform manifest
    Mock::given(method("GET"))
        .and(path(
            "/repos/octo-org/terraform-provider-test/contents/terraform-registry-manifest.json",
        ))
        .and(query_param("ref", "v1.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_terraform_manifest()))
        .mount(&mock_server)
        .await;

    let registry = setup_test_registry(&mock_server).await;
    let app = registry.create_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/terraform/providers/v1/octo-org/test/versions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["versions"].is_array());
    let versions = json["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0]["version"], "1.0.0");
    assert_eq!(versions[0]["platforms"][0]["os"], "linux");
    assert_eq!(versions[0]["platforms"][0]["arch"], "amd64");
}

#[tokio::test]
async fn test_list_versions_multiple_platforms() {
    let mock_server = MockServer::start().await;

    // Mock releases list
    Mock::given(method("GET"))
        .and(path("/repos/octo-org/terraform-provider-test/releases"))
        .and(query_param("per_page", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(vec![mock_release(
            "v2.0.0",
            vec![
                mock_release_asset(1, "terraform-provider-test_2.0.0_linux_amd64.zip"),
                mock_release_asset(2, "terraform-provider-test_2.0.0_darwin_arm64.zip"),
                mock_release_asset(3, "terraform-provider-test_2.0.0_windows_amd64.zip"),
            ],
        )]))
        .mount(&mock_server)
        .await;

    // Mock terraform manifest
    Mock::given(method("GET"))
        .and(path(
            "/repos/octo-org/terraform-provider-test/contents/terraform-registry-manifest.json",
        ))
        .and(query_param("ref", "v2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_terraform_manifest()))
        .mount(&mock_server)
        .await;

    let registry = setup_test_registry(&mock_server).await;
    let app = registry.create_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/terraform/providers/v1/octo-org/test/versions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let versions = json["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 3); // One entry per platform
}

#[tokio::test]
async fn test_list_versions_skips_invalid_semver() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octo-org/terraform-provider-test/releases"))
        .and(query_param("per_page", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(vec![mock_release(
            "v1_0_0", // Invalid semver with underscores
            vec![mock_release_asset(
                1,
                "terraform-provider-test_1_0_0_linux_amd64.zip",
            )],
        )]))
        .mount(&mock_server)
        .await;

    // Mock terraform manifest
    Mock::given(method("GET"))
        .and(path(
            "/repos/octo-org/terraform-provider-test/contents/terraform-registry-manifest.json",
        ))
        .and(query_param("ref", "v1_0_0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_terraform_manifest()))
        .mount(&mock_server)
        .await;

    let registry = setup_test_registry(&mock_server).await;
    let app = registry.create_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/terraform/providers/v1/octo-org/test/versions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ============================================================================
// Find Provider Package Endpoint Tests
// ============================================================================

#[tokio::test]
async fn test_find_provider_package_success() {
    let mock_server = MockServer::start().await;

    // Mock get release by tag
    Mock::given(method("GET"))
        .and(path(
            "/repos/octo-org/terraform-provider-test/releases/tags/v1.0.0",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_release(
            "v1.0.0",
            vec![
                mock_release_asset(1, "terraform-provider-test_1.0.0_linux_amd64.zip"),
                mock_release_asset(2, "terraform-provider-test_1.0.0_SHA256SUMS"),
                mock_release_asset(3, "terraform-provider-test_1.0.0_SHA256SUMS.sig"),
            ],
        )))
        .mount(&mock_server)
        .await;

    // Mock terraform manifest
    Mock::given(method("GET"))
        .and(path(
            "/repos/octo-org/terraform-provider-test/contents/terraform-registry-manifest.json",
        ))
        .and(query_param("ref", "v1.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_terraform_manifest()))
        .mount(&mock_server)
        .await;

    // Mock .zip file
    Mock::given(method("GET"))
        .and(path(
            "/repos/octo-org/terraform-provider-test/releases/assets/1",
        ))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "Location",
            "https://github.com/download/terraform-provider-test_1.0.0_linux_amd64.zip",
        ))
        .mount(&mock_server)
        .await;

    // Mock SHA256SUMS file
    Mock::given(method("GET"))
        .and(path(
            "/repos/octo-org/terraform-provider-test/releases/assets/2",
        ))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "Location",
            format!(
                "{}/stream/terraform-provider-test_1.0.0_SHA256SUMS",
                &mock_server.uri()
            ),
        ))
        .mount(&mock_server)
        .await;

    // Mock SHA256SUMS file content stream
    Mock::given(method("GET"))
        .and(path("/stream/terraform-provider-test_1.0.0_SHA256SUMS"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("abc123def456  terraform-provider-test_1.0.0_linux_amd64.zip\n"),
        )
        .mount(&mock_server)
        .await;

    // Mock SHA256SUMS.sig file
    Mock::given(method("GET"))
        .and(path(
            "/repos/octo-org/terraform-provider-test/releases/assets/3",
        ))
        .respond_with(ResponseTemplate::new(200).insert_header(
            "Location",
            "https://github.com/download/terraform-provider-test_1.0.0_SHA256SUMS.sig",
        ))
        .mount(&mock_server)
        .await;

    let registry = setup_test_registry(&mock_server).await;
    let app = registry.create_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/terraform/providers/v1/octo-org/test/1.0.0/download/linux/amd64")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["os"], "linux");
    assert_eq!(json["arch"], "amd64");
    assert_eq!(
        json["filename"],
        "terraform-provider-test_1.0.0_linux_amd64.zip"
    );
    assert!(json["download_url"].is_string());
    assert!(json["shasums_url"].is_string());
    assert!(json["shasums_signature_url"].is_string());
    assert_eq!(json["shasum"], "abc123def456");
}

#[tokio::test]
async fn test_find_provider_package_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(
            "/repos/octo-org/terraform-provider-test/releases/tags/v999.0.0",
        ))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "message": "Not Found"
        })))
        .mount(&mock_server)
        .await;

    let registry = setup_test_registry(&mock_server).await;
    let app = registry.create_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/terraform/providers/v1/octo-org/test/999.0.0/download/linux/amd64")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_find_provider_package_no_assets() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(
            "/repos/octo-org/terraform-provider-test/releases/tags/v1.0.0",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tag_name": "v1.0.0",
            "assets": [],
            "url": "https://api.github.com/repos/octo-org/terraform-provider-test/releases/v1.0.0"
        })))
        .mount(&mock_server)
        .await;

    let registry = setup_test_registry(&mock_server).await;
    let app = registry.create_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/terraform/providers/v1/octo-org/test/1.0.0/download/linux/amd64")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ============================================================================
// Custom Providers API URL Tests
// ============================================================================

#[tokio::test]
async fn test_custom_providers_url_in_routes() {
    let mock_server = MockServer::start().await;
    let custom_url = "/custom/terraform/v2/";

    let registry = setup_test_registry_with_custom_url(&mock_server, custom_url).await;
    let app = registry.create_router();

    // Test that discovery returns custom URL
    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/terraform.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["providers.v1"], custom_url);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_malformed_request_path() {
    let mock_server = MockServer::start().await;
    let registry = setup_test_registry(&mock_server).await;
    let app = registry.create_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/terraform/providers/v1/invalid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// #[tokio::test]
// async fn test_github_api_error() {
//     let mock_server = MockServer::start().await;

//     Mock::given(method("GET"))
//         .and(path("/repos/octo-org/terraform-provider-test/releases"))
//         .respond_with(ResponseTemplate::new(500).set_body_json(json!({
//             "message": "Internal Server Error"
//         })))
//         .mount(&mock_server)
//         .await;

//     let registry = setup_test_registry(&mock_server).await;
//     let app = registry.create_router();

//     let response = app
//         .oneshot(
//             Request::builder()
//                 .uri("/terraform/providers/v1/octo-org/test/versions")
//                 .body(Body::empty())
//                 .unwrap(),
//         )
//         .await
//         .unwrap();

//     // Handler panics on unwrap, which Axum converts to 500
//     assert!(response.status().is_server_error());
// }
