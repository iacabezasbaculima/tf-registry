use crate::AppState;
use crate::models::{ModuleVersion, ModuleVersions, ModuleVersionsRoot};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use http::{HeaderMap, header};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct ParamsListModuleVersions {
    namespace: String,
    name: String,
    system: String,
}

/// https://developer.hashicorp.com/terraform/internals/module-registry-protocol#list-available-versions-for-a-specific-module
pub async fn list_module_versions(
    Path(ParamsListModuleVersions {
        namespace,
        name,
        system,
    }): Path<ParamsListModuleVersions>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ModuleVersionsRoot>, (StatusCode, String)> {
    tracing::info!(
        "listing module versions for {}/{}/{}",
        namespace,
        name,
        system
    );

    let mut releases = state
        .github
        .repos(&namespace, &name)
        .releases()
        .list()
        .per_page(100)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                format!("failed to list module releases: {}", e),
            )
        })?;

    let mut module_version_infos: Vec<ModuleVersion> = Vec::new();

    loop {
        for r in &releases {
            let no_prefix_tag_name: String = match r.tag_name.starts_with("v") {
                false => r.tag_name.clone(),
                true => r.tag_name.replace("v", ""),
            };
            module_version_infos.push(ModuleVersion {
                version: no_prefix_tag_name,
            });
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

    let versions = ModuleVersionsRoot {
        modules: vec![ModuleVersions {
            versions: module_version_infos,
        }],
    };

    Ok(Json(versions))
}

#[derive(Deserialize)]
pub struct ParamsDownloadModuleVersion {
    namespace: String,
    name: String,
    system: String,
    version: String,
}

/// https://developer.hashicorp.com/terraform/internals/module-registry-protocol#download-source-code-for-a-specific-module-version
pub async fn download_module_version(
    Path(ParamsDownloadModuleVersion {
        namespace,
        name,
        system,
        version,
    }): Path<ParamsDownloadModuleVersion>,
    State(state): State<Arc<AppState>>,
) -> Result<HeaderMap, (StatusCode, String)> {
    tracing::info!(
        "downloading module version {} for /{}/{}/{}",
        namespace,
        name,
        system,
        version
    );

    let path = format!("/repos/{}/{}/tarball/v{}", namespace, name, version);

    let mut headers = HeaderMap::new();
    headers.append(
        header::ACCEPT,
        "application/vnd.github+json".parse().unwrap(),
    );

    let res = state
        .no_redirect_github
        ._get_with_headers(path, Some(headers))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to send request to GitHub: {e}"),
            )
        })?;

    let status = res.status();

    if !status.is_redirection() && !status.is_success() {
        let body = state
            .no_redirect_github
            .body_to_string(res)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to read body: {e}"),
                )
            })?;

        return Err((
            status,
            format!("failed to get repo tarball, GitHub returned: {status} {body}"),
        ));
    }

    // Expect a redirect (302) with Location header
    if let Some(location) = res.headers().get(http::header::LOCATION) {
        let download_url = location.to_str().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("X-Terraform-Get", download_url.parse().unwrap());
        Ok(headers)
    } else {
        Err((
            StatusCode::NOT_FOUND,
            "failed to find Location header".to_string(),
        ))
    }
}
