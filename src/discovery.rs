use crate::AppState;
use axum::{extract::State, response::Json};
use serde_json::{Value, json};
use std::sync::Arc;

/// https://developer.hashicorp.com/terraform/internals/provider-registry-protocol#service-discovery
pub async fn discovery(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "modules.v1": state.modules_api_base_url,
        "providers.v1": state.providers_api_base_url
    }))
}
