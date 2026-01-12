# tf-registry

[![Crates.io](https://img.shields.io/crates/v/tf-registry?logo=rust)](https://crates.io/crates/tf-registry/)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/iacabezasbaculima/tf-registry/blob/main/LICENSE)
[![CI](https://github.com/iacabezasbaculima/tf-registry/actions/workflows/ci.yml/badge.svg)](https://github.com/iacabezasbaculima/tf-registry/actions/workflows/ci.yml)

A high-performance, asynchronous implementation of the **[Terraform Provider Registry](https://developer.hashicorp.com/terraform/internals/provider-registry-protocol)** protocol. Built with **Tokio** and **Axum**, it allows you to serve private Terraform providers natively using GitHub Releases as a storage backend.

- **Cost-Effective**: Replace expensive IaC management platforms with a tiny, serverless-friendly binary.
- **Zero Storage Overhead**: Uses GitHub Releases as the source of truth. No S3 buckets or databases to manage.
- **Native Experience**: Supports the full `terraform init` workflow. No more network or file mirror hacks or manual binary injections.
- **Built for Scale**: Leveraging **Axum** and **Tokio**, it handles concurrent provider downloads in large CI/CD pipelines with minimal CPU/RAM usage.

## 🚀 Why `tf-registry`?

Modern infrastructure teams often outgrow public registries but face significant hurdles when managing private providers. This crate exists to provide a middle ground between "expensive enterprise platforms" and "manual hackery."

### 1. Cost Optimization

Enterprise solutions like **Terraform Cloud** or **Harness IaC Management** charge significant premiums for private registry functionality. `tf-registry` allows teams to self-host a private registry as a lightweight container (ECS/Kubernetes) or a serverless function (Lambda/Cloud Run), drastically reducing licensing overhead.

### 2. Native Workflow Integration

Without a registry, teams are often forced to manually inject provider binaries into CI/CD runners or use `filesystem_mirror` configurations.

- **The Problem**: Manual binary management is brittle, insecure, and hard to version.
- **The Solution**: This crate enables a native `terraform init` workflow. Your providers are discovered and installed automatically, just like official HashiCorp providers.

### 3. Automated GitHub Distribution

By leveraging GitHub Releases as a backend, this registry eliminates the need for a separate storage layer. It dynamically maps Terraform's protocol requests to your GitHub-hosted assets, providing a seamless bridge between your provider's source code and its consumption.

### 4. High-Performance Asynchronicity

Built with **Tokio** and **Axum**, this registry is designed to handle high-concurrency environments (like massive parallel CI/CD jobs) with minimal memory footprint, making it ideal for cost-effective serverless deployment.

## 🛠 Features

- ✅ Protocol Compliant: Fully implements the Provider Registry Protocol.
- ✅ GitHub Integration: Powered by `octocrab` for efficient asset discovery and fetching.
- ✅ GPG Signing Support: Automates the delivery of GPG public keys so Terraform can verify provider authenticity.

## 🏁 Getting started

### 1. Requirements

- A GitHub Personal Access Token (PAT) with access to your private provider repositories.
- A GPG Public Key (Base64-encoded or PEM) used to sign your provider binaries.

### 2. Installation

```toml
[dependencies]
tf-registry = "0.1"
tokio = { version = "1.0", features = ["full"] }
```

### 3. Basic example

```rust,no_run
use tf_registry::Registry;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = std::env::var("GITHUB_TOKEN")?;
    let gpg_key_id = std::env::var("GPG_KEY_ID")?;
    let gpg_public_key_base64 = std::env::var("GPG_PUBLIC_KEY_BASE64")?;

    // 1. Configure the Registry
    let registry = Registry::builder()
        .github_token(token)
        .gpg_signing_key(
            gpg_key_id,
            tf_registry::EncodingKey::Base64(gpg_public_key_base64),
        )
        .build()
        .await?;

    // 2. Create the Axum Router
    let app = registry.create_router();

    // 3. Run it
    let listener = tokio::net::TcpListener::bind("0.0.0.0:9000").await?;
    println!("Registry listening on: {}", listener.local_addr()?);
    axum::serve(listener, app).await?;

    Ok(())
}
```

## 📂 Architecture & Workflow

1. **Terraform CLI** requests a provider (e.g., `registry.example.com/my-org/my-provider`).
2. `tf-registry` queries the GitHub API to find matching releases and assets (zip files and SHA sums).
3. `tf-registry` returns the signed metadata, pointing Terraform to the GitHub download URL.
4. **Terraform** verifies the download using the GPG key provided by the registry.

## License

This project is licensed under the [MIT license](https://github.com/iacabezasbaculima/tf-registry/blob/main/LICENSE).
