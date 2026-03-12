# tf-registry Justfile

# Registry port (override: PORT=8080 just run)
port := env_var_or_default("PORT", "9000")

# Ngrok domain (required for ngrok/e2e recipes)
# NGROK_AUTHTOKEN is intentionally not captured here — the ngrok CLI reads it directly
# from the environment, so there is no need to pass it as a flag.
ngrok_domain := env_var_or_default("NGROK_DOMAIN", "")

# ── CI ───────────────────────────────────────────────────────────────────────

# Run lint, build and tests (mirrors CI pipeline)
ci: lint build test

# ── Build ─────────────────────────────────────────────────────────────────────

# Build all targets
build:
    cargo build --all-targets

# Check without producing binaries (faster)
check:
    cargo check --all-targets

# ── Lint ─────────────────────────────────────────────────────────────────────

# Run formatter and clippy
lint:
    cargo fmt --all -- --check
    cargo clippy --tests --examples -- -D warnings

# Auto-format all source files
fmt:
    cargo fmt --all

# ── Docs ─────────────────────────────────────────────────────────────────────

# Generate crate docs and open in browser
docs:
    cargo doc --no-deps --open

# ── Run ──────────────────────────────────────────────────────────────────────

# Run the registry example (requires GH_TOKEN or GH_APP_* and GPG_* env vars)
run:
    PORT={{port}} cargo run --example registry

# ── Ngrok ────────────────────────────────────────────────────────────────────

# Start an ngrok tunnel to the local registry in the background.
# Requires NGROK_AUTHTOKEN and NGROK_DOMAIN env vars.
ngrok:
    ngrok http --url https://{{ngrok_domain}} {{port}}

# ── Tests ─────────────────────────────────────────────────────────────────────

# Run all tests (unit + integration; excludes e2e which needs ngrok)
test:
    cargo test --lib --test integration

# Run unit tests only
test-unit:
    cargo test --lib

# Run integration tests only
test-integration:
    cargo test --test integration

# Run e2e tests only (requires ngrok + Terraform)
test-e2e:
    cargo test --test e2e

# ── Curl ─────────────────────────────────────────────────────────────────────

# Hit the service discovery endpoint
curl-discovery:
    curl -s http://localhost:{{port}}/.well-known/terraform.json | jq

# List versions for a provider   (usage: just curl-provider-versions iacabezasbaculima sandbox)
curl-provider-versions namespace="iacabezasbaculima" provider="sandbox":
    curl -s http://localhost:{{port}}/terraform/providers/v1/{{namespace}}/{{provider}}/versions | jq

# Get download URL for a specific provider version
# (usage: just curl-provider-download iacabezasbaculima sandbox 0.1.0 linux amd64)
curl-provider-download namespace="iacabezasbaculima" provider="sandbox" version="0.1.0" os="linux" arch="amd64":
    curl -sv http://localhost:{{port}}/terraform/providers/v1/{{namespace}}/{{provider}}/{{version}}/download/{{os}}/{{arch}} 2>&1 | grep -E "< HTTP|location:|x-terraform"

# List versions for a module   (usage: just curl-module-versions terraform-aws-modules terraform-aws-ecr aws)
curl-module-versions namespace="terraform-aws-modules" name="terraform-aws-ecr" system="aws":
    curl -s http://localhost:{{port}}/terraform/modules/v1/{{namespace}}/{{name}}/{{system}}/versions | jq

# Get download URL for a specific module version
# (usage: just curl-module-download terraform-aws-modules terraform-aws-ecr aws 3.2.0)
curl-module-download namespace="terraform-aws-modules" name="terraform-aws-ecr" system="aws" version="3.2.0":
    curl -sv http://localhost:{{port}}/terraform/modules/v1/{{namespace}}/{{name}}/{{system}}/{{version}}/download 2>&1 | grep -E "< HTTP|x-terraform-get"
