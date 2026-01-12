use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct Versions {
    pub versions: Vec<Version>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Version {
    pub version: String,
    pub platforms: Vec<Platform>,
    pub protocols: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Platform {
    pub os: String,
    pub arch: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct TerraformRegistryManifest {
    pub version: u32,
    pub metadata: TerraformRegistryManifestMetadata,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct TerraformRegistryManifestMetadata {
    pub protocol_versions: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AssetsInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub os: String,
    pub arch: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GPGPublicKey {
    pub key_id: String,
    pub ascii_armor: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SigningKeys {
    pub gpg_public_keys: Vec<GPGPublicKey>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProviderPackage {
    pub protocols: Vec<String>,
    pub os: String,
    pub arch: String,
    pub filename: String,
    pub download_url: Option<String>,
    pub shasums_url: Option<String>,
    pub shasums_signature_url: Option<String>,
    pub shasum: Option<String>,
    pub signing_keys: SigningKeys,
}
