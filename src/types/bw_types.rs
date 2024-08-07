use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Serialize, Deserialize, Debug)]
pub struct BwLoginResponse {
    #[serde(rename = "Kdf")]
    pub kdf: u32,
    #[serde(rename = "KdfIterations")]
    pub kdf_iterations: u32,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "PrivateKey")]
    pub private_key: String,
    #[serde(rename = "ResetMasterPassword")]
    pub reset_master_password: bool,
    pub access_token: String,
    pub expires_in: u32,
    pub scope: String,
    pub token_type: String,
    #[serde(rename = "unofficialServer")]
    pub unofficial_server: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BwPreloginResponse {
    pub kdf: u32,
    pub kdf_iterations: usize,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct BwSyncResponse {
    pub ciphers: Vec<BwCipher>,
    pub folders: Vec<BwFolder>,
}

#[derive(Serialize_repr, Deserialize_repr, Debug)]
#[repr(u8)]
pub enum BwCipherType {
    Login = 1,
    Note = 2,
    Card = 3,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct BwCipher {
    #[serde(rename = "Type")]
    pub t: BwCipherType,
    // pub login: Option<BwLogin>,
    pub notes: Option<String>,
    pub data: BwCipherData,
    pub name: String,
    pub folder_id: Option<String>,
}

#[derive(Serialize_repr, Deserialize_repr, Debug)]
#[repr(u8)]
pub enum BwFieldType {
    Text = 0,
    Hidden = 1,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct BwCipherData {
    pub fields: Option<Vec<BwCipherField>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct BwCipherField {
    #[serde(rename = "Type")]
    t: BwFieldType,
    pub name: Option<String>,
    pub value: Option<String>,
}

// #[derive(Serialize, Deserialize, Debug)]
// #[serde(rename_all = "PascalCase")]
// pub struct BwLogin {
//     pub username: String,
//     pub password: String,
// }

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct BwFolder {
    pub id: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BwTwoFactorResponse {
    #[serde(rename = "TwoFactorProviders")]
    pub two_factor_providers: Vec<u8>,
    #[serde(rename = "TwoFactorProviders2")]
    pub two_factor_map: HashMap<u8, Option<BwTwoFactorProvider>>,
    pub error: String,
    pub error_description: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum BwTwoFactorProvider {
    Fido {
        #[serde(rename = "allowCredentials")]
        allow_credentials: Vec<Thing>,
    },
    Yubico {
        #[serde(rename = "Nfc")]
        nfc: bool,
    },
    Email {
        #[serde(rename = "Email")]
        email: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Thing {
    pub id: String,
    #[serde(rename = "type")]
    pub t: String,
}
