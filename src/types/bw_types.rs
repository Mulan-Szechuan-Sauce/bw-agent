use serde::{Serialize, Deserialize};
use serde_repr::{Serialize_repr, Deserialize_repr};

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
#[serde(rename_all = "PascalCase")]
pub struct BwPreloginResponse {
    pub kdf: u32,
    pub kdf_iterations: usize,
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
    pub name: String,
    pub value: String,
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

