use clap::Parser;
use serde::{Serialize, Deserialize};
use serde_repr::{Serialize_repr, Deserialize_repr};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
   #[arg(short, long)]
   pub config: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub url: String,
    pub oauth_client_id: String,
    pub oauth_client_secret: String,
    pub email: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginResponse {
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
pub struct SyncResponse {
    pub ciphers: Vec<BwCipher>,
    pub folders: Vec<Folder>,
}

#[derive(Serialize_repr, Deserialize_repr, Debug)]
#[repr(u8)]
pub enum CipherType {
    Login = 1,
    Note = 2,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct BwCipher {
    #[serde(rename = "Type")]
    pub t: CipherType,
    pub login: Option<Login>,
    pub notes: Option<String>,
    pub data: Data,
    pub name: String,
    pub folder_id: Option<String>,
}

#[derive(Serialize_repr, Deserialize_repr, Debug)]
#[repr(u8)]
pub enum FieldType {
    Something = 1,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Data {
    pub fields: Option<Vec<Field>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Field {
    #[serde(rename = "Type")]
    t: FieldType,
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Login {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Folder {
    pub id: String,
    pub name: String,
}
