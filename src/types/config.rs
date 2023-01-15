use std::str::FromStr;

use log::LevelFilter;
use serde::{Deserialize, Serialize};

use crate::{crypto::{encrypt_text, EncryptedThruple, MasterKey}, BuisnessLogicError};

// TODO: Maybe don't copy pasta the skip serialization somehow
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub url: String,
    pub email: String,

    // Private encrypted fields
    #[serde(skip_serializing_if = "Option::is_none")]
    oauth_client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oauth_client_secret: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_untrusted_cert: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<LevelFilter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<String>,
}

impl Config {
    pub fn read_config(file: &str) -> Self {
        let config_str = std::fs::read_to_string(file).expect("Unable to read config file");
        serde_yaml::from_str::<Config>(&config_str).expect("Invalid yaml")
    }

    fn decrypt(&self, master_password: &str, text: &str) -> Result<String, BuisnessLogicError> {
        let master_key = MasterKey::new(self.email.as_bytes(), master_password.as_bytes(), 100_000);
        let (enc_key, mac_key) = master_key.expand();

        let e = EncryptedThruple::from_str(text)
            .map_err(|e| BuisnessLogicError::ThrupleFromStr("config file decryption field".to_owned(), e))?;
        e.mac_verify(&mac_key);

        Ok(std::str::from_utf8(&e.decrypt(&enc_key)).expect("Invalid UTF8 in config file").to_owned())
    }

    pub fn encrypt_fields(self, master_password: &str) -> Self {
        let oauth_client_id = self
            .oauth_client_id
            .as_ref()
            .map(|text| encrypt_text(&self.email, master_password, text).expect("Pee"));

        let oauth_client_secret = self
            .oauth_client_secret
            .as_ref()
            .map(|text| encrypt_text(&self.email, master_password, text).expect("Pee"));

        Config {
            oauth_client_id,
            oauth_client_secret,
            ..self
        }
    }

    pub fn oauth_client_id(&self, master_password: &str) -> Option<String> {
        self.oauth_client_id
            .as_ref()
            .and_then(|id| self.decrypt(master_password, id).ok())
    }

    pub fn oauth_client_secret(&self, master_password: &str) -> Option<String> {
        self.oauth_client_secret
            .as_ref()
            .and_then(|secret| self.decrypt(master_password, secret).ok())
    }
}
