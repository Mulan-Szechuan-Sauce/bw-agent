use std::str::FromStr;

use log::LevelFilter;
use serde::{Deserialize, Serialize};

use crate::crypto::{EncryptedThruple, MasterKey};

// TODO: Maybe don't copy pasta the skip serialization somehow
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub url: String,
    pub email: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_client_secret: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_untrusted_cert: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<LevelFilter>,
}

impl Config {
    pub fn read_config(file: &str) -> Self {
        let config_str = std::fs::read_to_string(file).expect("Unable to read config file");
        serde_yaml::from_str::<Config>(&config_str).expect("Invalid yaml")
    }

    pub fn decrypt_config(file: &str, master_password: &str) -> Self {
        let mut config = Self::read_config(file);

        let master_key = MasterKey::new(config.email.as_bytes(), master_password.as_bytes(), 100_000);
        let (enc_key, mac_key) = master_key.expand();

        let make_thruple = |s: String| {
            let e = EncryptedThruple::from_str(&s).ok()?;
            e.mac_verify(&mac_key);
            Some(e)
        };

        let client_id = config.oauth_client_id.and_then(make_thruple);
        let client_secret = config.oauth_client_secret.and_then(make_thruple);

        let decrypt_to_str = |e: EncryptedThruple| std::str::from_utf8(&e.decrypt(&enc_key)).unwrap().to_owned();

        let id = client_id.map(decrypt_to_str);
        let secret = client_secret.map(decrypt_to_str);

        config.oauth_client_id = id;
        config.oauth_client_secret = secret;

        config
    }
}
