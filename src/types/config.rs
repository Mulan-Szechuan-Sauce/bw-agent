use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub url: String,
    pub oauth_client_id: String,
    pub oauth_client_secret: String,
    pub email: String,
}

pub struct AdditionalFlags {
    pub ignore_untrusted_cert: bool,
}