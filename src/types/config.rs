use log::LevelFilter;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub ignore_untrusted_cert: bool,
    pub url: String,
    pub email: String,
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret: Option<String>,
    pub log_level: Option<LevelFilter>,
}
