use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub ignore_untrusted_cert: bool,
    pub url: String,
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret: Option<String>,
    pub email: String,
}
