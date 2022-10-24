use clap_serde_derive::{
    clap::{self, ArgAction},
    ClapSerde,
};

#[derive(ClapSerde, Debug)]
pub struct Config {
    #[clap(long, action = ArgAction::SetTrue)]
    pub ignore_untrusted_cert: bool,
    #[clap(long)]
    pub url: String,
    #[clap(long)]
    pub oauth_client_id: String,
    #[clap(long)]
    pub oauth_client_secret: String,
    #[clap(long)]
    pub email: String,
}