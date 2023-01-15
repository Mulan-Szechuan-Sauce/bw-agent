use std::{collections::HashMap, str::FromStr};

use clap::Parser;
use openssl::base64;
use ssh_agent_lib::Agent;
use ssh_key::PrivateKey;

mod types;
use thiserror::Error;
use types::*;
use uuid::Uuid;

mod ssh_agent;
use ssh_agent::BwSshAgent;

mod crypto;
use crypto::{EncryptedThruple, MasterKey};

#[derive(Debug)]
struct BwSshKeyEntry {
    key: PrivateKey,
    passphrase: Option<Vec<u8>>,
    name: String,
}

fn oath_login(config: &Config, master_password: &str) -> BwLoginResponse {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(config.ignore_untrusted_cert.unwrap_or(false))
        .build()
        .unwrap();

    let device_uuid = Uuid::new_v4().to_string();
    let client_id = config.oauth_client_id(master_password).unwrap();
    let client_secret = config.oauth_client_secret(master_password).unwrap();
    let params = HashMap::from([
        ("grant_type", "client_credentials"),
        ("scope", "api"),
        ("client_id", &client_id),
        ("client_secret", &client_secret),
        ("device_identifier", &device_uuid),
        ("device_name", &device_uuid),
    ]);

    let response = client
        .post(format!("{}/identity/connect/token", config.url))
        .form(&params)
        .send()
        .expect("Login request failed");

    response
        .json::<BwLoginResponse>()
        .expect("Login json failed to deserialize")
}

// TODO: Rename me something saner
#[derive(Error, Debug)]
pub enum BuisnessLogicError {
    #[error(
        "There was an error parsing {0} as symetrically encrypted aes_256_cbc cyphertext: {1}"
    )]
    ThrupleFromStr(String, #[source] openssl::error::ErrorStack),
}

fn fetch_ssh_keys(
    config: &Config,
    master_password: &str,
    login_response: &BwLoginResponse,
) -> Result<Vec<BwSshKeyEntry>, BuisnessLogicError> {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(config.ignore_untrusted_cert.unwrap_or(false))
        .build()
        .unwrap();

    let master_key = MasterKey::new(
        config.email.as_bytes(),
        master_password.as_bytes(),
        login_response.kdf_iterations as usize,
    );

    let (enc_key, mac_key) = master_key.expand();

    let key_parts = EncryptedThruple::from_str(&login_response.key)
        .map_err(|e| BuisnessLogicError::ThrupleFromStr("login response key".to_owned(), e))?;

    key_parts.mac_verify(&mac_key);

    let key = key_parts.decrypt(&enc_key);

    let data_key = &key[..32];
    let data_mac = &key[32..];

    let response = client
        .get(format!("{}/api/sync", config.url))
        .bearer_auth(login_response.access_token.clone())
        .send()
        .expect("Sync request failed");

    let sync_response = response
        .json::<BwSyncResponse>()
        .expect("Sync json failed to deserialize");

    let folder_id = sync_response
        .folders
        .into_iter()
        .find_map(|folder| {
            let enc_name = EncryptedThruple::from_str(&folder.name).ok()?;
            enc_name.mac_verify(data_mac);

            if enc_name.decrypt(data_key) == b"ssh-keys" {
                Some(folder.id)
            } else {
                None
            }
        })
        .expect("ssh-keys folder does not exist");

    Ok(sync_response
        .ciphers
        .into_iter()
        .filter_map(|cipher| {
            let cipher = match (&cipher.t, &cipher.folder_id) {
                (BwCipherType::Note, Some(fid)) if *fid == folder_id => Some(cipher),
                _ => None,
            }?;

            let note = EncryptedThruple::from_str(&cipher.notes.unwrap()).ok()?;
            note.mac_verify(data_mac);

            let unencrypted_ssh_key = note.decrypt(data_key);

            let fields = cipher.data.fields.unwrap_or(vec![]);

            let passphrase_field = extract_field(data_mac, data_key, &fields, b"passphrase");

            let name_cipher = EncryptedThruple::from_str(&cipher.name).ok()?;
            name_cipher.mac_verify(data_mac);
            let name_bytes = name_cipher.decrypt(data_key);
            let name = std::str::from_utf8(&name_bytes)
                .expect("Invalid UTF-8 entry name")
                .to_owned();

            Some(BwSshKeyEntry {
                key: PrivateKey::from_openssh(unencrypted_ssh_key)
                    .expect("Failed to parse private key"),
                passphrase: passphrase_field,
                name,
            })
        })
        .collect())
}

fn extract_field(
    data_mac: &[u8],
    data_key: &[u8],
    fields: &[BwCipherField],
    field_name: &[u8],
) -> Option<Vec<u8>> {
    fields.iter().find_map(|field| {
        let enc_name = EncryptedThruple::from_str(&field.name).ok()?;
        enc_name.mac_verify(data_mac);
        let name = enc_name.decrypt(data_key);

        if name == field_name {
            let enc_value = EncryptedThruple::from_str(&field.value).ok()?;
            enc_value.mac_verify(data_mac);
            Some(enc_value.decrypt(data_key))
        } else {
            None
        }
    })
}

fn password_login(config: &Config, master_password: &str) -> BwLoginResponse {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(config.ignore_untrusted_cert.unwrap_or(false))
        .build()
        .unwrap();

    let prelogin_params = HashMap::from([("email", &config.email)]);
    let prelogin_response = client
        .post(format!("{}/api/accounts/prelogin", config.url))
        .json(&prelogin_params)
        .send()
        .expect("Pre login request failed");

    let prelogin = prelogin_response
        .json::<BwPreloginResponse>()
        .expect("Preflight json failed to deserialize");

    let master_key = MasterKey::new(
        config.email.as_bytes(),
        master_password.as_bytes(),
        prelogin.kdf_iterations,
    );

    let hashed = master_key
        .pbkdf2_hmac_sha256::<32>(master_password.as_bytes())
        .expect("Failed to hash user master password");

    let encoded = base64::encode_block(&hashed);

    let device_uuid = Uuid::new_v4().to_string();
    let mut params = HashMap::from([
        ("grant_type", "password".to_owned()),
        ("scope", "api offline_access".to_owned()),
        ("client_id", "web".to_owned()),
        ("device_identifier", device_uuid.clone()),
        ("device_name", device_uuid),
        ("device_type", "10".to_owned()),
        ("username", config.email.clone()),
        ("password", encoded),
    ]);

    let mut response = client
        .post(format!("{}/identity/connect/token", config.url))
        .form(&params)
        .send()
        .expect("Login request failed");

    if response.status() == 400 {
        let totp_response = response
            .json::<BwTwoFactorResponse>()
            .expect("2FA json failed to deserialize");

        match *totp_response.two_factor_providers.first().unwrap() {
            // TOTP or Yubikey TOTP
            id @ (0 | 1 | 3) => {
                let prompt = match id {
                    0 => "TOTP",
                    1 => "Emailed Code",
                    3 => "Yubikey OTP",
                    _ => unreachable!(
                        "Rust isn't smart enough to know these are the only valid cases"
                    ),
                };

                let totp = rpassword::prompt_password(format!("{prompt}: ")).unwrap();
                params.insert("twoFactorToken", totp);
                params.insert("twoFactorProvider", id.to_string());
                params.insert("twoFactorRemember", "0".to_owned()); // TODO: Don't be an old man
            }
            // FIDO
            7 => {}
            _ => panic!("Unsupported 2FA type"),
        }
        response = client
            .post(format!("{}/identity/connect/token", config.url))
            .form(&params)
            .send()
            .expect("Login request failed");
    }

    response
        .json::<BwLoginResponse>()
        .expect("Login json failed to deserialize")
}

fn main() {
    let args = Args::parse();
    let config = Config::read_config(
        &args
            .config
            .unwrap_or(format!("{}/.bw-agent.yaml", std::env::var("HOME").unwrap())),
    );

    let master_password = rpassword::prompt_password("Master Password: ").unwrap();

    match args.action {
        Command::Encrypt => {
            let new_config = config.encrypt_fields(&master_password);

            println!("{}", serde_yaml::to_string(&new_config).unwrap());
        }
        Command::Run => {
            if let Some(level) = config.log_level {
                env_logger::Builder::new().filter_level(level).init();
            } else {
                env_logger::init();
            }

            let login = if config.oauth_client_id(&master_password).is_some() {
                oath_login(&config, &master_password)
            } else {
                password_login(&config, &master_password)
            };

            let agent = BwSshAgent {
                config,
                master_password,
                login,
            };

            let mut path = std::env::current_dir().expect("Not in a working directory");
            path.push("connect.sock");
            let _ = std::fs::remove_file(path.clone());

            println!(
                "SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;",
                path.to_str().expect("Path is not valid utf8")
            );

            log::info!("Starting socket");
            agent.run_unix(path).expect("Failed to run socket");
        }
    };
}
