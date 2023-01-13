use std::collections::HashMap;

use clap::Parser;
use clap_serde_derive::ClapSerde;
use hmac::{Hmac, Mac};
use openssl::{hash::MessageDigest, symm::Cipher};
use sha2::Sha256;
use ssh_agent_lib::Agent;
use ssh_key::{PrivateKey, PublicKey};

mod types;
use types::*;
use uuid::Uuid;

mod ssh_agent;
use ssh_agent::BwSshAgent;

struct MasterKey([u8; 32]);

impl MasterKey {
    fn new(email: &[u8], password: &[u8], kdf_iterations: usize) -> Self {
        let mut res = [0; 32];
        openssl::pkcs5::pbkdf2_hmac(
            password.as_ref(),
            email.as_ref(),
            kdf_iterations,
            MessageDigest::sha256(),
            &mut res,
        )
        .expect("Key derivation failed");
        MasterKey(res)
    }

    fn expand(&self) -> ([u8; 32], [u8; 32]) {
        let hkdf = hkdf::Hkdf::<Sha256>::from_prk(&self.0).unwrap();
        let mut enc = [0; 32];
        hkdf.expand(b"enc", &mut enc).unwrap();
        let mut mac = [0; 32];
        hkdf.expand(b"mac", &mut mac).unwrap();
        (enc, mac)
    }
}

struct EncryptedThruple {
    iv: Vec<u8>,
    ct: Vec<u8>,
    mac: Vec<u8>,
}

impl EncryptedThruple {
    fn from_str(thing: &str) -> Self {
        let blah = thing[2..].split("|").collect::<Vec<&str>>();
        Self {
            iv: base64::decode(blah[0]).expect("iv failed to base64 decode"),
            ct: base64::decode(blah[1]).expect("ct failed to base64 decode"),
            mac: base64::decode(blah[2]).expect("ct failed to base64 decode"),
        }
    }

    fn mac_verify(&self, mac_key: &[u8]) {
        let mut mac_to_verify =
            Hmac::<Sha256>::new_from_slice(mac_key).expect("HMAC can take key of any size");
        mac_to_verify.update(&self.iv);
        mac_to_verify.update(&self.ct);
        mac_to_verify.verify_slice(&self.mac).unwrap();
    }

    fn decrypt(&self, enc_key: &[u8]) -> Vec<u8> {
        openssl::symm::decrypt(Cipher::aes_256_cbc(), &enc_key, Some(&self.iv), &self.ct)
            .expect("Decryption failed")
    }
}

#[derive(Debug)]
struct BwSshKeyEntry {
    key: PrivateKey,
    passphrase: Option<Vec<u8>>,
    name: String,
}

fn oath_login(config: &Config) -> BwLoginResponse {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(config.ignore_untrusted_cert)
        .build()
        .unwrap();

    let device_uuid = Uuid::new_v4().to_string();
    let params = HashMap::from([
        ("grant_type", "client_credentials"),
        ("scope", "api"),
        ("client_id", config.oauth_client_id.as_ref().unwrap()),
        (
            "client_secret",
            config.oauth_client_secret.as_ref().unwrap(),
        ),
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

fn fetch_ssh_keys(
    config: &Config,
    master_password: &str,
    login_response: &BwLoginResponse,
) -> Vec<BwSshKeyEntry> {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(config.ignore_untrusted_cert)
        .build()
        .unwrap();

    let master_key = MasterKey::new(
        config.email.as_bytes(),
        master_password.as_bytes(),
        login_response.kdf_iterations as usize,
    );

    let (enc_key, mac_key) = master_key.expand();

    let key_parts = EncryptedThruple::from_str(&login_response.key);

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
            let enc_name = EncryptedThruple::from_str(&folder.name);
            enc_name.mac_verify(data_mac);

            if enc_name.decrypt(data_key) == b"ssh-keys" {
                Some(folder.id)
            } else {
                None
            }
        })
        .expect("ssh-keys folder does not exist");

    sync_response
        .ciphers
        .into_iter()
        .filter_map(|cipher| {
            let cipher = match (&cipher.t, &cipher.folder_id) {
                (BwCipherType::Note, Some(fid)) if *fid == folder_id => Some(cipher),
                _ => None,
            }?;

            let note = EncryptedThruple::from_str(&cipher.notes.unwrap());
            note.mac_verify(&data_mac);

            let unencrypted_ssh_key = note.decrypt(data_key);

            let fields = cipher.data.fields.unwrap_or(vec![]);

            let passphrase_field = extract_field(data_mac, data_key, &fields, b"passphrase");

            let name_cipher = EncryptedThruple::from_str(&cipher.name);
            name_cipher.mac_verify(data_mac);
            let name_bytes = name_cipher.decrypt(data_key);
            let name = std::str::from_utf8(&name_bytes)
                .expect("Invalid UTF-8 entry name")
                .to_owned();

            Some(BwSshKeyEntry {
                key: PrivateKey::from_openssh(unencrypted_ssh_key)
                    .expect("Failed to parse private key"),
                passphrase: passphrase_field,
                name: name,
            })
        })
        .collect()
}

fn extract_field(
    data_mac: &[u8],
    data_key: &[u8],
    fields: &Vec<BwCipherField>,
    field_name: &[u8],
) -> Option<Vec<u8>> {
    fields.iter().find_map(|field| {
        let enc_name = EncryptedThruple::from_str(&field.name);
        enc_name.mac_verify(&data_mac);
        let name = enc_name.decrypt(data_key);

        if name == field_name {
            let enc_value = EncryptedThruple::from_str(&field.value);
            enc_value.mac_verify(&data_mac);
            Some(enc_value.decrypt(data_key))
        } else {
            None
        }
    })
}

fn password_login(config: &Config, master_password: &str) -> BwLoginResponse {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(config.ignore_untrusted_cert)
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

    let mut hashed = [0u8; 32];
    openssl::pkcs5::pbkdf2_hmac(
        &master_key.0,
        master_password.as_bytes(),
        1,
        MessageDigest::sha256(),
        &mut hashed,
    )
    .expect("Failed to hash user master password");

    let encoded = base64::encode(hashed);

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

                let totp = rpassword::prompt_password(format!("{}: ", prompt)).unwrap();
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
    let mut cli_args = Args::parse();

    let config = match std::fs::read_to_string(&cli_args.config) {
        Ok(x) => Config::from(serde_yaml::from_str::<<Config as ClapSerde>::Opt>(&x).unwrap())
            .merge(&mut cli_args.user_config),
        Err(_) => Config::from(&mut cli_args.user_config),
    };

    let master_password = rpassword::prompt_password("Master Password: ").unwrap();
    let login = if config.oauth_client_id.is_some() {
        oath_login(&config)
    } else {
        password_login(&config, &master_password)
    };

    let agent = BwSshAgent {
        config,
        master_password,
        login,
    };
    let socket = "connect.sock";
    let _ = std::fs::remove_file(socket);

    agent.run_unix(socket).expect("Failed to run socket");
}
