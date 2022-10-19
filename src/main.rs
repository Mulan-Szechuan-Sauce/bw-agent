use std::{collections::HashMap, os::unix::net::UnixStream, io::{Write, Read}, net::Shutdown};

use byteorder::{BigEndian, ByteOrder};
use bytes::{BytesMut, BufMut};
use clap::Parser;
use hmac::{Hmac, Mac};
use openssl::{symm::Cipher, hash::MessageDigest};
use sha2::Sha256;
use ssh_key::{PrivateKey, MPInt};

mod types;
use types::*;

struct MasterKey([u8; 32]);

impl MasterKey {
    fn new(email: &[u8], password: &[u8], kdf_iterations: usize) -> Self {
        let mut res = [0; 32];
        openssl::pkcs5::pbkdf2_hmac(
            password.as_ref(),
            email.as_ref(),
            kdf_iterations,
            MessageDigest::sha256(),
            &mut res
            ).expect("Key derivation failed");
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

struct CipherString {
    iv: Vec<u8>,
    ct: Vec<u8>,
    mac: Vec<u8>,
}

impl CipherString {
    fn from_str(thing: &str) -> Self {
        let blah = thing[2..].split("|").collect::<Vec<&str>>();
        Self {
            iv: base64::decode(blah[0]).expect("iv failed to base64 decode"),
            ct: base64::decode(blah[1]).expect("ct failed to base64 decode"),
            mac: base64::decode(blah[2]).expect("ct failed to base64 decode"),
        }
    }

    fn mac_verify(&self, mac_key: &[u8]) {
        let mut mac_to_verify = Hmac::<Sha256>::new_from_slice(mac_key).expect("HMAC can take key of any size");
        mac_to_verify.update(&self.iv);
        mac_to_verify.update(&self.ct);
        mac_to_verify.verify_slice(&self.mac).unwrap();
    }

    fn decrypt(&self, enc_key: &[u8]) -> Vec<u8> {
        openssl::symm::decrypt(
            Cipher::aes_256_cbc(),
            &enc_key,
            Some(&self.iv),
            &self.ct,
        ).expect("Decryption failed")
    }
}

struct BwSshKeyEntry {
    key: Vec<u8>,
    passphrase: Option<Vec<u8>>,
    name: String,
}

fn fetch_ssh_keys(config: &Config) -> Vec<BwSshKeyEntry> {
    let client = reqwest::blocking::Client::new();

    let params = HashMap::from([
        ("grant_type", "client_credentials"),
        ("scope", "api"),
        ("client_id", &config.oauth_client_id),
        ("client_secret", &config.oauth_client_secret),
        ("device_identifier", "literal_trash"),
        ("device_name", "literal_trash"),
    ]);

    let response = client.post(format!("{}/identity/connect/token", config.url))
        .form(&params)
        .send()
        .expect("Login request failed");

    let login_response = response.json::<LoginResponse>().expect("Login json failed to deserialize");

    let master_password = rpassword::prompt_password("Master Password: ").unwrap();
    let master_key = MasterKey::new(
        config.email.as_bytes(),
        master_password.as_bytes(),
        login_response.kdf_iterations as usize,
    );

    let (enc_key, mac_key) = master_key.expand();

    let key_parts = CipherString::from_str(&login_response.key);

    key_parts.mac_verify(&mac_key);

    let key = key_parts.decrypt(&enc_key);

    let data_key = &key[..32];
    let data_mac = &key[32..];

    let response = client.get(format!("{}/api/sync", config.url))
        .bearer_auth(login_response.access_token)
        .send()
        .expect("Sync request failed");

    let sync_response = response.json::<SyncResponse>().expect("Sync json failed to deserialize");

    let folder_id = sync_response.folders.into_iter().find_map(|folder| {
        let enc_name = CipherString::from_str(&folder.name);
        enc_name.mac_verify(data_mac);

        if enc_name.decrypt(data_key) == b"ssh-keys" {
            Some(folder.id)
        } else {
            None
        }
    }).expect("ssh-keys folder does not exist");

    sync_response.ciphers.into_iter().filter_map(|cipher| {
        let cipher = match (&cipher.t, &cipher.folder_id) {
            (CipherType::Note, Some(fid)) if *fid == folder_id => Some(cipher),
            _ => None,
        }?;

        let note = CipherString::from_str(&cipher.notes.unwrap());
        note.mac_verify(&data_mac);

        let unencrypted_ssh_key = note.decrypt(data_key);

        let fields = cipher.data.fields.unwrap_or(vec![]);

        let passphrase_field = fields.iter().find_map(|field| {
            let enc_name = CipherString::from_str(&field.name);
            enc_name.mac_verify(&data_mac);
            let field_name = enc_name.decrypt(data_key);

            if field_name == b"passphrase" {
                let enc_value = CipherString::from_str(&field.value);
                enc_value.mac_verify(&data_mac);
                Some(enc_value.decrypt(data_key))
            } else {
                None
            }
        });

        let name_cipher = CipherString::from_str(&cipher.name);
        name_cipher.mac_verify(data_mac);
        let name_bytes = name_cipher.decrypt(data_key);
        let name = std::str::from_utf8(&name_bytes).expect("Invalid UTF-8 entry name").to_owned();

        Some(BwSshKeyEntry { 
            key: unencrypted_ssh_key, 
            passphrase: passphrase_field,
            name: name,
        })
    }).collect()
}

fn write_mpint(buffer: &mut BytesMut, value: &MPInt) {
    let bytes = value.as_bytes();
    buffer.put_u32(bytes.len() as u32);
    buffer.put_slice(bytes);
}

fn send_keys_to_agent(keys: Vec<BwSshKeyEntry>) {
    let sock_path = std::env::var_os("SSH_AUTH_SOCK").expect("Socket path is not set");
    let mut stream = UnixStream::connect(sock_path).expect("Could not connect to ssh-agent socket");

    for key in keys {
        let mut message = BytesMut::new();
        message.put_bytes(17u8, 1);

        let msg_type = b"ssh-rsa";
        message.put_u32(usize::try_into(msg_type.len()).unwrap());
        message.put_slice(msg_type);

        let pk = PrivateKey::from_openssh(&key.key).unwrap();
        let pk = if pk.is_encrypted() { 
            // TODO: Prompt for user input of key passphrase
            pk.decrypt(key.passphrase.expect("Git rekt")).expect("Invalid password")
        } else {
            pk
        };

        let rsa_keypair = pk.key_data().rsa().expect("Only supports RSA now");

        write_mpint(&mut message, &rsa_keypair.public.n);
        write_mpint(&mut message, &rsa_keypair.public.e);
        write_mpint(&mut message, &rsa_keypair.private.d);
        write_mpint(&mut message, &rsa_keypair.private.iqmp);
        write_mpint(&mut message, &rsa_keypair.private.p);
        write_mpint(&mut message, &rsa_keypair.private.q);

        let comment = [b"BW: ", key.name.as_bytes()].concat();
        message.put_u32(usize::try_into(comment.len()).unwrap());
        message.put_slice(&comment);

        let frozen = message.freeze();

        let mut final_msg = BytesMut::new();
        final_msg.put_u32(u32::try_from(frozen.len()).unwrap());
        final_msg.put_slice(&frozen);

        stream.write_all(&final_msg.freeze()).unwrap();

        let mut size_bytes = vec![0u8; 4];
        stream.read_exact(&mut size_bytes).unwrap();

        let _size = BigEndian::read_u32(&size_bytes);
    }

    stream.shutdown(Shutdown::Both).expect("shutdown function failed");
}

fn main() {
    let args = Args::parse();

    let config_string = std::fs::read_to_string(args.config).expect("Config file not found");
    let config = serde_yaml::from_str::<Config>(&config_string).expect("Config file failed to deserialize");

    let bw_ssh_keys = fetch_ssh_keys(&config);
    send_keys_to_agent(bw_ssh_keys);

    println!("Successfully added keys.");
}
