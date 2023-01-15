use std::str::FromStr;

use openssl::{hash::MessageDigest, symm::{Cipher, self}, pkcs5, base64};
use rand::{rngs::OsRng, RngCore};

pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn new(email: &[u8], password: &[u8], kdf_iterations: usize) -> Self {
        let mut res = [0; 32];
        pkcs5::pbkdf2_hmac(
            password,
            email,
            kdf_iterations,
            MessageDigest::sha256(),
            &mut res,
        )
        .expect("Key derivation failed");
        MasterKey(res)
    }

    pub fn expand(&self) -> ([u8; 32], [u8; 32]) {
        let hkdf = ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, &self.0);

        let enc = hkdf.expand(&[b"enc"], ring::hkdf::HKDF_SHA256).unwrap();
        let mac = hkdf.expand(&[b"mac"], ring::hkdf::HKDF_SHA256).unwrap();

        let mut enc_bytes = [0; 32];
        let mut mac_bytes = [0; 32];
        enc.fill(&mut enc_bytes).unwrap();
        mac.fill(&mut mac_bytes).unwrap();

        (enc_bytes, mac_bytes)
    }

    pub fn pbkdf2_hmac_sha256<const S: usize>(
        &self,
        target: &[u8],
    ) -> Result<[u8; S], openssl::error::ErrorStack> {
        let mut hashed = [0u8; S];
        pkcs5::pbkdf2_hmac(&self.0, target, 1, MessageDigest::sha256(), &mut hashed)?;

        Ok(hashed)
    }
}

pub struct EncryptedThruple {
    init_vec: Vec<u8>,
    cypher_text: Vec<u8>,
    mac: Vec<u8>,
}

impl EncryptedThruple {
    pub fn mac_verify(&self, mac_key: &[u8]) {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, mac_key);
        ring::hmac::verify(
            &key,
            &[&self.init_vec[..], &self.cypher_text].concat(),
            &self.mac,
        )
        .expect("Error verifying mac");
    }

    pub fn decrypt(&self, enc_key: &[u8]) -> Vec<u8> {
        symm::decrypt(
            Cipher::aes_256_cbc(),
            enc_key,
            Some(&self.init_vec),
            &self.cypher_text,
        )
        .expect("Decryption failed")
    }
}

impl FromStr for EncryptedThruple {
    type Err = openssl::error::ErrorStack;

    fn from_str(value: &str) -> Result<Self, openssl::error::ErrorStack> {
        let tmp = value[2..].split('|').collect::<Vec<&str>>();
        Ok(Self {
            init_vec: base64::decode_block(tmp[0])?,
            cypher_text: base64::decode_block(tmp[1])?,
            mac: base64::decode_block(tmp[2])?,
        })
    }
}

pub fn encrypt_text(email: &str, master_password: &str, text: &str) -> Result<String, ()> {
    let master_key = MasterKey::new(email.as_bytes(), master_password.as_bytes(), 100_000);

    let (enc_key, mac_key) = master_key.expand();
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    let encrypted =
        symm::encrypt(Cipher::aes_256_cbc(), &enc_key, Some(&iv), text.as_bytes())
            .expect("Blah blah blah");

    let hmac_tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &mac_key),
        &[&iv[..], &encrypted].concat(),
    );

    Ok(format!(
        "2.{}|{}|{}",
        base64::encode_block(&iv),
        base64::encode_block(&encrypted),
        base64::encode_block(hmac_tag.as_ref()),
    ))
}
