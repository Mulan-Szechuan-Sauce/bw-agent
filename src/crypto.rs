use std::str::FromStr;

use hmac::{Hmac, Mac};
use openssl::{hash::MessageDigest, symm::Cipher};
use sha2::Sha256;

pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn new(email: &[u8], password: &[u8], kdf_iterations: usize) -> Self {
        let mut res = [0; 32];
        openssl::pkcs5::pbkdf2_hmac(
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
        let hkdf = hkdf::Hkdf::<Sha256>::from_prk(&self.0).unwrap();
        let mut enc = [0; 32];
        hkdf.expand(b"enc", &mut enc).unwrap();
        let mut mac = [0; 32];
        hkdf.expand(b"mac", &mut mac).unwrap();
        (enc, mac)
    }

    pub fn pbkdf2_hmac_sha256<const S: usize>(&self, target: &[u8]) -> Result<[u8; S], openssl::error::ErrorStack> {
        let mut hashed = [0u8; S];
        openssl::pkcs5::pbkdf2_hmac(
            &self.0,
            target,
            1,
            MessageDigest::sha256(),
            &mut hashed,
        )?;

        Ok(hashed)
    }
}

pub struct EncryptedThruple {
    iv: Vec<u8>,
    ct: Vec<u8>,
    mac: Vec<u8>,
}

impl EncryptedThruple {
    pub fn mac_verify(&self, mac_key: &[u8]) {
        let mut mac_to_verify =
            Hmac::<Sha256>::new_from_slice(mac_key).expect("HMAC can take key of any size");
        mac_to_verify.update(&self.iv);
        mac_to_verify.update(&self.ct);
        mac_to_verify.verify_slice(&self.mac).unwrap();
    }

    pub fn decrypt(&self, enc_key: &[u8]) -> Vec<u8> {
        openssl::symm::decrypt(Cipher::aes_256_cbc(), enc_key, Some(&self.iv), &self.ct)
            .expect("Decryption failed")
    }
}

impl FromStr for EncryptedThruple {
    type Err = base64::DecodeError;

    fn from_str(value: &str) -> Result<Self, base64::DecodeError> {
        let blah = value[2..].split('|').collect::<Vec<&str>>();
        Ok(Self {
            iv: base64::decode(blah[0])?,
            ct: base64::decode(blah[1])?,
            mac: base64::decode(blah[2])?,
        })
    }

}
