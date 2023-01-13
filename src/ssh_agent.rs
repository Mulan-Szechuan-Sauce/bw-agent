use std::error::Error;

use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use ssh_agent_lib::agent::Agent;
use ssh_agent_lib::proto::message::Message;
use ssh_agent_lib::proto::{Identity, Signature};
use ssh_key::{PrivateKey, SigningKey};

use crate::fetch_ssh_keys;
use crate::types::{BwLoginResponse, Config};

pub struct BwSshAgent {
    pub config: Config,
    pub master_password: String,
    pub login: BwLoginResponse,
}

impl Agent for BwSshAgent {
    type Error = ();

    fn handle(&self, message: Message) -> Result<Message, ()> {
        let bw_ssh_keys = fetch_ssh_keys(&self.config, &self.master_password, &self.login);

        match message {
            Message::RequestIdentities => Ok(Message::IdentitiesAnswer(
                bw_ssh_keys
                    .iter()
                    .map(|key| Identity {
                        pubkey_blob: key.key.public_key().to_bytes().unwrap(),
                        comment: key.name.clone(),
                    })
                    .collect(),
            )),
            Message::SignRequest(request) => {
                let key = bw_ssh_keys
                    .iter()
                    .find(|key| key.key.public_key().to_bytes().unwrap() == request.pubkey_blob);

                if let Some(k) = key {
                    let (digest, algorithm) = if request.flags & 4 != 0 {
                        (MessageDigest::sha512(), "rsa-sha2-512")
                    } else if request.flags & 2 != 0 {
                        (MessageDigest::sha256(), "rsa-sha2-256")
                    } else {
                        (MessageDigest::sha1(), "ssh-rsa")
                    };

                    // TODO: Write this nicer. Get rid of the un-needed clone
                    let decrypted_key = if k.key.is_encrypted() {
                        k.key
                            .decrypt(
                                k.passphrase
                                    .as_ref()
                                    .expect("Key is encrypted yet no passphrase was provided"),
                            )
                            .expect("Unabled to decrypt key with passphrase")
                    } else {
                        k.key.to_owned()
                    };

                    let keypair = PKey::from_rsa(
                        rsa_openssl_from_ssh(&decrypted_key).expect("Failed to convert key"),
                    )
                    .expect("Failed to construct PKey");
                    let mut signer =
                        Signer::new(digest, &keypair).expect("Failed to create signed");
                    signer
                        .update(&request.data)
                        .expect("Failed to update signer");

                    let signature = Signature {
                        algorithm: algorithm.to_owned(),
                        blob: signer
                            .sign_to_vec()
                            .expect("Failed to convert signed to vec"),
                    };

                    Ok(Message::SignResponse(
                        ssh_agent_lib::proto::to_bytes(&signature)
                            .expect("Failed to convert signature to bytes"),
                    ))
                } else {
                    Ok(Message::Failure)
                }
            }
            Message::Extension(request) if request.extension_type == "session-bind@openssh.com" => {
                /* This seems to be optional to implement */
                Ok(Message::ExtensionFailure)
            }
            msg => {
                dbg!(msg);
                Ok(Message::Failure)
            }
        }
    }
}

fn rsa_openssl_from_ssh(private_key: &PrivateKey) -> Result<Rsa<Private>, Box<dyn Error>> {
    let data = private_key.key_data().rsa().expect("Only support rsa keys");
    let n = BigNum::from_slice(data.public.n.as_bytes())?;
    let e = BigNum::from_slice(data.public.e.as_bytes())?;
    let d = BigNum::from_slice(data.private.d.as_bytes())?;
    let qi = BigNum::from_slice(data.private.iqmp.as_bytes())?;
    let p = BigNum::from_slice(data.private.p.as_bytes())?;
    let q = BigNum::from_slice(data.private.q.as_bytes())?;
    let dp = &d % &(&p - &BigNum::from_u32(1)?);
    let dq = &d % &(&q - &BigNum::from_u32(1)?);

    Ok(Rsa::from_private_components(n, e, d, p, q, dp, dq, qi)?)
}
