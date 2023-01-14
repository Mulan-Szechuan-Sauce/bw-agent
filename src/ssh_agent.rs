use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use ssh_agent_lib::agent::Agent;
use ssh_agent_lib::proto::message::Message;
use ssh_agent_lib::proto::{Identity, Signature};
use ssh_key::private::RsaKeypair;
use thiserror::Error;

use crate::types::{BwLoginResponse, Config};
use crate::{fetch_ssh_keys, BuisnessLogicError, BwSshKeyEntry};

pub struct BwSshAgent {
    pub config: Config,
    pub master_password: String,
    pub login: BwLoginResponse,
}

#[derive(Error, Debug)]
pub enum AgentError {
    #[error("Key {0} is encrypted but no passphrase was provided")]
    MissingPassphrase(String),
    #[error("Unable to decrypt key {0} with provided passphrase: {1}")]
    PassphraseDecrypt(String, #[source] ssh_key::Error),
    #[error("Openssl encountered an error: {0}")]
    Openssl(#[source] openssl::error::ErrorStack),
    #[error("Proto encountered an error: {0}")]
    SshAgentProto(#[source] ssh_agent_lib::proto::error::ProtoError),
    #[error("Unspported key type: {0}")]
    UnsupportedKey(String),

    #[error("{0}")]
    OtherError(#[from] BuisnessLogicError),
}

impl BwSshAgent {
    fn handle_with_err(&self, message: Message) -> Result<Message, AgentError> {
        let bw_ssh_keys = fetch_ssh_keys(&self.config, &self.master_password, &self.login)?
            .into_iter()
            .filter_map(|key| match key.key.public_key().to_bytes() {
                Ok(blob) => {
                    let comment = key.name.clone();
                    Some((
                        key,
                        Identity {
                            pubkey_blob: blob,
                            comment,
                        },
                    ))
                }
                Err(e) => {
                    log::warn!("Key '{}' public key could not be loaded", e);
                    None
                }
            })
            .collect::<Vec<(BwSshKeyEntry, Identity)>>();

        match message {
            Message::RequestIdentities => Ok(Message::IdentitiesAnswer(
                bw_ssh_keys
                    .iter()
                    .map(|(_, identity)| identity.to_owned())
                    .collect(),
            )),
            Message::SignRequest(request) => {
                let key_identity = bw_ssh_keys
                    .iter()
                    .find(|(_, identity)| identity.pubkey_blob == request.pubkey_blob);

                if let Some((k, identity)) = key_identity {
                    let (digest, algorithm) = if request.flags & 4 != 0 {
                        (MessageDigest::sha512(), "rsa-sha2-512")
                    } else if request.flags & 2 != 0 {
                        (MessageDigest::sha256(), "rsa-sha2-256")
                    } else {
                        (MessageDigest::sha1(), "ssh-rsa")
                    };

                    // TODO: Write this nicer. Get rid of the un-needed clone
                    let decrypted_key =
                        if k.key.is_encrypted() {
                            k.key
                                .decrypt(k.passphrase.as_ref().ok_or(
                                    AgentError::MissingPassphrase(identity.comment.clone()),
                                )?)
                                .map_err(|e| {
                                    AgentError::PassphraseDecrypt(identity.comment.clone(), e)
                                })?
                        } else {
                            k.key.to_owned()
                        };

                    let keypair = PKey::from_rsa(
                        rsa_openssl_from_ssh(decrypted_key.key_data().rsa().ok_or(
                            AgentError::UnsupportedKey(
                                decrypted_key.algorithm().as_str().to_owned(),
                            ),
                        )?)
                        .map_err(AgentError::Openssl)?,
                    )
                    .map_err(AgentError::Openssl)?;

                    let mut signer = Signer::new(digest, &keypair).map_err(AgentError::Openssl)?;
                    signer.update(&request.data).map_err(AgentError::Openssl)?;

                    let signature = Signature {
                        algorithm: algorithm.to_owned(),
                        blob: signer.sign_to_vec().map_err(AgentError::Openssl)?,
                    };

                    Ok(Message::SignResponse(
                        ssh_agent_lib::proto::to_bytes(&signature)
                            .map_err(AgentError::SshAgentProto)?,
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

impl Agent for BwSshAgent {
    type Error = ();

    fn handle(&self, message: Message) -> Result<Message, ()> {
        match self.handle_with_err(message) {
            Ok(msg) => Ok(msg),
            Err(e) => {
                log::error!("{}", e);
                Err(())
            }
        }
    }
}

fn rsa_openssl_from_ssh(rsa: &RsaKeypair) -> Result<Rsa<Private>, openssl::error::ErrorStack> {
    let n = BigNum::from_slice(rsa.public.n.as_bytes())?;
    let e = BigNum::from_slice(rsa.public.e.as_bytes())?;
    let d = BigNum::from_slice(rsa.private.d.as_bytes())?;
    let qi = BigNum::from_slice(rsa.private.iqmp.as_bytes())?;
    let p = BigNum::from_slice(rsa.private.p.as_bytes())?;
    let q = BigNum::from_slice(rsa.private.q.as_bytes())?;
    let dp = &d % &(&p - &BigNum::from_u32(1)?);
    let dq = &d % &(&q - &BigNum::from_u32(1)?);

    Rsa::from_private_components(n, e, d, p, q, dp, dq, qi)
}
