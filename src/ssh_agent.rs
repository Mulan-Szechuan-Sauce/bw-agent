use ssh_agent_lib::agent::Agent;
use ssh_agent_lib::proto::message::Message;
use ssh_agent_lib::proto::{Identity, Signature, Blob};

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
            Message::RequestIdentities => {
                Ok(Message::IdentitiesAnswer(
                    bw_ssh_keys
                        .iter()
                        .map(|key| Identity {
                            pubkey_blob: key.pubkey.to_bytes().unwrap(),
                            comment: key.name.clone(),
                        })
                        .collect(),
                ))
            },
            Message::SignRequest(request) => {
                let key = bw_ssh_keys.iter().find(|key| {
                    key.pubkey.to_bytes().unwrap() == request.pubkey_blob
                });

                if let Some(k) = key {
                    let (hash_alg, algorithm) =  if request.flags & 4 != 0 {
                        (ssh_key::HashAlg::Sha512, "rsa-sha2-512")
                    } else if request.flags & 2 != 0 {
                        (ssh_key::HashAlg::Sha256, "rsa-sha2-256")
                    } else {
                        return Ok(Message::Failure)
                    };

                    let signed = k.key.sign("namespace.fixme", hash_alg, &request.data).expect("Thingy");
                    let signature = Signature {
                        algorithm: algorithm.to_owned(),
                        blob: signed.signature_bytes().to_owned(),
                    };

                    Ok(Message::SignResponse(signature.to_blob().expect("Blobify failed")))
                } else {
                    Ok(Message::Failure)
                }

            },
            Message::Extension(request) if request.extension_type == "session-bind@openssh.com" => {
                /* This seems to be optional to implement */
                Ok(Message::ExtensionFailure)
            },
            msg => {
                dbg!(msg);
                Ok(Message::Failure)
            },
        }
    }
}
