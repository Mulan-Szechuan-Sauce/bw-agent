#[repr(u8)]
pub enum SshMessageType {
    Failure = 5,
    Success = 6,
    AddIdentity = 17,
}

pub const SSH_RSA_KEY_TYPE: &[u8] = b"ssh-rsa";
