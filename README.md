# Bitwarden Agent

A replacement for `ssh-agent` that pulls ssh keys from Bitwarden secure notes.

**This project is not associated with the [Bitwarden](https://bitwarden.com/) project, Bitwarden, Inc., or [Vaultwarden](https://github.com/dani-garcia/vaultwarden)**
#### ⚠️**IMPORTANT**⚠️: When using this client, please report any bugs or suggestions to us directly, regardless of whatever server you are using (Bitwarden, Bitwarden Self-Hosted, Vaultwarden, etc.). DO NOT use the official support channels.

![](https://i.imgur.com/BgNGN0Q.gif)

## Getting Started

1. Copy `config-sample.yaml` to `~/.bw-agent.yaml` or a temporary location if you'll be using oauth.
2. Edit your config files and update the fields to match your setup. If you don't mind inputting your 2FA on start you can leave 
off the oauth client id and secret.
  - If you specified oauth credentials run `bw-agent --config <path to config> encrypt > ~/.bw-agent.yaml` to encrypt the sensitive fields
3. Launch `bw-agent` (you may specify `--config <path>` if you've placed it in another location)
4. Authenticate using your bitwarden master password
5. Copy and paste the `SSH_AUTH_SOCK` command outputted and execute it.
  - You may also place this in your shell for convenience in the future.

## TODOs
- [X] Implement basic Bitwarden Client to pull Secure Notes
- [X] Implement ssh-agent client support to import SSH keys
- [ ] Implement 2FA support for Bitwarden Client
  - [X] TOTP Authenticator
  - [X] Email
  - [X] Yubico Authenticator
  - [ ] FIDO
- [X] Implement encryption on sensitive config fields
- [X] Implement ssh-agent server
