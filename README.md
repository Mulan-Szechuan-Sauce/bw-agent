# Bitwarden Agent

Pulls ssh keys from Bitwarden secure notes and loads them into `ssh-agent`.

**This project is not associated with the [Bitwarden](https://bitwarden.com/) project, Bitwarden, Inc., or [Vaultwarden](https://github.com/dani-garcia/vaultwarden)**
#### ⚠️**IMPORTANT**⚠️: When using this client, please report any bugs or suggestions to us directly, regardless of whatever server you are using (Bitwarden, Bitwarden Self-Hosted, Vaultwarden, etc.). DO NOT use the official support channels.

![](https://i.imgur.com/jbtksv0.gif)

# TODOs
- [X] Implement basic Bitwarden Client to pull Secure Notes
- [X] Implement ssh-agent client support to import SSH keys
- [ ] Implement 2FA support for Bitwarden Client
  - [X] TOTP Authenticator
  - [X] Email
  - [X] Yubico Authenticator
  - [ ] FIDO
- [ ] Implement encryption on sensitive config fields
- [ ] Implement ssh-agent server
