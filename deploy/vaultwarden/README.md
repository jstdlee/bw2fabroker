# Self-hosted Bitwarden

The broker does not embed a vault. It points the `bw` CLI at a server you choose. Three kinds work:

- Bitwarden cloud: `https://vault.bitwarden.com` or `https://vault.bitwarden.eu`
- Vaultwarden, including the stack in this directory
- Bitwarden's own self-hosted server (the official Linux installer). Use the URL you configured there, usually `https://vault.example.com`

The agents account has to exist on that server, in one organization collection that holds only agent-safe items. Log in once with that account's API key: `bw login --apikey`. The master password is used later, by `broker unlock`, and is not the approval password.

## This Vaultwarden stack

```sh
cd deploy/vaultwarden
docker compose up -d
```

It listens on `127.0.0.1:8080` only. Create the agents account in the web vault, turn signups off, then in the broker admin panel set the server to `http://127.0.0.1:8080` and save. The panel runs `bw config server`. The broker runs it again at startup from `vault.server` or `BW_SERVER`.

Plain HTTP is refused except for localhost, a loopback address, a private address, or a tailnet address. A public name needs HTTPS. If the certificate is private, set `NODE_EXTRA_CA_CERTS` for the broker user; the broker passes that variable through to `bw`.

Official Bitwarden self-host is a separate install. Do not point this compose file at it. Set the broker's server URL to the host you already deployed.
