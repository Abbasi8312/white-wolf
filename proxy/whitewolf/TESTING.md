# Testing Whitewolf: Server and Client

Run one xray instance as **server** and one as **client** on the same machine or two machines.

## 1. Generate keys

**Symmetric key (32 bytes, for proxy layer)** — same on server and client:

```bash
# Base64RawURL (recommended)
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='

# Or Base64 (also accepted)
openssl rand -base64 32
```

**Reality/Whitewolf transport keys** (TLS layer):

```bash
# Run xray once to get X25519 keys
./xray x25519
```

You get:
- `PrivateKey` — use in **server** `whitewolfSettings.privateKey`
- `Password` — use in **client** `whitewolfSettings.publicKey`

**ShortId** (8 bytes, hex):

```bash
openssl rand -hex 8
```

Use the same shortId on server (`shortIds`) and client (`shortId`).

## 2. Server config

Save as `server_whitewolf.json`. Replace placeholders:

- `SYMMETRIC_KEY_BASE64` — from step 1 (32-byte key, base64).
- `PRIVATE_KEY` — from `xray x25519` (PrivateKey).
- `SHORT_ID_HEX` — 16 hex chars, e.g. `a1b2c3d4e5f67890` (without spaces).

```json
{
  "log": { "loglevel": "debug" },
  "inbounds": [{
    "tag": "whitewolf-in",
    "listen": "0.0.0.0",
    "port": 443,
    "protocol": "whitewolf",
    "settings": {
      "symmetricKey": "SYMMETRIC_KEY_BASE64",
      "fallbackDest": "tcp:google.com:443"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "whitewolf",
      "whitewolfSettings": {
        "dest": "google.com:443",
        "serverNames": ["google.com"],
        "privateKey": "PRIVATE_KEY",
        "shortIds": ["SHORT_ID_HEX"]
      }
    },
    "sniffing": { "enabled": true }
  }],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" }
  ],
  "routing": {
    "rules": [{ "type": "field", "outboundTag": "direct", "domain": ["geosite:category-ads-all"] }]
  }
}
```

Run server:

```bash
./xray run -c server_whitewolf.json
```

## 3. Client config

Save as `client_whitewolf.json`. Replace:

- `SYMMETRIC_KEY_BASE64` — **same** as on server.
- `SERVER_IP` — server IP (e.g. `127.0.0.1` or your VPS IP).
- `PUBLIC_KEY` — from `xray x25519` (Password), **server’s** public key.
- `SHORT_ID_HEX` — **same** as on server.

```json
{
  "log": { "loglevel": "debug" },
  "inbounds": [{
    "tag": "in",
    "listen": "127.0.0.1",
    "port": 1080,
    "protocol": "socks",
    "settings": { "udp": true }
  }],
  "outbounds": [{
    "tag": "whitewolf-out",
    "protocol": "whitewolf",
    "settings": {
      "address": "SERVER_IP",
      "port": 443,
      "symmetricKey": "SYMMETRIC_KEY_BASE64"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "whitewolf",
      "whitewolfSettings": {
        "serverName": "google.com",
        "fingerprint": "firefox",
        "publicKey": "PUBLIC_KEY",
        "shortId": "SHORT_ID_HEX"
      }
    }
  }],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [{ "type": "field", "outboundTag": "whitewolf-out", "network": "tcp,udp" }]
  }
}
```

Run client:

```bash
./xray run -c client_whitewolf.json
```

## 4. Test

- Set browser or `curl` to use SOCKS5 `127.0.0.1:1080`.
- Traffic will go: app → client (SOCKS) → client (whitewolf+TLS) → server (whitewolf) → server (dispatcher) → target.

Quick check:

```bash
curl -x socks5h://127.0.0.1:1080 https://example.com
```

## 5. Same machine (localhost)

Use `SERVER_IP`: `127.0.0.1` in client config and run server and client in two terminals:

- Terminal 1: `./xray run -c server_whitewolf.json`
- Terminal 2: `./xray run -c client_whitewolf.json`
- Then: `curl -x socks5h://127.0.0.1:1080 https://example.com`

## Notes

- **whitewolfSettings** use the same shape as **realitySettings** (dest, serverNames, privateKey, publicKey, shortIds/shortId, fingerprint, etc.).
- Server **must** set `fallbackDest` (e.g. `tcp:google.com:443`) for passthrough when the first block is not valid whitewolf.
- Client uses `fingerprint`: `"firefox"` by default so the TLS ClientHello looks like Firefox.
