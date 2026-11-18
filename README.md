# BEACON Push

Push notification relay for self-hosted Beacon servers. Apple and Google only
let an app's publisher send it push notifications, so a self-hosted
[beacon-server](https://github.com/MeshCore-Beacon/beacon-server) cannot reach
the Beacon mobile app directly. beacon-push is the small service the Beacon
project runs at `https://push.meshcorebeacon.ca` that does it for them. Every
server, the project's own included, sends its push alerts through it.

## How it fits

```
beacon-server ──HTTPS──> beacon-push ──FCM──> phone (iOS and Android)
```

1. A server operator registers at `https://push.meshcorebeacon.ca/register`
   and gets a **Push ID** and a **Push secret**.
2. The operator turns push on in beacon-server's config
   (`alerts.push.enabled`, `alerts.push.id`, and `BEACON_PUSH_SECRET`).
3. The Beacon app gets a device handle from the relay that only works for that
   server, and gives the handle to the server.
4. When an alert fires, beacon-server encrypts it for that device and sends
   it to the relay, which forwards it through Firebase Cloud Messaging.

## What the relay sees

The relay attributes every notification to the server that sent it, puts the
server's registered name on it, rate-limits each server and device, and keeps
usage records (server, time, device handle, size, a hash of the ciphertext)
for 30 days to catch abuse. Notification contents are end-to-end encrypted
between beacon-server and the app; the relay cannot read them.

## Registering a server

- A verified email address is always required. Each email can register up to
  two servers. Disposable email domains are refused.
- A public URL is optional. If given, the relay checks it daily (see
  [Domain check](#domain-check)); a server that passes gets the higher tier.

| Tier | Requires | Per minute | Per day |
|---|---|---|---|
| email | verified email | 30 | 500 |
| verified | email and a passing domain check | 300 | 10,000 |
| custom | set by an admin | as set | as set |

Every device also has its own limits: 10 notifications a minute and 200 a day.

## API

All bodies are JSON. Errors look like `{"error": {"code": "...", "message": "..."}}`.
A `429` carries `Retry-After` in seconds.

### For beacon-server

Authenticate with `Authorization: Bearer <push id>.<push secret>`.

**`POST /v1/hello`**, at startup and then hourly:

```json
{ "pushId": "inst_7f3k2m9qxa", "name": "Ottawa Mesh", "status": "active", "tier": "email",
  "limits": { "perMinute": 30, "perDay": 500, "perDevicePerDay": 200 },
  "url": "https://beacon.example.org", "domainVerified": false, "termsOutdated": false, "devices": 12 }
```

`status` is `active` or `suspended`. A banned server gets `403 banned`.

**`POST /v1/send`**, with 1 to 100 messages:

```json
{ "messages": [ { "handle": "h_…", "ciphertext": "<base64>", "collapseKey": "4711", "ttlSeconds": 86400 } ] }
```

- `ciphertext` is standard base64, at most 2,048 bytes once decoded.
- `collapseKey` is optional, up to 40 of `A-Z a-z 0-9 _ - . :`. The relay
  prefixes it with the Push ID, so a server only ever collapses its own
  notifications.
- `ttlSeconds` defaults to one day and can be at most 28 days.

The answer has one result per message, in order:
`{"results": [{"messageId": "m_…", "status": "ok"}]}`.

| status | Meaning | What the server does |
|---|---|---|
| `ok` | Handed to FCM | Mark delivered |
| `rate_limited` | Over a limit | Retry after `Retry-After` |
| `invalid_handle` | Unknown, revoked, another server's, or gone at FCM | Delete the device |
| `too_large`, `invalid` | Bad item | Drop it |
| `failed` | FCM refused for another reason | Retry later |

A suspended server gets `403 suspended` for the whole batch.

**`POST /v1/verify-domain`** runs the domain check now:
`{"domainVerified": true}` or `{"domainVerified": false, "reason": "..."}`.

### For the app

**`POST /v1/handles`** with `{"pushId", "platform": "ios"|"android", "fcmToken"}`
returns `{"handle", "handleSecret"}`. The same token on the same server keeps
its handle and gets a new secret.

**`PUT /v1/handles/{handle}`** with `{"handleSecret", "fcmToken"}` moves the
handle to a refreshed token. It answers `204`.

**`DELETE /v1/handles/{handle}`** with `{"handleSecret"}` stops the handle. It
answers `204`. An unknown handle or a wrong secret gets `404 unknown_handle`.

### What reaches the phone

FCM data, the same on both platforms:

```json
{ "v": "1", "pushId": "inst_…", "serverName": "Ottawa Mesh", "messageId": "m_…", "ct": "<base64 ciphertext>" }
```

Android gets a data-only, high-priority message. iOS gets a placeholder alert
(title: the server name, body: "New alert") with `mutable-content: 1`, so the
Notification Service Extension decrypts the message and replaces the text.

### Domain check

The relay requests
`GET <registered url>/.well-known/beacon-push?challenge=<random>` over
https, from a public address only, with no redirects, and gives up after a few
seconds. beacon-server answers:

```json
{ "pushId": "inst_…", "mac": "<hex HMAC-SHA256(key = SHA-256(push secret), \"beacon-push-challenge:\" + pushId + \":\" + challenge)>" }
```

A match proves that the host at that URL holds the Push secret.

## Running the relay

The project runs the official instance, and the Beacon app only accepts
notifications from it. Forks that ship their own app and Firebase project can
run their own; there's no support for that beyond this README.

The image is `ghcr.io/meshcore-beacon/beacon-push`. Configuration comes from
the environment: see [`.env.example`](.env.example). It needs:

- a Firebase service-account key file, mounted read-only;
- an SMTP account for registration mail;
- a volume at `/data` for the SQLite database. Back it up daily with
  `beacon-push admin backup /data/backup-$(date +%F).db` (from cron through `docker exec`) and copy the file off
  the box.

Put it behind a TLS proxy such as Caddy, with `PUSH_TRUST_PROXY=true`.

### Admin commands

```
docker exec beacon-push beacon-push admin list
docker exec beacon-push beacon-push admin show <push id>
docker exec beacon-push beacon-push admin suspend <push id>
docker exec beacon-push beacon-push admin unsuspend <push id>
docker exec beacon-push beacon-push admin ban <push id>
docker exec beacon-push beacon-push admin set-quota <push id> <per minute> <per day>
docker exec beacon-push beacon-push admin backup /data/backup.db
```

A server that addresses too many device handles that aren't its own (more
than 20% of at least 100 in an hour) is suspended automatically, and the admin
address gets a mail. So does every new registration, a lost domain
verification, and an email-tier server reaching 1,000 devices.

### Local development

```
PUSH_DEV_MODE=true PUSH_PUBLIC_URL=http://localhost:8080 PUSH_DATABASE_PATH=./dev.db go run ./cmd/beacon-push
```

Dev mode logs mail (including registration links) and pushes instead of
sending them.

Checks before pushing: `go build ./... && go vet ./... && go test ./...` and
`gofmt -l .`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributors are welcome; please
also read the [Code of Conduct](CODE_OF_CONDUCT.md). To report a security issue,
see [SECURITY.md](SECURITY.md).
