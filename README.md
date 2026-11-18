# BEACON Push

Push notification relay for self-hosted Beacon servers. Apple and Google only
let an app's publisher send it push notifications, so a self-hosted
[beacon-server](https://github.com/MeshCore-Beacon/beacon-server) cannot reach
the Beacon mobile app directly. beacon-push is the small service the Beacon
project runs at `https://push.meshcorebeacon.ca` that does it for them. Every
server, the project's own included, sends its push alerts through it.

## How it fits

```
beacon-server ──HTTPS──> beacon-push ──APNs──> iPhone
                                     └──FCM───> Android phone
```

1. A server operator registers at `https://push.meshcorebeacon.ca/register`
   and gets a **Push ID** and a **Push secret**.
2. The operator turns push on in beacon-server's config
   (`alerts.push.enabled`, `alerts.push.id`, and `BEACON_PUSH_SECRET`).
3. The Beacon app gets a device handle from the relay that only works for that
   server, and gives the handle to the server.
4. When an alert fires, beacon-server encrypts it for that device and sends
   it to the relay, which forwards it straight to Apple's push service (APNs)
   for an iPhone, or through Firebase Cloud Messaging (FCM) for Android.

## What the relay sees

The relay attributes every notification to the server that sent it, puts the
server's registered name on it, rate-limits each server and device, and keeps
usage records (server, time, device handle, size, a hash of the ciphertext)
for 30 days to catch abuse. Notification contents are end-to-end encrypted
between beacon-server and the app; the relay cannot read them.

Apple sees the notifications that go to iPhones and Google sees the ones that
go to Android phones, each with its device token and the encrypted payload.
Neither sees the other platform's traffic.

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

All bodies are JSON, at most 512 KiB (a bigger one gets `413 too_large`).
Errors look like `{"error": {"code": "...", "message": "..."}}`. A `429`
carries `Retry-After` in seconds.

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
{ "messages": [ { "handle": "h_…", "ciphertext": "<base64>", "collapseKey": "4711", "ttlSeconds": 86400,
                  "id": "1234:9b2c…" } ] }
```

- `ciphertext` is standard base64, at most 2,048 bytes once decoded.
- `collapseKey` is optional, up to 40 of `A-Z a-z 0-9 _ - . :`. The relay
  prefixes it with the Push ID, so a server only ever collapses its own
  notifications.
- `ttlSeconds` defaults to one day and can be at most 28 days (2,419,200).
- `id` is optional, up to 64 of `A-Z a-z 0-9 _ - . :`, and makes a retry safe.
  It is scoped to the sending server, and the relay remembers each id's
  outcome for at least 24 hours (30 days in practice). Repeating an id that
  was sent answers `ok` with the earlier `messageId` and sends and counts
  nothing, even if the handle has gone or the relay is paused since. Repeating an id whose send is still under way, or whose outcome
  is unknown because the relay stopped mid-send, answers `rate_limited` with
  `retryAfterSeconds: 30`; after 2 minutes such a send counts as failed, its
  quota is given back (with or without an id) and the next repeat sends again. Repeating an id whose send failed sends again.
  beacon-server uses `<outbox row id>:<device session uuid>`.

The relay sends up to 8 messages of a batch at once and starts no new one
after 10 seconds; each message's whole send to APNs or FCM, token refresh
included, is limited to 10 seconds, so the answer comes within about 20 seconds. Items not started in time answer `rate_limited` with
`retryAfterSeconds: 5`.

The answer has one result per message, in order:
`{"results": [{"messageId": "m_…", "status": "ok"}, {"status": "rate_limited", "retryAfterSeconds": 42}]}`.
`retryAfterSeconds` (whole seconds, at least 1) comes with every
`rate_limited` result and with a `failed` one caused by an APNs or FCM outage. The
response's `Retry-After` header carries the largest wait in the batch, for
servers that do not read the field.

| status | Meaning | What the server does |
|---|---|---|
| `ok` | Handed to APNs or FCM | Mark delivered |
| `rate_limited` | Not sent: over a limit, the device's push service is paused after an outage, not started before the batch deadline, or an `id` still in flight | Hold until `retryAfterSeconds` (else `Retry-After`); not an attempt |
| `invalid_handle` | Unknown, revoked, another server's, or the push service no longer knows the handle's current token (APNs 410, `BadDeviceToken` or `DeviceTokenNotForTopic`; FCM UNREGISTERED) | Delete the device |
| `too_large`, `invalid` | Refused: a bad item, a payload over APNs' 4 KB, or the push service refused the message (APNs 400, FCM 400 INVALID_ARGUMENT) | Done for this notice, never resend |
| `failed` | Transient: the push service unreachable or another error from it, the relay's own APNs or FCM credentials refused, the token changed while sending, or the relay could not record a send the push service accepted | Retry later; counts an attempt |

APNs and FCM are paused separately: an outage of one never holds back the
other. When APNs answers 5xx or FCM answers 500 or 503, the relay stops
sending through that service for its `Retry-After`, at most a day. Without
one it pauses a minute, doubling with each new outage up to an hour, until a
send through it succeeds after the pause has ended. That item is `failed` and
every later item for the same service is `rate_limited` until the pause ends.
A 429 for a device makes that item `rate_limited`, for the `Retry-After` the
service gave (a minute if it gives none, at most a day), and later items for
the same device wait, without reaching the service, until the longest wait
asked for that device ends. A message counts against the daily quotas while
it is being sent and stays counted only if the push service accepts it.

When APNs refuses the relay's provider token as expired or invalid, the relay
signs a new one and tries once more. If that fails too, the item is `failed`
and the relay logs an error: its APNs key needs attention.

A suspended server gets `403 suspended` for the whole batch, and a banned one
`403 banned`. A batch waiting behind another from the same server checks the
server's status and quotas again before it starts, and each message checks
them again before it goes out.

**`POST /v1/verify-domain`** runs the domain check now:
`{"domainVerified": true}` or `{"domainVerified": false, "reason": "..."}`.

### For the app

**`POST /v1/handles`** with
`{"pushId", "platform": "ios"|"android", "token", "apnsEnvironment"}`
answers `200` with `{"handle", "handleSecret"}`.

- On iOS, `token` is the APNs device token in hex (64 to 200 characters,
  either case; stored lower-case), and `apnsEnvironment` is `sandbox` for a
  development build or `production` for TestFlight and App Store builds.
- On Android, `token` is the FCM registration token, up to 4,096 of
  `A-Z a-z 0-9 _ - :`, and `apnsEnvironment` must be left out.

The same token on the same server keeps its handle and gets a new secret.
Errors:

- `400 bad_platform`: `platform` is not `ios` or `android`.
- `400 bad_apns_environment`: iOS without `sandbox` or `production`, or
  Android with an `apnsEnvironment`.
- `400 bad_token`: `token` is missing or malformed for the platform.
- `404 unknown_server`: no server has that Push ID.
- `403 server_unavailable`: the server is suspended or banned.

**`PUT /v1/handles/{handle}`** with `{"handleSecret", "token", "apnsEnvironment"}`
moves the handle to a refreshed token, and on iOS to the given environment,
which is required there as on `POST`. It answers `204`, `400 bad_token` or
`400 bad_apns_environment`.

**`DELETE /v1/handles/{handle}`** with `{"handleSecret"}` stops the handle. It
answers `204`.

On `PUT` and `DELETE`, an unknown or revoked handle or a wrong secret gets
`404 unknown_handle`. Each address may create 20 handles an hour and make 60
updates and deletes an hour; past that it gets `429 rate_limited` with
`Retry-After`.

### What reaches the phone

The same fields on both platforms:

```json
{ "v": "1", "pushId": "inst_…", "serverName": "Ottawa Mesh", "messageId": "m_…", "ct": "<base64 ciphertext>" }
```

Android gets them as the data of a data-only, high-priority FCM message. iOS
gets them as top-level keys of the APNs payload, next to a placeholder alert
(title: the server name, body: "New alert") with `mutable-content: 1`, so the
Notification Service Extension decrypts the message and replaces the text.
The APNs request has `apns-push-type: alert`, `apns-priority: 10`, an
`apns-expiration` from `ttlSeconds`, and the collapse key as
`apns-collapse-id` (hashed when the prefixed key is over 64 bytes).

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
notifications from it. Forks that ship their own app, Apple team and Firebase
project can run their own; there's no support for that beyond this README.

The image is `ghcr.io/meshcore-beacon/beacon-push`. Configuration comes from
the environment: see [`.env.example`](.env.example). It needs:

- a Firebase service-account key file, mounted read-only, for Android;
- an APNs auth key (`.p8`) from the Apple Developer account, mounted
  read-only, with its key ID, the team ID and the app's bundle ID
  (`PUSH_APNS_KEY`, `PUSH_APNS_KEY_ID`, `PUSH_APNS_TEAM_ID`,
  `PUSH_APNS_TOPIC`), for iOS. The key works for both the sandbox and
  production environments; each handle says which one its device uses. A key
  that cannot be read stops the relay at startup;
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

A server that addresses too many live device handles that aren't its own
(50 in an hour, or more than 20% of at least 100 live handles in an hour) is
suspended automatically, and the admin address gets a mail. Handles that
don't exist or are revoked don't count either way. So does every new registration, a lost domain
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
