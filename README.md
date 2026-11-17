# BEACON Push

Push notification relay for self-hosted Beacon servers. Apple and Google only
let an app's publisher send it push notifications, so a self-hosted
[beacon-server](https://github.com/MeshCore-Beacon/beacon-server) cannot reach
the Beacon mobile app directly. beacon-push is the small service the Beacon
project runs at `push.meshcorebeacon.ca` that does it for them.

> Early development. Nothing here is ready to deploy yet.

## How it fits

```
beacon-server ──HTTPS──> beacon-push ──FCM──> phone (iOS and Android)
```

1. A server operator registers their server with the relay and gets an
   instance ID and secret.
2. The operator turns push on in their beacon-server config. It is off by
   default.
3. The Beacon app gets a device handle from the relay that only works for the
   server it registered with, and gives that handle to the server.
4. When an event matches a user's alert rules, beacon-server sends an
   encrypted notification to the relay, which forwards it through Firebase
   Cloud Messaging.

## What the relay sees

The relay attributes every notification to the server that sent it,
rate-limits each server and device, and keeps usage records (server, time,
device handle, size) to detect and act on abuse. Notification contents are
end-to-end encrypted between beacon-server and the app; the relay cannot read
them unless a user reports a notification from the app.

## Registering a server

Registration needs a verified email address, and a server with a public URL
can verify its domain for a higher quota. Each email can register up to two
servers. Details will be published here and in
[beacon-docs](https://github.com/MeshCore-Beacon/beacon-docs) once the relay
is live.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributors are welcome; please
also read the [Code of Conduct](CODE_OF_CONDUCT.md). To report a security issue,
see [SECURITY.md](SECURITY.md).
