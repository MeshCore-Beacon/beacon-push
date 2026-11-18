# Shoulders

Beacon Push stands on the shoulders of giants. Thank you to the following open source
projects that make this possible. Add new dependencies here in the PR that introduces them.

## The network

- [MeshCore](https://github.com/meshcore-dev/MeshCore): the mesh whose events these
  notifications report on

## Libraries

- [Go](https://go.dev/): the language and its standard library, including the SMTP, TLS, HTTP/2 and crypto packages
- [chi](https://github.com/go-chi/chi): HTTP routing
- [modernc.org/sqlite](https://gitlab.com/cznic/sqlite): SQLite without cgo
- [disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains): the CC0
  blocklist of throwaway email domains, vendored in `internal/disposable/list.txt`

## Services

- [Apple Push Notification service](https://developer.apple.com/documentation/usernotifications): delivery to iOS
- [Firebase Cloud Messaging](https://firebase.google.com/docs/cloud-messaging): delivery to Android
