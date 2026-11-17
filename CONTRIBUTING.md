# Contributing to Beacon Push

Thank you for your interest in contributing. Beacon is a focused project and we
want contributions to be high quality and sustainable. Please read this guide
before opening a PR.

---

## Workflow

Branches, the pull request flow, commit message format and the release process are the same
for every Beacon repo and live in
[beacon-docs/CONTRIBUTING.md](https://github.com/MeshCore-Beacon/beacon-docs/blob/main/CONTRIBUTING.md).
In short: open or comment on an issue first, branch from `dev`, keep each PR to one change,
write conventional commit messages, and open the PR against `dev`.

---

## What the relay does

beacon-push accepts notifications from registered beacon-server instances and
forwards them to the Beacon app through Firebase Cloud Messaging. It handles
server registration, device handles, rate limits and abuse reports. Rule
matching and notification content belong in
[beacon-server](https://github.com/MeshCore-Beacon/beacon-server), not here.

Keep in mind when contributing:

- **Every server is untrusted.** Anyone can register one. Authenticate every
  request, enforce limits before doing work, and never let one server reach
  devices registered with another.
- **The relay must not read content.** Payloads are encrypted between
  beacon-server and the app. Do not add logging, parsing or storage of
  payload bodies.
- **Credentials are secrets.** The Firebase key, SMTP password and instance
  secrets come from the environment, never from source, logs or responses.
  Instance secrets are stored hashed.
- **Keep usage records minimal.** Log what abuse tracking needs (server, time,
  handle, size) and nothing more, with a fixed retention period.

---

## Code style

- Follow the existing patterns before introducing new ones
- Keep functions small and single-purpose
- Comments state the non-obvious *why* in one terse line; a wrong comment is
  worse than none

---

## Tests

- **Practice TDD for bugfixes and features**: write the failing test first,
  watch it fail, then implement.
- Run the test suite before opening a PR. All tests must pass.
- If you are fixing a bug, add a test that would have caught it.

---

## Releases

The flow is in
[Releases and versioning](https://github.com/MeshCore-Beacon/beacon-docs/blob/main/docs/releases.md#cutting-a-release).

---

## Recognition

If you'd like to be listed as a contributor, add yourself to
[CONTRIBUTORS.md](CONTRIBUTORS.md) in your PR.
