# Security Policy

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Instead, contact the maintainers directly via the MeshCore Canada Discord
server: [MeshCore Canada Discord](https://discord.gg/Gz3KvJx2hf); reach out to
**dedskelly** directly. Include as much detail as possible: the nature of the
issue, steps to reproduce, and any potential impact.

We will acknowledge receipt within 48 hours and aim to provide a fix or
mitigation within 14 days depending on severity.

Once a fix is released we will publish a security advisory on the repository.

## Scope

beacon-push is the relay that forwards notifications from self-hosted
beacon-server instances to the Beacon app, through Apple's push service (APNs)
for iOS and Firebase Cloud Messaging for Android.
Relevant findings include ways to send notifications without valid instance
credentials, to reach devices registered with another server, to get around
rate limits or registration limits, to read notification contents, leaks of
the Firebase key, the APNs key, SMTP credentials or instance secrets, weaknesses in email or
domain verification, dependency vulnerabilities, and issues in the container
image or build pipeline. Vulnerabilities in rule matching or payload
encryption on the server side belong in the
[beacon-server](https://github.com/MeshCore-Beacon/beacon-server) repository.
