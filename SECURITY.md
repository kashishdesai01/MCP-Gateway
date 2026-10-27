# Security

This gateway is a bounded reference implementation. Read the [threat model](docs/threat-model.md) before handling sensitive data. Do not publish credentials, customer content, browser traces, or live attack payloads in an issue. Use synthetic reproductions and describe the violated boundary and affected version.

The demo's local issuer, synthetic credentials, insecure single-node database, and development Keycloak instance must remain loopback-only. Production mode intentionally rejects demo identity. An audit hash chain is not a substitute for separately controlled backups or checkpoints.
