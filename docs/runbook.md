# Operations runbook

## Local runtime

`npm run demo` binds the gateway and fixture to loopback. It creates only `gateway_demo`, provisions `gateway_runtime`, and preserves keys in mode-0600 files. The local insecure CockroachDB listener is not a production deployment. Do not publish its ports. Re-running the demo does not reset taint, revoke state, audit history, or pins.

To test the full external identity path, install Keycloak 26.4.2 under `.local/keycloak` and use Java 21:

```sh
curl -fL https://github.com/keycloak/keycloak/releases/download/26.4.2/keycloak-26.4.2.tar.gz -o .local/keycloak.tgz
mkdir -p .local/keycloak
tar -xzf .local/keycloak.tgz -C .local/keycloak --strip-components=1
KEYCLOAK_JAVA_HOME=/path/to/java21 npm run demo:oidc
```

The isolated identity demo binds Keycloak to 18090 and a second gateway to 3100, uses `gateway_oidc_demo`, and writes the generated test login to `.local/oidc-test.env`. It requires the local database to be running. Sign in as `operator` using that file's password. For automated verification:

```sh
set -a
source .local/oidc-test.env
set +a
npm run test:oidc
```

Never publish browser traces from identity tests: traces can contain tokens, cookies, and test passwords. All traces stay ignored under `.local/`.

## Identity and trusted provisioning

Use an HTTPS issuer/JWKS endpoint in production. Configure a pre-registered public console client for authorization code flow with PKCE S256 and an exact redirect URI. Ensure access tokens contain a signed `sub` and realm-role mapping. The template uses explicit protocol mappers rather than relying on built-in scopes surviving a realm import. Configure the resource audience mapper and optional `mcp:tools` scope. The committed realm is a development template, not a production realm. Pre-registration avoids a dependency on experimental CIMD/DCR support.

For headless agents, create a confidential client with client credentials at the AS. Explicitly bind its signed service-account subject and client ID to a gateway owner. Do not derive ownership from the client ID alone. The client-credentials token exchange is performed by the agent, not by the gateway.

The console has no general signup or credential-upload endpoint. A trusted operator uses `npm run provision -- /secure/provision.json` with `GITHUB_TOKEN` and `MIGRATION_DATABASE_URL` supplied from a secret manager. The JSON contains `ownerSubject`, `agentSubject`, `clientId`, `agentName`, `connectorName`, `agentPolicy`, and `ownerPolicy`. Run migrations before provisioning. The existing normal configuration must also be present. The CLI never prints the token or auto-approves real tools. Use a fine-grained PAT restricted to the intended repositories and minimal permissions; then review tool definitions in the console.

Changing a binding, credential, or source-classification policy is a trusted administrative operation. A new grant must not be used to clear taint while reusing the old agent's memory. Automated credential refresh and hot encryption-key rotation are not implemented. Keep old keys available during an explicit offline re-encryption migration; replacing the master key alone makes retained envelopes unreadable.

## Database roles and migrations

Use separate migration/owner and runtime credentials. `scripts/runtime-role.ts` is a local provisioning example. In production, grant schema usage and CONNECT to the deployment database, then:

```sql
GRANT SELECT ON users, connectors, delegation_connectors TO gateway_runtime;
GRANT SELECT, INSERT, UPDATE ON delegations, tool_pins, operations, audit_heads TO gateway_runtime;
GRANT SELECT, INSERT ON audit_events, policy_versions TO gateway_runtime;
```

Do not grant UPDATE/DELETE on audit or policy history. Runtime must not own these tables or inherit an owner role. Its startup probes reject mutable history. Apply versioned schema changes in a maintenance window with owner credentials; never run migrations with the application role. Back up before upgrades and validate on a restored copy. The current initial schema installer is idempotent and intended for a fresh database, not an online migration orchestration system.

## Unknown outcomes and crashes

Recovery runs on startup and every ten seconds. It marks dispatches past their database-time deadline as unknown and releases their active reservation. Late completions are fenced. Private taint remains. No worker replays an expired network operation.

For an unknown write, inspect the operation's target and the upstream system manually. Determine whether the effect exists before taking a new action. Do not invent a new UUID and blindly retry. There is no generic reconciliation API because the supported upstream has no universal operation-identity lookup. Keep the unknown record as evidence even when a human determines the external outcome.

If audit storage fails before admission, no call dispatches. If storage fails after dispatch, the caller may receive uncertainty even when the upstream succeeded. Restore database availability, let recovery run, and inspect the external effect. Never infer failure from an HTTP timeout.

## Audit verification and retention

Run `DATABASE_URL=... npm run audit:verify -- <delegation-uuid>`. Export the returned head to a separately controlled append-only destination if your threat model includes DBA compromise. The built-in verifier has no external trust anchor.

Arguments are not retained in audit. Successful results are encrypted in operation records and may contain sensitive data; encryption is not a retention policy. Establish an explicit retention period before deployment. Expired result envelopes may be cleared by a trusted maintenance process while retaining operation identity and outcome tombstones. A cleared success must never be redispatched. Audit pruning requires exported checkpoints and a verifier that understands the retained starting point; arbitrary deletion breaks this release's verification contract.

## Deployment prerequisites

Terminate TLS at a controlled ingress, restrict network paths and upstream egress, apply ingress rate limits/body limits, mount a read-only filesystem with a writable temporary directory if required, inject independent keys from a secret manager, use verified database TLS and restricted roles, and configure authenticated metrics scraping. Review access to backups and traces. Production mode is a guardrail, not proof that these controls exist.

Exercise restore procedures, key rotation, revocation, dependency outages, capacity limits, and incident response in the target environment before routing organizational workloads. Docker build, cloud deployment, HA operation, and production capacity require their own recorded verification. The included container and CI configuration are deployment artifacts, not evidence those checks ran remotely.
