# Architecture and consistency contracts

## Identity and ownership

The resource server verifies JWT signature, issuer, audience membership, expiry, issue time, token age, and scope. Only RS256/ES256 are accepted. `azp` is the application identity for Keycloak; `client_id` is accepted for issuers using that claim. Conflicting identities deny. The signed tuple `(issuer, subject, clientId)` selects a provisioned delegation. No request header chooses an owner, delegation, credential, or taint lifetime.

Interactive users bind their user subject and application to a delegation. Headless clients bind their signed service-account subject and application to an operator-selected owner. OAuth client credentials do not themselves establish human ownership. Resource tokens are never forwarded to the upstream.

Connector queries join through the delegation and require the connector owner to equal the delegation owner. Admin routes independently resolve the authenticated user's owner record and require the signed `gateway-admin` role. Delegation revocation governs future admissions; it cannot cancel already admitted network effects. Admin-role changes take effect when tokens are replaced or expire.

## Call lifecycle

1. Strictly validate the supported tool's arguments. Remove the gateway operation identity before forwarding.
2. Refresh the upstream tool definition over a bounded connection. Reject arbitrary endpoints and redirects.
3. In one serializable database transaction, lock the delegation, recheck enablement/ownership, inspect the pin, intersect both Cedar policies, and apply the mandatory flow rule.
4. Check operation identity against delegation, connector, tool, and keyed argument commitment. An existing success can replay its encrypted result; other existing outcomes never dispatch again.
5. Reserve private/untrusted labels with monotonic OR updates, reserve the delegation's active operation, insert dispatch intent, and append audit. Commit before contacting the upstream.
6. Call the upstream outside the SQL retry closure. Only the explicit supported tool call is proxied. Sampling, elicitation, resource fetching, and upstream tool descriptions do not become client instructions through this adapter.
7. Bound and filter the response. Persist its authenticated encrypted envelope and completion audit in one transaction, checking the active operation and database-time deadline. Only then release the result.

The active-operation row serializes calls across processes. Source labels are reserved before dispatch rather than discovered after response delivery, so even a failed read can conservatively taint a delegation. This reduces availability and freedom of use but prevents late source results from escaping an untainted context. No taint reset is exposed.

An external call and a SQL transaction cannot commit atomically. A lost response, failed output filter, or failed completion write can leave an unknown outcome. The gateway withholds results and never automatically repeats that identity. Recovery marks expired dispatches unknown and fences late completions. It does not promise that a timed-out remote process stopped.

## Policy and catalog

Cedar receives schema-validated principals, tools, and facts. Both evaluations must allow and contain no diagnostic errors. Policy updates use optimistic version checks and retain the complete previous version. Owner policy is managed entitlement data rather than an assertion that the gateway has synchronized an external IAM system.

Tool effects and source classification are gateway-owned. All real GitHub reads conservatively taint private exposure. The fixture has a controlled public issue source. All supported writes are external sinks, regardless of upstream annotation hints. After private exposure, writes deny even if a policy permits them and no injection has been observed.

Tools are namespaced by operator-provisioned connector name. The catalog lists approved, reachable, hash-matching tools for the delegation's connectors, with private zero-TTL cache hints. It does not attempt to prove satisfiability of every Cedar condition during listing. Per-call authorization remains authoritative. The whole upstream definition is hashed, including optional output schemas and metadata. A refresh cannot prove that a remote server keeps its behavior constant between discovery and invocation.

## Audit and secrets

Each delegation has an atomically updated audit head. An event commits with its head, sequence, canonical hash, prior hash, database timestamp, trace identity, policy version, and safe decision metadata. Arguments are represented by an HMAC, not a plain low-entropy hash. Credentials and retained successful results use envelope encryption: independent AES-256-GCM data keys and nonces, with record identity bound as AAD. The master key is supplied externally; no KMS integration or hot key rotation is claimed.

Audit and policy history grant only SELECT/INSERT to the runtime. Operational tables allow the minimum additional mutations needed by the service. A DBA or migration owner is a separate trust boundary. The internal chain detects edits and truncation against its retained head, but is not an independently anchored transparency log.

## Operational shape

The service uses bounded request/response bodies, connection and statement timeouts, a fixed upstream allowlist, same-origin browser writes, a restrictive CSP, safe error codes, Prometheus counters/histograms, structured logs, and W3C trace-context propagation. Metrics cover the complete tool-call path. A full OTel collector/export pipeline, distributed rate limiting, production SLOs, and multi-region capacity are not implemented.
