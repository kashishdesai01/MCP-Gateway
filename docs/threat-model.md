# Threat model

The attacker controls an agent's tool arguments and can fully influence its prompts. The identity provider, gateway process, database role provisioning, encryption keys, and reviewed tool registry are trusted. The agent has no authorized direct access to the gateway's upstream credential.

| Threat                                          | Enforcement                                                              | Limit                                                                                  |
| ----------------------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------- |
| Cross-user access with a shared OAuth app       | Signed issuer/subject/client binding and ownership joins                 | Trusted operator must provision the correct binding                                    |
| Token misuse                                    | JWT/JWKS checks, audience, expiry, scope, maximum age                    | Stolen valid tokens remain usable until revocation or expiry                           |
| Grant revocation                                | Recheck within admission transaction                                     | Already admitted effects can finish                                                    |
| Prompt injection                                | Capability policy and mandatory source/sink rule                         | No injection detector; allowed reads can still reveal data to the authenticated client |
| Token refresh or fabricated run ID clears taint | Persistent delegation state; no run header used                          | Memory shared with another grant or an external channel is outside the boundary        |
| Concurrent source/sink calls                    | Locked admission, private taint before dispatch, one active call         | Reduced throughput per delegation                                                      |
| Unknown or stale tools                          | Supported registry, exact definition pins, bounded refresh               | Unchanged definitions can conceal malicious behavior                                   |
| Tool name shadowing                             | Operator-controlled installation namespace                               | Operators must review approved installations                                           |
| Read arguments used as an egress channel        | Narrow schemas and repository-constrained policy                         | An allowed repository is itself an allowed destination; no universal semantic DLP      |
| Repeated write after response loss              | Durable operation identity; unknown outcomes never replay automatically  | A caller choosing a new UUID creates a new operation                                   |
| Audit storage unavailable before dispatch       | Transaction cannot commit, so no dispatch                                | Availability loss                                                                      |
| Audit storage unavailable after dispatch        | Withhold result, retain uncertainty, recover without replay              | Cannot undo a remote effect                                                            |
| Audit edits or truncation                       | Append-only runtime grants and head-checked hash chain                   | DBA rewrite of both history and head requires external checkpoints to detect           |
| Credential theft from a database snapshot       | Envelope encryption and record-bound AAD                                 | Running process/master-key compromise is outside this defense                          |
| Secret patterns in results                      | Bounded output and selected token/private-key redaction                  | Semantic leaks and all secret formats are not detected                                 |
| SSRF / token forwarding                         | Exact GitHub endpoint; fixture loopback only in demo; redirects rejected | Trusted DNS/TLS and upstream service remain dependencies                               |

General SQL execution is deliberately absent. No claim depends on a parser denylist being a complete SQL sandbox. Demo content is synthetic, including the salary value and private canary.
