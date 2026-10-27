# API

All authenticated routes use `Authorization: Bearer <access_token>`. Browser writes accept only the configured resource origin. Bodies are bounded at 64 KiB. No cookie authentication or ambient browser credentials are used.

## MCP

`POST /mcp` serves MCP 2026-07-28 through the official server SDK's modern per-request handler. Clients must send the required version/method/name headers and per-request metadata. Use the official client with `versionNegotiation: { mode: 'auto' }` or pin the modern revision. Earlier protocol revisions are rejected.

Supported tool names are `<connector-name>__list_issues`, `<connector-name>__get_file_contents`, and `<connector-name>__create_issue`. All require `operationId` (UUID), `owner`, and `repo`. File reads also require `path`; issue creation requires `title` and `body`. Unknown arguments deny. The operation ID is not forwarded to the upstream.

Repeating the same completed call replays the retained encrypted result. Conflicting inputs deny. Pending and unknown calls deny without dispatch. There is no generic exactly-once guarantee for a newly chosen operation ID.

`GET /.well-known/oauth-protected-resource/mcp` and the root metadata alias advertise the exact resource URI, issuer, and scope. Missing/invalid tokens return 401 with a metadata challenge; insufficient scope returns 403.

## Admin

All routes additionally require `gateway-admin` and a provisioned user matching the signed issuer and subject. Access is restricted to that user's records.

| Method | Route                                  | Purpose                                                                                 |
| ------ | -------------------------------------- | --------------------------------------------------------------------------------------- |
| GET    | `/admin/v1/state`                      | Own delegations/connectors/pins and latest 100 operations/events                        |
| PATCH  | `/admin/v1/delegations/:id`            | Revoke with `{ "enabled": false }`                                                      |
| PUT    | `/admin/v1/delegations/:id/policy`     | Save `{ version, agentPolicy, ownerPolicy }`; validates both and checks current version |
| POST   | `/admin/v1/simulate`                   | Evaluate `{ delegationId, tool, repo }` against current security state without dispatch |
| GET    | `/admin/v1/connectors/:id/tools/:tool` | Fetch current definition and canonical hash for review                                  |
| PUT    | `/admin/v1/connectors/:id/tools/:tool` | Approve `{ expectedHash }`; refetch and reject a changed hash                           |
| GET    | `/admin/v1/delegations/:id/verify`     | Recompute audit chain against retained head                                             |

## Operations

`GET /health/live` is process liveness; `GET /health/ready` requires database/schema access. Neither proves upstream availability. `GET /metrics` requires an admin token and exposes bounded-cardinality tool outcomes and latency histograms. Do not put subject IDs, tool arguments, or tokens into metric labels.

`/demo/login` and `/demo/jwks` exist only when the application is explicitly constructed with local demo identity. The production entrypoint forbids demo identity. `/auth/config` supplies public issuer/client/resource configuration to the console.
