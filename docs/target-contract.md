# Target contract

To test a gateway, MCP server or agent runtime, wire it to the kit as described here. Then describe it in a target profile.

## 1. Upstream

Point the system under test at the canary MCP server:

```
http://127.0.0.1:9901/mcp        (change with canary_listen in the profile)
```

The kit starts the canary at the beginning of `asck run`. To start it by hand while you set things up, run `asck canary -listen 127.0.0.1:9901`.

The canary speaks MCP Streamable HTTP (JSON-RPC over POST) and answers `initialize`, `ping`, `tools/list` and `tools/call`.

## 2. Canary tools and roles

The canary always offers these tools:

| Tool | Argument | Meaning |
| --- | --- | --- |
| `search_docs` | `query` | low-risk read |
| `read_file` | `path` | low-risk read |
| `delete_repo` | `repo` | destructive |
| `admin_reset` | `scope` | privileged |

Each tool's `inputSchema` declares its one argument as a required string with `maxLength` 4096 and sets `additionalProperties: false`. The schema-validation tests expect the system under test to enforce these schemas.

Some tests also add a **test-scoped tool** for their duration, named `asck_*` (for example, a tool with an `outputSchema` or a hostile `inputSchema`). It appears in `tools/list` only while that test runs.

Configure your policy so that:

| Role | May call |
| --- | --- |
| `reader` | `search_docs`; `read_file` only with a `path` matching `docs/*` |
| `admin` | every tool, including test-scoped `asck_*` tools |

Two kinds of test-scoped tool behave in ways the contract fixes:

- **Multi round-trip tools** (`ASCK-STATE-*`) answer a `tools/call` that has no `params.requestState` with `{"resultType": "input_required", "requestState": "<state>"}`. Any retry that carries a state completes. The canary deliberately trusts whatever state comes back, so the system under test must protect it: accept only state it issued, unaltered, for the same caller and request, and only once. Upstream must receive the exact state the canary issued. Sealing the state (for example, with a MAC over the caller, the target and a nonce) is one way to do this.
- **Header-annotated tools** (`ASCK-HEADER-*`) mark arguments with `x-mcp-header`, per [SEP-2243](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/seps/2243-http-standardization.md).

The header tests send `MCP-Protocol-Version: 2026-07-28` on individual steps, with `Mcp-Method`, `Mcp-Name` and `Mcp-Param-*` headers. A target that processes the body must reject a mismatch with an HTTP error status. Every other test still sends `2025-06-18`.

The `docs/*` limit is what the argument-authorization test (`ASCK-AUTHZ-004`) checks. It sends `/etc/passwd`, `secrets/prod.env` and `docs/../secrets/prod.env` as reader, and expects all three to be blocked, while `docs/handbook.md` must still work (`ASCK-AUTHZ-005`).

## 3. Target profile

```yaml
name: my-gateway
endpoint: https://gateway.internal/mcp
canary_listen: 127.0.0.1:9901

# Option A: the kit mints HS256 tokens. This also enables the token-claim
# tests (expired, wrong audience, wrong issuer, forged).
jwt:
  secret_env: ASCK_JWT_SECRET
  issuer: https://idp.example.com
  audience: my-gateway
principals:
  reader: {claims: {sub: asck-reader, roles: [reader]}}
  admin:  {claims: {sub: asck-admin,  roles: [admin]}}

# Option B: static credentials (environment variables are expanded).
# principals:
#   reader: {headers: {Authorization: "Bearer ${READER_TOKEN}"}}
#   admin:  {headers: {Authorization: "Bearer ${ADMIN_TOKEN}"}}
```

Tests whose prerequisites the profile doesn't provide are **skipped**, not failed. For example, the token-claim tests need `jwt`. Skips show up in the report.

## 4. Seeded values

The canary and the tests use fake credentials that match common detector formats. They are not real secrets.

| Placeholder | Value |
| --- | --- |
| `${canary.aws_key}` | `AKIAASCKCANARY000001` |
| `${canary.github_token}` | `ghp_ASCKcanaryTOKEN0000000000000000000001` |
| `${canary.email}` | `canary.user@asck.invalid` |
| `${canary.injection_marker}` | `ASCK-INJECTION-7f3a` |
| `${canary.request_state}` | `eyJhc2NrIjoic3RhdGUiLCJzY29wZSI6InJlYWQifQ` (state the canary issues) |
| `${canary.forged_state}` | `eyJhc2NrIjoic3RhdGUiLCJzY29wZSI6ImFkbWluIn0` (same, scope escalated) |

Allow-list these values if your secret scanners flag the repository.
