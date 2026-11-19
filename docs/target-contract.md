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

Allow-list these values if your secret scanners flag the repository.
