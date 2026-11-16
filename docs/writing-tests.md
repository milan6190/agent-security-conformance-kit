# Writing tests

Each test is one YAML file under `tests/`. A test must:

1. **Cite AISVS.** List at least one AISVS 1.01 requirement ID in `aisvs`. The loader rejects unknown or removed IDs.
2. **Judge observable effects.** Assert on what the canary received or what the client got back. Never assert on model wording.
3. **Tell the reference targets apart.** The test must pass on `reference-gateway` and fail on `naive-proxy`. If the naive proxy should pass it, add it to `controlTests` in `e2e/e2e_test.go`. `make test` enforces this.

## Format

```yaml
id: ASCK-AUTHZ-002                  # unique; prefix by area
title: Call to a tool outside the caller's grant is blocked before the tool
aisvs: ["10.2.5", "9.5.1"]          # AISVS 1.01 requirement IDs
risks: [ASI02, MCP02]               # Agentic Top 10 / MCP Top 10 IDs
level: 2                            # highest AISVS level among the cited requirements
requires: [principal:reader]        # jwt | principal:<name> | capability:<name>
rationale: Why this matters, in one or two sentences.
canary:
  results:                          # optional: override what a tool returns
    search_docs: "text with ${canary.aws_key}"
steps:
  - name: reader calls delete_repo
    as: reader                      # anonymous | garbage | <principal> | <principal>:<variant>
    headers: {Origin: "http://evil.asck.invalid"}   # optional
    pad_bytes: 0                    # optional: inflate the request body
    canary_mutate:                  # optional: change a tool definition first
      search_docs: {description: "new text"}
    rpc: {method: tools/call, params: {name: delete_repo, arguments: {repo: prod}}}
    expect:
      blocked: true                 # HTTP >= 400 or a JSON-RPC error
      canary_not_called: [delete_repo]
```

Token variants (require `jwt` in the target profile): `expired`, `wrong_audience`, `wrong_issuer`, `bad_signature`, `alg_none`.

## Assertions

| Key | Passes when |
| --- | --- |
| `blocked: true` | HTTP status ≥ 400 or the response holds a JSON-RPC error |
| `allowed: true` | HTTP 2xx and no JSON-RPC error |
| `canary_called: [tool]` | the tool was invoked during this step |
| `canary_not_called: [tool]` | the tool was not invoked during this step |
| `canary_received_not_contains: [s]` | no request body or header the canary got during this step contains `s` |
| `canary_auth_not_client_token: true` | the client's bearer token appears in no header the canary received |
| `response_contains` / `response_not_contains` | raw response body check |
| `tools_list_includes` / `tools_list_excludes` | names in a `tools/list` result |
| `blocked_or_excludes: [tool]` | the step was blocked, or the tool is absent from the list |

## Pair every deny test with a control

A target that blocks everything passes every deny test. Where a deny test could pass that way, add or reuse a control test proving that allowed traffic still works (see `ASCK-AUTHZ-003`).
