# OWASP Agentic Security Conformance Kit (asck)

**Executable tests that check whether an AI agent gateway or MCP deployment meets the agentic (C9) and MCP (C10) requirements of [OWASP AISVS](https://github.com/OWASP/AISVS) 1.01.**

> Status: v0.1 in development, OWASP Incubator application submitted. Tests map to AISVS 1.01 and will track 1.02.

AISVS says what must be true. The OWASP Top 10 for Agentic Applications and the MCP Top 10 say what can go wrong. This kit checks whether a real deployment holds up. You point it at an endpoint, and it sends attacks and control requests. It reports pass or fail for each AISVS requirement, as JSON, SARIF and Markdown.

## How it works

```
 test packs ──► runner ──► system under test ──► canary MCP server
  (YAML)           │       (gateway / server)         │ logs every request
                   │                                  │
                   └────────── oracle ◄───────────────┘
                                 │
                       report.json · report.sarif · report.md
```

The kit judges what the tools actually received, never what a model said. You configure the system under test to use the kit's **canary MCP server** as its upstream. The canary records every request. Tests then assert on that record: was `delete_repo` reached, did the client's token arrive upstream, did a seeded AWS key leave. Protocol tests involve no model, so every run gives the same verdict.

## Quick start

Requires Go 1.24+.

```bash
make build                  # bin/asck, bin/reference-gateway, bin/naive-proxy
make demo                   # runs the kit against both reference targets
```

Against your own target:

1. Configure your gateway's upstream as `http://127.0.0.1:9901/mcp` and apply the [target contract](docs/target-contract.md): four canary tools, plus two roles (`reader`, `admin`).
2. Write a target profile (copy [`targets/reference-gateway/target.yaml`](targets/reference-gateway/target.yaml)). It tells the kit how to authenticate as each role.
3. Run:

```bash
bin/asck run -target my-target.yaml -tests tests -out asck-report
```

The command exits 1 if any test fails, so it can gate CI.

## v0.1 test pack

| Area | Checks | AISVS 1.01 |
| --- | --- | --- |
| Token validation | missing, malformed, expired, wrong audience, wrong issuer, forged (bad signature, `alg: none`) | 10.2.1, 10.2.2, 10.2.7 |
| Tool authorization | `tools/list` filtered per caller; unauthorized `tools/call` blocked before the tool; argument values outside the caller's grant (including path traversal) blocked; control tests that allowed calls still work | 10.2.4, 10.2.5, 9.5.1, 9.5.3 |
| Token passthrough | the client's token never reaches the upstream server | 10.2.7 |
| Transport | hostile `Origin` and `Host` rejected (DNS rebinding) | 10.3.3 |
| Limits | oversized payload rejected | 10.4.5 |
| Schema validation | unrecognized, mistyped, missing and oversized arguments rejected; results checked against `outputSchema` (with control) | 10.4.1, 10.4.3, 10.4.4, 9.3.2 |
| Schema safety | remote `$ref` never fetched and treated as invalid; pathologically deep schemas bounded | 10.4.13, 10.4.14, 10.4.15 |
| Request state | forged, tampered and transplanted `requestState` rejected; replay refused (with control) | 10.2.8, 10.2.10 |
| Mirrored headers | `Mcp-Method`, `Mcp-Name` and `Mcp-Param-*` must match the body under 2026-07-28 (with control); not trusted under older versions; tools with invalid `x-mcp-header` annotations dropped individually | 10.3.6, 10.4.11, 10.4.12 |
| Secrets | credentials in tool results and tool arguments do not cross the boundary | 9.5.4 |
| Injection | hidden instructions in tool results and tool descriptions screened | 10.4.2 |
| Rug pull | a tool whose definition changes after approval cannot be called | 10.4.8 |

Run `bin/asck list` for the full list. These tests cover 24 of the 76 active C9/C10 requirements. The report's coverage map shows every requirement as pass, fail, skipped or not covered.

**What "pass" means.** A requirement passes when every test mapped to it passes. The tests check specific, observable behaviour. A pass is evidence, not certification, and a requirement can have aspects no test covers yet.

## Reference targets

The kit tests itself on every commit (`make test`):

- **`reference-gateway`** (known-good) must pass every test. It's a small MCP security gateway built to validate the tests, not a production product.
- **`naive-proxy`** (known-bad) is a pass-through proxy with no controls. It must fail every test except the control tests.

If a new test can't tell these two apart, it isn't measuring anything.

## CI

```yaml
- uses: OWASP/www-project-agentic-security-conformance-kit@v0
  with:
    target: ci/asck-target.yaml
```

The action uploads `report.sarif` to code scanning. See [`action.yml`](action.yml).

## Project

- [Writing tests](docs/writing-tests.md) · [Target contract](docs/target-contract.md) · [Contributing](CONTRIBUTING.md)
- Roadmap: v0.1 protocol tests (Mar 2027) → v0.5 agent-in-the-loop mode, budget, kill-switch and delegation packs (Jun 2027) → v1.0 with tests for at least 80% of C9/C10 (Dec 2027)
- License: Apache-2.0 for code. AISVS requirement IDs and section titles come from [OWASP AISVS](https://github.com/OWASP/AISVS) (CC BY-SA 4.0). Requirement text is not copied; each report links to it.
