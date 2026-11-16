# Contributing

Thanks for helping. This is an OWASP project: vendor-neutral and community-driven, and anyone may contribute.

## Ways to help

- **Add a test.** Pick an AISVS C9/C10 requirement that shows as "not covered" in the coverage map and follow [docs/writing-tests.md](docs/writing-tests.md).
- **Add an adapter or target profile** for an open-source gateway or MCP server.
- **Report a false pass or false fail.** Open an issue with the target, the test ID and the report.

## Ground rules

1. **Every test cites an AISVS requirement ID** and judges observable behaviour, never model wording.
2. **`make test` must pass.** Every test passes on the reference gateway and fails on the naive proxy (control tests excepted).
3. **Vendor neutrality.** No product endorsements in tests or docs. Any public comparison runs the same tests and settings for every product, and is published along with its target profiles so others can reproduce it.
4. **No real secrets.** Use the `${canary.*}` placeholders.
5. **Licensing.** Contributions are under Apache-2.0. Don't paste AISVS requirement text (CC BY-SA 4.0) into code; link to it.

## Development

```bash
make lint test      # gofmt, go vet, unit and end-to-end tests
make demo           # run the CLI against both reference targets
```
