VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -s -w -X github.com/OWASP/www-project-agentic-security-conformance-kit/internal/report.Version=$(VERSION)
DEMO_SECRET ?= asck-demo-secret-asck-demo-secret-0001

.PHONY: build test lint demo clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/ ./cmd/...

test:
	go test -race -count=1 ./...

lint:
	@test -z "$$(gofmt -l .)" || (gofmt -l .; exit 1)
	go vet ./...

# Runs the CLI against the known-good and known-bad reference targets.
demo: build
	@export ASCK_JWT_SECRET=$(DEMO_SECRET) MCP_UPSTREAM_AUTH="Bearer upstream-only-token"; \
	bin/reference-gateway -config targets/reference-gateway/config.json >/dev/null 2>&1 & GW=$$!; \
	bin/naive-proxy -listen 127.0.0.1:8081 -upstream http://127.0.0.1:9901/mcp >/dev/null 2>&1 & NP=$$!; \
	sleep 1; \
	echo "== reference-gateway (expect all pass)"; bin/asck run -target targets/reference-gateway/target.yaml -tests tests -out reports/reference-gateway; R1=$$?; \
	echo "== naive-proxy (expect failures)"; bin/asck run -target targets/naive-proxy/target.yaml -tests tests -out reports/naive-proxy; \
	kill $$GW $$NP; exit $$R1

clean:
	rm -rf bin reports
