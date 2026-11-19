// Package e2e validates the test pack itself: every protocol test must pass
// against the known-good reference gateway and fail against the known-bad
// naive proxy (except control tests). A test that cannot tell them apart is
// not measuring anything.
package e2e

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/canary"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw/config"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/runner"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/spec"
)

const secret = "asck-e2e-secret-asck-e2e-secret-0001"

// controlTests are expected to pass on any working target.
var controlTests = map[string]bool{"ASCK-AUTHZ-003": true, "ASCK-AUTHZ-005": true, "ASCK-SCHEMA-005": true}

func setup(t *testing.T) (*canary.Server, string, []spec.Test) {
	t.Helper()
	c := canary.New()
	up, err := c.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	tests, err := spec.LoadTests("../tests")
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) == 0 {
		t.Fatal("no tests loaded")
	}
	return c, up, tests
}

func target(name, endpoint, audience string) *spec.Target {
	return &spec.Target{
		Name:     name,
		Endpoint: endpoint,
		JWT:      &spec.JWTConfig{Secret: secret, Issuer: "https://idp.asck.invalid", Audience: audience},
		Principals: map[string]spec.Principal{
			"reader": {Claims: map[string]any{"sub": "asck-reader", "roles": []string{"reader"}}},
			"admin":  {Claims: map[string]any{"sub": "asck-admin", "roles": []string{"admin"}}},
		},
	}
}

func TestReferenceGatewayPassesEverything(t *testing.T) {
	c, up, tests := setup(t)
	t.Setenv("ASCK_JWT_SECRET", secret)
	t.Setenv("MCP_UPSTREAM_AUTH", "Bearer upstream-only-token")
	cfg, err := config.Load("../targets/reference-gateway/config.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(nil)
	addr := srv.Listener.Addr().String()
	cfg.UpstreamURL, _ = url.Parse(up)
	cfg.Hardening.AllowedHosts = []string{addr}
	h, err := refgw.Handler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = h
	srv.Start()
	defer srv.Close()

	results := runner.New(target("reference-gateway", srv.URL+"/mcp", "reference-gateway"), c).RunAll(tests)
	for _, r := range results {
		if r.Status != runner.Pass {
			t.Errorf("%s %s: %s %s %+v", r.ID, r.Title, r.Status, r.Reason, r.Steps)
		}
	}
}

func TestNaiveProxyFailsEverythingButControls(t *testing.T) {
	c, up, tests := setup(t)
	srv := httptest.NewServer(refgw.NaiveHandler(up))
	defer srv.Close()

	results := runner.New(target("naive-proxy", srv.URL+"/mcp", "naive-proxy"), c).RunAll(tests)
	for _, r := range results {
		want := runner.Fail
		if controlTests[r.ID] {
			want = runner.Pass
		}
		if r.Status != want {
			t.Errorf("%s %s: got %s, want %s (%s) %+v", r.ID, r.Title, r.Status, want, r.Reason, r.Steps)
		}
	}
}
