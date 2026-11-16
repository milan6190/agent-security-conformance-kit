package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw/auth"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw/policy"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw/redact"
)

var secret = []byte("0123456789abcdef0123456789abcdef")

// fakeMCP is a minimal upstream MCP server.
func fakeMCP(t *testing.T, sse bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer upstream-token" {
			t.Errorf("upstream got client credentials or none: %q", r.Header.Get("Authorization"))
		}
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		var result any
		switch m["method"] {
		case "tools/list":
			result = map[string]any{"tools": []any{
				map[string]any{"name": "search_docs"},
				map[string]any{"name": "delete_repo"},
				map[string]any{"name": "db.query"},
			}}
		case "tools/call":
			args, _ := json.Marshal(m["params"].(map[string]any)["arguments"])
			result = map[string]any{"content": []any{map[string]any{
				"type": "text",
				"text": "echo " + string(args) + " contact bob@corp.com, SSN 123-45-6789",
			}}}
		}
		resp, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m["id"], "result": result})
		if sse {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "id: 1\nevent: message\ndata: "+string(resp)+"\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	}))
}

func newGW(t *testing.T, upstream string) *Gateway {
	u, _ := url.Parse(upstream)
	red, _ := redact.New([]string{"all"}, nil)
	return New(Options{
		Upstream:           u,
		UpstreamAuthHeader: "Bearer upstream-token",
		Auth:               auth.New(auth.Config{JWTSecret: secret}),
		Policy: &policy.Policy{Rules: []policy.Rule{
			{Role: "analyst", AllowTools: []string{"search_docs", "db.*"}, DenyTools: []string{"db.drop*"}},
		}},
		Redactor:        red,
		RedactRequests:  true,
		RedactResponses: true,
		RatePerMinute:   100,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func token(roles ...string) string {
	return auth.SignHS256(secret, map[string]any{
		"sub": "alice", "roles": roles, "exp": time.Now().Add(time.Hour).Unix(),
	})
}

func call(t *testing.T, gw *Gateway, tok, body string) (int, string) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

func TestUnauthenticated(t *testing.T) {
	up := fakeMCP(t, false)
	defer up.Close()
	code, _ := call(t, newGW(t, up.URL), "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", code)
	}
}

func TestToolsListFiltered(t *testing.T) {
	up := fakeMCP(t, false)
	defer up.Close()
	_, body := call(t, newGW(t, up.URL), token("analyst"), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if strings.Contains(body, "delete_repo") {
		t.Fatalf("unauthorized tool leaked in list: %s", body)
	}
	if !strings.Contains(body, "search_docs") || !strings.Contains(body, "db.query") {
		t.Fatalf("allowed tools missing: %s", body)
	}
}

func TestToolCallDenied(t *testing.T) {
	up := fakeMCP(t, false)
	defer up.Close()
	gw := newGW(t, up.URL)
	for _, tool := range []string{"delete_repo", "db.drop_table"} {
		_, body := call(t, gw, token("analyst"), `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"`+tool+`"}}`)
		if !strings.Contains(body, `"code":-32001`) || !strings.Contains(body, `"id":7`) {
			t.Fatalf("%s: expected forbidden error, got %s", tool, body)
		}
	}
	if gw.Metrics.Denied.Load() != 2 {
		t.Fatalf("denied metric = %d", gw.Metrics.Denied.Load())
	}
}

func TestUnknownMethodDenied(t *testing.T) {
	up := fakeMCP(t, false)
	defer up.Close()
	_, body := call(t, newGW(t, up.URL), token("analyst"), `{"jsonrpc":"2.0","id":1,"method":"admin/shutdown"}`)
	if !strings.Contains(body, "method not permitted") {
		t.Fatalf("got %s", body)
	}
}

func TestBatchWithOneDeniedRejectsAll(t *testing.T) {
	up := fakeMCP(t, false)
	defer up.Close()
	_, body := call(t, newGW(t, up.URL), token("analyst"),
		`[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_docs"}},
		  {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_repo"}}]`)
	if strings.Contains(body, "result") || !strings.Contains(body, "-32001") {
		t.Fatalf("got %s", body)
	}
}

func TestRedactionBothDirections(t *testing.T) {
	for _, sse := range []bool{false, true} {
		up := fakeMCP(t, sse)
		_, body := call(t, newGW(t, up.URL), token("analyst"),
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_docs","arguments":{"q":"card 4111 1111 1111 1111"}}}`)
		up.Close()
		for _, leak := range []string{"bob@corp.com", "123-45-6789", "4111 1111 1111 1111"} {
			if strings.Contains(body, leak) {
				t.Fatalf("sse=%v leaked %q: %s", sse, leak, body)
			}
		}
		for _, want := range []string{"[REDACTED:EMAIL]", "[REDACTED:SSN]", "[REDACTED:CARD]"} {
			if !strings.Contains(body, want) {
				t.Fatalf("sse=%v missing %s: %s", sse, want, body)
			}
		}
		if sse && !strings.HasPrefix(body, "id: 1\nevent: message\ndata: ") {
			t.Fatalf("SSE framing not preserved: %q", body)
		}
	}
}

func TestRateLimit(t *testing.T) {
	up := fakeMCP(t, false)
	defer up.Close()
	gw := newGW(t, up.URL)
	gw.limiter = newLimiter(2)
	tok := token("analyst")
	var last int
	for i := 0; i < 3; i++ {
		last, _ = call(t, gw, tok, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", last)
	}
}

func TestOversizeBody(t *testing.T) {
	up := fakeMCP(t, false)
	defer up.Close()
	gw := newGW(t, up.URL)
	gw.opt.MaxBodyBytes = 10
	code, _ := call(t, gw, token("analyst"), `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", code)
	}
}
