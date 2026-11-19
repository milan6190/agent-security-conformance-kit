package proxy

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStateSealer(t *testing.T) {
	s := newStateSealer([]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }

	tok := s.seal("alice", "tool:x", "upstream-state")
	if _, err := s.open(tok, "bob", "tool:x"); !errors.Is(err, errStateBinding) {
		t.Fatalf("other subject: got %v", err)
	}
	if _, err := s.open(tok, "alice", "tool:y"); !errors.Is(err, errStateBinding) {
		t.Fatalf("other target: got %v", err)
	}
	if _, err := s.open(tok+"x", "alice", "tool:x"); !errors.Is(err, errStateInvalid) {
		t.Fatalf("tampered: got %v", err)
	}
	if _, err := s.open("upstream-state", "alice", "tool:x"); !errors.Is(err, errStateInvalid) {
		t.Fatalf("raw upstream state: got %v", err)
	}
	other := newStateSealer([]byte("ffffffffffffffffffffffffffffffff"), time.Minute)
	if _, err := s.open(other.seal("alice", "tool:x", "s"), "alice", "tool:x"); !errors.Is(err, errStateInvalid) {
		t.Fatalf("foreign key: got %v", err)
	}
	up, err := s.open(tok, "alice", "tool:x")
	if err != nil || up != "upstream-state" {
		t.Fatalf("valid: got %q, %v", up, err)
	}
	if _, err := s.open(tok, "alice", "tool:x"); !errors.Is(err, errStateConsumed) {
		t.Fatalf("replay: got %v", err)
	}
	late := s.seal("alice", "tool:x", "s")
	now = now.Add(2 * time.Minute)
	if _, err := s.open(late, "alice", "tool:x"); !errors.Is(err, errStateExpired) {
		t.Fatalf("expired: got %v", err)
	}
}

func schemaOf(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestHeaderAnnotations(t *testing.T) {
	for s, ok := range map[string]bool{
		`{"properties":{"r":{"type":"string","x-mcp-header":"Region"}}}`:                                           true,
		`{"properties":{"n":{"type":"integer","x-mcp-header":"Count"},"f":{"type":"boolean","x-mcp-header":"F"}}}`: true,
		`{"properties":{"r":{"type":"string","x-mcp-header":"Method"}}}`:                                           true, // Mcp-Param-Method is allowed
		`{"properties":{"r":{"type":"string","x-mcp-header":""}}}`:                                                 false,
		`{"properties":{"r":{"type":"string","x-mcp-header":"Region:Primary"}}}`:                                   false,
		`{"properties":{"r":{"type":"string","x-mcp-header":"Région"}}}`:                                           false,
		`{"properties":{"r":{"type":"number","x-mcp-header":"Ratio"}}}`:                                            false,
		`{"properties":{"r":{"type":"array","x-mcp-header":"List"}}}`:                                              false,
		`{"properties":{"r":{"type":"string","x-mcp-header":"Region"}},"$defs":{"d":{"x-mcp-header":"X"}}}`:        false,
	} {
		_, err := headerAnnotations(schemaOf(t, s))
		if (err == nil) != ok {
			t.Errorf("%s: got err=%v, want ok=%v", s, err, ok)
		}
	}
}

func TestParamHeaders(t *testing.T) {
	in := schemaOf(t, `{"properties":{"t":{"type":"string","x-mcp-header":"Tenant"},"n":{"type":"integer","x-mcp-header":"Count"},"v":{"type":"boolean","x-mcp-header":"Verbose"}}}`)
	args := map[string]any{"t": "Hello", "n": json.Number("42"), "v": true}
	cases := []struct {
		hdr  map[string]string
		args map[string]any
		ok   bool
	}{
		{map[string]string{"Mcp-Param-Tenant": "Hello", "Mcp-Param-Count": "42.0", "Mcp-Param-Verbose": "true"}, args, true},
		{map[string]string{"Mcp-Param-Tenant": "=?base64?SGVsbG8=?=", "Mcp-Param-Count": "42", "Mcp-Param-Verbose": "true"}, args, true},
		{map[string]string{"Mcp-Param-Tenant": "=?base64?SGVsbG8?=", "Mcp-Param-Count": "42", "Mcp-Param-Verbose": "true"}, args, false},  // bad padding
		{map[string]string{"Mcp-Param-Tenant": "=?BASE64?SGVsbG8=?=", "Mcp-Param-Count": "42", "Mcp-Param-Verbose": "true"}, args, false}, // literal, mismatches
		{map[string]string{"Mcp-Param-Tenant": "Hello", "Mcp-Param-Count": "43", "Mcp-Param-Verbose": "true"}, args, false},
		{map[string]string{"Mcp-Param-Tenant": "Hello", "Mcp-Param-Count": "42", "Mcp-Param-Verbose": "True"}, args, false},
		{map[string]string{"Mcp-Param-Tenant": "Hello", "Mcp-Param-Count": "42", "Mcp-Param-Verbose": "true", "Mcp-Param-Extra": "x"}, args, false},
		{map[string]string{"Mcp-Param-Tenant": "Hello"}, map[string]any{"t": "Hello", "n": nil}, true}, // null and absent need no header
		{map[string]string{"Mcp-Param-Tenant": "Hello", "Mcp-Param-Count": "1"}, map[string]any{"t": "Hello"}, false},
	}
	for i, c := range cases {
		r := httptest.NewRequest("POST", "/mcp", nil)
		for k, v := range c.hdr {
			r.Header.Set(k, v)
		}
		if reason := checkParamHeaders(r, "tools/call", in, c.args); (reason == "") != c.ok {
			t.Errorf("case %d: reason %q, want ok=%v", i, reason, c.ok)
		}
	}
}

func TestMirroredVersion(t *testing.T) {
	for v, want := range map[string]bool{"2026-07-28": true, "2027-01-01": true, "2025-11-25": false, "": false, "2026-07-28x": false} {
		r := httptest.NewRequest("POST", "/mcp", nil)
		if v != "" {
			r.Header.Set("MCP-Protocol-Version", v)
		}
		if got := mirroredVersion(r); got != want {
			t.Errorf("%q: got %v want %v", v, got, want)
		}
	}
}
