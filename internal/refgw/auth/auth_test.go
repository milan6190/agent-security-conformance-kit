package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http/httptest"
	"testing"
	"time"
)

var secret = []byte("0123456789abcdef0123456789abcdef")

func TestJWT(t *testing.T) {
	a := New(Config{JWTSecret: secret, Issuer: "idp", Audience: "mcp"})
	exp := time.Now().Add(time.Hour).Unix()
	good := SignHS256(secret, map[string]any{"sub": "u1", "iss": "idp", "aud": []string{"mcp"}, "exp": exp, "roles": []string{"a", "b"}})
	p, err := a.VerifyJWT(good)
	if err != nil || p.Subject != "u1" || len(p.Roles) != 2 {
		t.Fatalf("valid token rejected: %v %+v", err, p)
	}

	cases := map[string]string{
		"wrong secret": SignHS256([]byte("x-other-secret-x-other-secret-xx"), map[string]any{"sub": "u", "iss": "idp", "aud": "mcp", "exp": exp}),
		"expired":      SignHS256(secret, map[string]any{"sub": "u", "iss": "idp", "aud": "mcp", "exp": time.Now().Add(-time.Hour).Unix()}),
		"no exp":       SignHS256(secret, map[string]any{"sub": "u", "iss": "idp", "aud": "mcp"}),
		"wrong aud":    SignHS256(secret, map[string]any{"sub": "u", "iss": "idp", "aud": "other", "exp": exp}),
		"wrong iss":    SignHS256(secret, map[string]any{"sub": "u", "iss": "evil", "aud": "mcp", "exp": exp}),
		"alg none": base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u","iss":"idp","aud":"mcp","exp":9999999999}`)) + ".",
		"garbage": "not.a.jwt",
	}
	for name, tok := range cases {
		if _, err := a.VerifyJWT(tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAPIKey(t *testing.T) {
	sum := sha256.Sum256([]byte("s3cret-key"))
	a := New(Config{APIKeys: []APIKey{{SHA256: hex.EncodeToString(sum[:]), Subject: "ci-bot", Roles: []string{"reader"}}}})
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("X-API-Key", "s3cret-key")
	if p, err := a.Authenticate(r); err != nil || p.Subject != "ci-bot" {
		t.Fatalf("valid key rejected: %v", err)
	}
	r.Header.Set("X-API-Key", "wrong")
	if _, err := a.Authenticate(r); err == nil {
		t.Fatal("wrong key accepted")
	}
}
