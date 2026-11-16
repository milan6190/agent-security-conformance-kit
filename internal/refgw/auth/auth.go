// Package auth authenticates callers of the gateway using either
// HS256-signed JWTs (e.g. minted by an IdP or token exchange) or static
// API keys stored as SHA-256 hashes. It uses only the standard library.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Principal is an authenticated caller.
type Principal struct {
	Subject string   `json:"sub"`
	Roles   []string `json:"roles"`
	Method  string   `json:"auth_method"`
}

// APIKey is a static credential. Only the SHA-256 hex digest is stored.
type APIKey struct {
	SHA256  string   `json:"sha256"`
	Subject string   `json:"subject"`
	Roles   []string `json:"roles"`
}

// Config controls authentication.
type Config struct {
	JWTSecret  []byte   `json:"-"`
	Issuer     string   `json:"issuer"`
	Audience   string   `json:"audience"`
	RolesClaim string   `json:"roles_claim"`
	ClockSkew  Duration `json:"clock_skew"`
	APIKeys    []APIKey `json:"api_keys"`
}

// Duration is a time.Duration that unmarshals from strings like "30s".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	d.Duration = v
	return err
}

var (
	ErrMissing = errors.New("missing credentials")
	ErrInvalid = errors.New("invalid credentials")
)

// Authenticator validates requests.
type Authenticator struct {
	cfg Config
	now func() time.Time
}

func New(cfg Config) *Authenticator {
	if cfg.RolesClaim == "" {
		cfg.RolesClaim = "roles"
	}
	return &Authenticator{cfg: cfg, now: time.Now}
}

// Authenticate inspects Authorization: Bearer <jwt> or X-API-Key.
func (a *Authenticator) Authenticate(r *http.Request) (*Principal, error) {
	if key := r.Header.Get("X-API-Key"); key != "" {
		return a.apiKey(key)
	}
	h := r.Header.Get("Authorization")
	if h == "" {
		return nil, ErrMissing
	}
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return nil, ErrInvalid
	}
	return a.VerifyJWT(strings.TrimSpace(tok))
}

func (a *Authenticator) apiKey(key string) (*Principal, error) {
	sum := sha256.Sum256([]byte(key))
	got := hex.EncodeToString(sum[:])
	var match *APIKey
	// Compare against every key to keep timing independent of position.
	for i := range a.cfg.APIKeys {
		k := &a.cfg.APIKeys[i]
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(k.SHA256)), []byte(got)) == 1 {
			match = k
		}
	}
	if match == nil {
		return nil, ErrInvalid
	}
	return &Principal{Subject: match.Subject, Roles: match.Roles, Method: "api_key"}, nil
}

// VerifyJWT validates an HS256 token and extracts subject and roles.
func (a *Authenticator) VerifyJWT(tok string) (*Principal, error) {
	if len(a.cfg.JWTSecret) == 0 {
		return nil, ErrInvalid
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, ErrInvalid
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := decodeSeg(parts[0], &hdr); err != nil || hdr.Alg != "HS256" {
		// Rejects "none" and algorithm-confusion attempts.
		return nil, ErrInvalid
	}
	mac := hmac.New(sha256.New, a.cfg.JWTSecret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, ErrInvalid
	}
	var claims map[string]any
	if err := decodeSeg(parts[1], &claims); err != nil {
		return nil, ErrInvalid
	}
	now := a.now()
	skew := a.cfg.ClockSkew.Duration
	exp, ok := numClaim(claims, "exp")
	if !ok || now.After(time.Unix(int64(exp), 0).Add(skew)) {
		return nil, ErrInvalid
	}
	if nbf, ok := numClaim(claims, "nbf"); ok && now.Add(skew).Before(time.Unix(int64(nbf), 0)) {
		return nil, ErrInvalid
	}
	if a.cfg.Issuer != "" && claims["iss"] != a.cfg.Issuer {
		return nil, ErrInvalid
	}
	if a.cfg.Audience != "" && !hasAudience(claims["aud"], a.cfg.Audience) {
		return nil, ErrInvalid
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, ErrInvalid
	}
	return &Principal{Subject: sub, Roles: stringList(claims[a.cfg.RolesClaim]), Method: "jwt"}, nil
}

func decodeSeg(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func numClaim(c map[string]any, k string) (float64, bool) {
	f, ok := c[k].(float64)
	return f, ok
}

func hasAudience(v any, want string) bool {
	switch t := v.(type) {
	case string:
		return t == want
	case []any:
		for _, x := range t {
			if x == want {
				return true
			}
		}
	}
	return false
}

func stringList(v any) []string {
	switch t := v.(type) {
	case string:
		return strings.Fields(t)
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// SignHS256 mints a token. Intended for tests and local development.
func SignHS256(secret []byte, claims map[string]any) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	b, _ := json.Marshal(claims)
	p := base64.RawURLEncoding.EncodeToString(b)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(h + "." + p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
