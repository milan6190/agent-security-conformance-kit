package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

// --- requestState integrity and single use (AISVS 10.2.8, 10.2.10) ---
//
// In a multi round-trip request the server returns an opaque requestState
// that the client must echo when it retries. The client controls what it
// echoes, so the gateway never lets upstream state reach the client as is.
// It seals the state, binding it to the caller, the target tool or resource,
// a nonce and an expiry, and on the retry it accepts only a valid seal it
// issued, once, for the same caller and target. Upstream then receives
// exactly the state it issued.

const statePrefix = "mcpg1."

type stateClaims struct {
	Subject  string `json:"sub"`
	Target   string `json:"tgt"`
	Upstream string `json:"st"`
	Nonce    string `json:"n"`
	Expires  int64  `json:"exp"`
}

type stateSealer struct {
	key []byte
	ttl time.Duration
	now func() time.Time

	mu   sync.Mutex
	used map[string]int64 // nonce -> expiry
}

func newStateSealer(key []byte, ttl time.Duration) *stateSealer {
	if len(key) == 0 {
		key = make([]byte, 32)
		rand.Read(key)
	}
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	return &stateSealer{key: key, ttl: ttl, now: time.Now, used: map[string]int64{}}
}

func (s *stateSealer) seal(subject, target, upstream string) string {
	n := make([]byte, 16)
	rand.Read(n)
	b, _ := json.Marshal(stateClaims{
		Subject:  subject,
		Target:   target,
		Upstream: upstream,
		Nonce:    base64.RawURLEncoding.EncodeToString(n),
		Expires:  s.now().Add(s.ttl).Unix(),
	})
	p := base64.RawURLEncoding.EncodeToString(b)
	return statePrefix + p + "." + s.mac(p)
}

func (s *stateSealer) mac(payload string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(statePrefix + payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

var (
	errStateInvalid  = errors.New("requestState failed integrity verification")
	errStateBinding  = errors.New("requestState was issued for a different caller or target")
	errStateExpired  = errors.New("requestState has expired")
	errStateConsumed = errors.New("requestState has already been used")
)

// open verifies a sealed state and consumes it. It returns the upstream
// state to forward.
func (s *stateSealer) open(token, subject, target string) (string, error) {
	rest, ok := strings.CutPrefix(token, statePrefix)
	if !ok {
		return "", errStateInvalid
	}
	p, sig, ok := strings.Cut(rest, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(s.mac(p))) {
		return "", errStateInvalid
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return "", errStateInvalid
	}
	var c stateClaims
	if json.Unmarshal(b, &c) != nil || c.Nonce == "" {
		return "", errStateInvalid
	}
	if c.Subject != subject || c.Target != target {
		return "", errStateBinding
	}
	now := s.now().Unix()
	if now > c.Expires {
		return "", errStateExpired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for n, exp := range s.used {
		if now > exp {
			delete(s.used, n) // expired states are refused anyway
		}
	}
	if _, seen := s.used[c.Nonce]; seen {
		return "", errStateConsumed
	}
	s.used[c.Nonce] = c.Expires
	return c.Upstream, nil
}
