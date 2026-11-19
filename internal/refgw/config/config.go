// Package config loads the gateway's JSON configuration file.
// Secrets are never stored in the file; they are read from environment
// variables named in the config.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw/auth"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw/policy"
)

type Config struct {
	Listen   string `json:"listen"`
	Upstream struct {
		URL           string `json:"url"`
		AuthHeaderEnv string `json:"auth_header_env"`
	} `json:"upstream"`
	Auth struct {
		auth.Config
		JWTSecretEnv string `json:"jwt_secret_env"`
	} `json:"auth"`
	Policy    policy.Policy `json:"policy"`
	Redaction struct {
		Detectors []string          `json:"detectors"`
		Custom    map[string]string `json:"custom"`
		Requests  bool              `json:"requests"`
		Responses bool              `json:"responses"`
	} `json:"redaction"`
	Limits struct {
		MaxBodyBytes  int64 `json:"max_body_bytes"`
		RatePerMinute int   `json:"rate_per_minute"`
	} `json:"limits"`
	Hardening struct {
		AllowedOrigins  []string `json:"allowed_origins"`
		AllowedHosts    []string `json:"allowed_hosts"`
		ScreenInjection bool     `json:"screen_injection"`
		PinTools        bool     `json:"pin_tools"`
		ValidateSchemas bool     `json:"validate_schemas"`
		// ValidateMirroredHeaders enforces SEP-2243 header mirroring.
		ValidateMirroredHeaders bool `json:"validate_mirrored_headers"`
		// SealRequestState seals upstream requestState; the MAC key comes
		// from StateKeyEnv, or is random per process if that is unset.
		SealRequestState bool   `json:"seal_request_state"`
		StateKeyEnv      string `json:"state_key_env"`
	} `json:"hardening"`

	// Resolved values.
	UpstreamURL        *url.URL `json:"-"`
	UpstreamAuthHeader string   `json:"-"`
	StateKey           []byte   `json:"-"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.Upstream.URL == "" {
		return nil, errors.New("upstream.url is required")
	}
	if c.UpstreamURL, err = url.Parse(c.Upstream.URL); err != nil {
		return nil, fmt.Errorf("upstream.url: %w", err)
	}
	if c.Upstream.AuthHeaderEnv != "" {
		c.UpstreamAuthHeader = os.Getenv(c.Upstream.AuthHeaderEnv)
	}
	if c.Auth.JWTSecretEnv != "" {
		s := os.Getenv(c.Auth.JWTSecretEnv)
		if len(s) > 0 && len(s) < 32 {
			return nil, fmt.Errorf("%s must be at least 32 bytes", c.Auth.JWTSecretEnv)
		}
		c.Auth.JWTSecret = []byte(s)
	}
	if c.Hardening.StateKeyEnv != "" {
		k := os.Getenv(c.Hardening.StateKeyEnv)
		if len(k) > 0 && len(k) < 32 {
			return nil, fmt.Errorf("%s must be at least 32 bytes", c.Hardening.StateKeyEnv)
		}
		c.StateKey = []byte(k)
	}
	if len(c.Auth.JWTSecret) == 0 && len(c.Auth.APIKeys) == 0 {
		return nil, errors.New("no authentication configured: set auth.jwt_secret_env or auth.api_keys")
	}
	if len(c.Policy.Rules) == 0 {
		return nil, errors.New("policy.rules is empty; everything would be denied")
	}
	return &c, nil
}
