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
	} `json:"hardening"`

	// Resolved values.
	UpstreamURL        *url.URL `json:"-"`
	UpstreamAuthHeader string   `json:"-"`
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
	if len(c.Auth.JWTSecret) == 0 && len(c.Auth.APIKeys) == 0 {
		return nil, errors.New("no authentication configured: set auth.jwt_secret_env or auth.api_keys")
	}
	if len(c.Policy.Rules) == 0 {
		return nil, errors.New("policy.rules is empty; everything would be denied")
	}
	return &c, nil
}
