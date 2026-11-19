// Package spec defines the YAML formats for test cases and target profiles.
package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/aisvs"
	"github.com/goccy/go-yaml"
)

// Test is one conformance test case.
type Test struct {
	ID        string      `yaml:"id"`
	Title     string      `yaml:"title"`
	AISVS     []string    `yaml:"aisvs"`
	Risks     []string    `yaml:"risks"`
	Level     int         `yaml:"level"`
	Mode      string      `yaml:"mode"` // "protocol" (v0.1); "agent" planned
	Requires  []string    `yaml:"requires"`
	Rationale string      `yaml:"rationale"`
	Canary    CanarySetup `yaml:"canary"`
	Steps     []Step      `yaml:"steps"`

	File string `yaml:"-"`
}

// CanarySetup customizes the canary MCP server for one test.
type CanarySetup struct {
	// Results overrides the text a tool returns.
	Results map[string]string `yaml:"results"`
	// Structured sets the structuredContent a tool returns.
	Structured map[string]any `yaml:"structured"`
	// Tools adds test-scoped tools. Their names must start with "asck_";
	// the target contract grants them to the admin principal.
	Tools []ToolDef `yaml:"tools"`
}

// ToolDef is a test-scoped canary tool.
type ToolDef struct {
	Name         string         `yaml:"name"`
	Description  string         `yaml:"description"`
	InputSchema  map[string]any `yaml:"input_schema"`
	OutputSchema map[string]any `yaml:"output_schema"`
	// NestedSchemaDepth, if set, replaces InputSchema with an object schema
	// nested this many levels deep (for schema resource-bound tests).
	NestedSchemaDepth int `yaml:"nested_schema_depth"`
	// InputRequired makes the tool answer a call that carries no
	// requestState with an input_required result (multi round-trip).
	InputRequired bool `yaml:"input_required"`
}

// Step is one request sent to the system under test.
type Step struct {
	Name     string            `yaml:"name"`
	As       string            `yaml:"as"` // principal name, "anonymous", or a token variant such as "reader:expired"
	RPC      map[string]any    `yaml:"rpc"`
	Headers  map[string]string `yaml:"headers"`
	PadBytes int               `yaml:"pad_bytes"` // adds a large junk field to the request
	// ArgBytes sets each named tools/call argument to a string of that many bytes.
	ArgBytes map[string]int `yaml:"arg_bytes"`
	// MirrorHeaders sends MCP-Protocol-Version 2026-07-28 with correctly
	// mirrored Mcp-Method, Mcp-Name and Mcp-Param-* headers (SEP-2243).
	// Headers then overrides them and OmitHeaders removes them.
	MirrorHeaders bool     `yaml:"mirror_headers"`
	OmitHeaders   []string `yaml:"omit_headers"`
	// CanaryMutate changes tool definitions on the canary before this step runs.
	CanaryMutate map[string]ToolPatch `yaml:"canary_mutate"`
	Expect       Expect               `yaml:"expect"`
}

// ToolPatch changes a canary tool definition.
type ToolPatch struct {
	Description string         `yaml:"description"`
	InputSchema map[string]any `yaml:"input_schema"`
}

// Expect lists the assertions for a step. All present assertions must hold.
type Expect struct {
	Blocked *bool `yaml:"blocked"`
	Allowed *bool `yaml:"allowed"`
	// HTTPError passes if the HTTP status is 400 or higher (intermediaries
	// must reject header validation failures with an HTTP error status).
	HTTPError                 bool     `yaml:"http_error"`
	CanaryReceivedContains    []string `yaml:"canary_received_contains"`
	CanaryCalled              []string `yaml:"canary_called"`
	CanaryNotCalled           []string `yaml:"canary_not_called"`
	CanaryReceivedNotContains []string `yaml:"canary_received_not_contains"`
	CanaryAuthNotClientToken  bool     `yaml:"canary_auth_not_client_token"`
	// CanaryNoFetch passes if nothing made a non-MCP HTTP request to the
	// canary (for example, to resolve a remote JSON Schema $ref).
	CanaryNoFetch       bool     `yaml:"canary_no_fetch"`
	ResponseContains    []string `yaml:"response_contains"`
	ResponseNotContains []string `yaml:"response_not_contains"`
	ToolsListIncludes   []string `yaml:"tools_list_includes"`
	ToolsListExcludes   []string `yaml:"tools_list_excludes"`
	// BlockedOrExcluded passes if the step was blocked OR tools/list omits the tool.
	BlockedOrExcludes []string `yaml:"blocked_or_excludes"`
}

// Target describes the system under test and how to reach it.
type Target struct {
	Name     string `yaml:"name"`
	Endpoint string `yaml:"endpoint"`
	// CanaryListen is where the kit starts the canary MCP server. The system
	// under test must be configured to use http://<canary_listen>/mcp upstream.
	CanaryListen string               `yaml:"canary_listen"`
	Principals   map[string]Principal `yaml:"principals"`
	JWT          *JWTConfig           `yaml:"jwt"`
	Capabilities []string             `yaml:"capabilities"`
}

// Principal is a caller identity.
type Principal struct {
	Headers map[string]string `yaml:"headers"`
	// Claims mints an HS256 JWT from Target.JWT when set.
	Claims map[string]any `yaml:"claims"`
}

// JWTConfig lets the kit mint tokens, enabling token-claim tests.
type JWTConfig struct {
	SecretEnv string `yaml:"secret_env"`
	Issuer    string `yaml:"issuer"`
	Audience  string `yaml:"audience"`
	Secret    string `yaml:"-"`
}

// LoadTests reads every *.yaml file under dir.
func LoadTests(dir string) ([]Test, error) {
	var tests []Test
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !(strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var t Test
		if err := yaml.UnmarshalWithOptions(b, &t, yaml.Strict()); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		t.File = p
		if err := t.validate(); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		tests = append(tests, t)
		return nil
	})
	sort.Slice(tests, func(i, j int) bool { return tests[i].ID < tests[j].ID })
	seen := map[string]bool{}
	for _, t := range tests {
		if seen[t.ID] {
			return nil, fmt.Errorf("duplicate test id %s", t.ID)
		}
		seen[t.ID] = true
	}
	return tests, err
}

func (t *Test) validate() error {
	if t.ID == "" || t.Title == "" {
		return fmt.Errorf("id and title are required")
	}
	if t.Mode == "" {
		t.Mode = "protocol"
	}
	if t.Mode != "protocol" {
		return fmt.Errorf("unsupported mode %q (v0.1 supports protocol)", t.Mode)
	}
	if len(t.AISVS) == 0 {
		return fmt.Errorf("at least one aisvs requirement id is required")
	}
	for _, id := range t.AISVS {
		if _, ok := aisvs.Lookup(id); !ok {
			return fmt.Errorf("unknown or removed AISVS %s requirement %q", aisvs.Version, id)
		}
	}
	if len(t.Steps) == 0 {
		return fmt.Errorf("at least one step is required")
	}
	for _, d := range t.Canary.Tools {
		if !strings.HasPrefix(d.Name, "asck_") {
			return fmt.Errorf("test-scoped tool %q: name must start with asck_", d.Name)
		}
		if d.NestedSchemaDepth < 0 || d.NestedSchemaDepth > 4000 {
			return fmt.Errorf("test-scoped tool %q: nested_schema_depth must be 0..4000", d.Name)
		}
	}
	return nil
}

// LoadTarget reads a target profile and resolves secrets from the environment.
func LoadTarget(path string) (*Target, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Target
	if err := yaml.UnmarshalWithOptions(b, &t, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if t.Endpoint == "" || t.CanaryListen == "" {
		return nil, fmt.Errorf("%s: endpoint and canary_listen are required", path)
	}
	if t.JWT != nil && t.JWT.SecretEnv != "" {
		t.JWT.Secret = os.Getenv(t.JWT.SecretEnv)
	}
	for name, p := range t.Principals {
		for k, v := range p.Headers {
			p.Headers[k] = os.ExpandEnv(v)
		}
		t.Principals[name] = p
	}
	return &t, nil
}

// HasCapability reports whether the target declared a capability.
func (t *Target) HasCapability(c string) bool {
	for _, x := range t.Capabilities {
		if x == c {
			return true
		}
	}
	return false
}
