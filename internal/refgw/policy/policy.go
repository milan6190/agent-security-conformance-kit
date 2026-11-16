// Package policy implements default-deny RBAC for MCP tools, resources
// and prompts. Deny rules win over allow rules across all of a caller's roles.
package policy

import "path"

// Kind is the type of MCP capability being accessed.
type Kind string

const (
	Tool     Kind = "tool"
	Resource Kind = "resource"
	Prompt   Kind = "prompt"
)

// Rule grants (or denies) capabilities to a role. Patterns use path.Match
// globs, e.g. "github.*", "file:///srv/docs/*", or "*".
type Rule struct {
	Role           string   `json:"role"`
	AllowTools     []string `json:"allow_tools"`
	DenyTools      []string `json:"deny_tools"`
	AllowResources []string `json:"allow_resources"`
	DenyResources  []string `json:"deny_resources"`
	AllowPrompts   []string `json:"allow_prompts"`
}

// Policy is the full rule set.
type Policy struct {
	Rules []Rule `json:"rules"`
}

// Decision is the outcome of an authorization check.
type Decision struct {
	Allowed bool
	Reason  string
}

// Check decides whether any of roles may access name of the given kind.
func (p *Policy) Check(roles []string, kind Kind, name string) Decision {
	allowed := false
	for _, r := range p.Rules {
		if !hasRole(roles, r.Role) {
			continue
		}
		allow, deny := r.lists(kind)
		if matchAny(deny, name) {
			return Decision{false, "denied by role " + r.Role}
		}
		if matchAny(allow, name) {
			allowed = true
		}
	}
	if !allowed {
		return Decision{false, "no rule grants access (default deny)"}
	}
	return Decision{true, "allowed"}
}

func (r Rule) lists(k Kind) (allow, deny []string) {
	switch k {
	case Tool:
		return r.AllowTools, r.DenyTools
	case Resource:
		return r.AllowResources, r.DenyResources
	case Prompt:
		return r.AllowPrompts, nil
	}
	return nil, nil
}

func hasRole(roles []string, want string) bool {
	if want == "*" {
		return true
	}
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if ok, err := path.Match(p, name); err == nil && ok {
			return true
		}
		// Allow "*" to also match names containing "/" (e.g. URIs).
		if p == "*" {
			return true
		}
	}
	return false
}
