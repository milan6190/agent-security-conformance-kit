// Package policy implements default-deny RBAC for MCP tools, resources
// and prompts. Deny rules win over allow rules across all of a caller's roles.
package policy

import (
	"fmt"
	"path"
	"strings"
)

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
	// ArgRules restrict argument values for tools this rule grants
	// (AISVS 10.2.5, 9.5.1). A grant holds only if every rule for the
	// tool is satisfied.
	ArgRules []ArgRule `json:"arg_rules"`
}

// ArgRule limits one string argument of a tool to values matching Allow
// (path.Match globs). Values must be canonical paths: absolute paths,
// "..", "." segments and NUL bytes are refused before matching.
type ArgRule struct {
	Tool  string   `json:"tool"`
	Arg   string   `json:"arg"`
	Allow []string `json:"allow"`
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
// It ignores argument rules; use CheckCall for tool invocations.
func (p *Policy) Check(roles []string, kind Kind, name string) Decision {
	return p.check(roles, kind, name, nil, false)
}

// CheckCall decides whether any of roles may call tool with args.
func (p *Policy) CheckCall(roles []string, tool string, args map[string]any) Decision {
	return p.check(roles, Tool, tool, args, true)
}

func (p *Policy) check(roles []string, kind Kind, name string, args map[string]any, withArgs bool) Decision {
	allowed := false
	argReason := ""
	for _, r := range p.Rules {
		if !hasRole(roles, r.Role) {
			continue
		}
		allow, deny := r.lists(kind)
		if matchAny(deny, name) {
			return Decision{false, "denied by role " + r.Role}
		}
		if matchAny(allow, name) {
			if withArgs {
				if reason := r.checkArgs(name, args); reason != "" {
					argReason = reason
					continue
				}
			}
			allowed = true
		}
	}
	if !allowed && argReason != "" {
		return Decision{false, argReason}
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

func (r Rule) checkArgs(tool string, args map[string]any) string {
	for _, ar := range r.ArgRules {
		if ok, _ := path.Match(ar.Tool, tool); !ok && ar.Tool != tool {
			continue
		}
		v, ok := args[ar.Arg].(string)
		if !ok {
			return fmt.Sprintf("argument %q of %s must be a string allowed for role %s", ar.Arg, tool, r.Role)
		}
		if !canonical(v) {
			return fmt.Sprintf("argument %q of %s is not a canonical relative path", ar.Arg, tool)
		}
		if !matchAny(ar.Allow, v) {
			return fmt.Sprintf("argument %q of %s is outside the grant for role %s", ar.Arg, tool, r.Role)
		}
	}
	return ""
}

func canonical(v string) bool {
	if v == "" || strings.ContainsRune(v, 0) || strings.Contains(v, "\\") || path.IsAbs(v) {
		return false
	}
	return path.Clean(v) == v && v != ".." && !strings.HasPrefix(v, "../")
}
