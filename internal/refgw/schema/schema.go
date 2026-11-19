// Package schema is the reference gateway's JSON Schema validator for tool
// arguments and tool results (AISVS 10.4.1, 10.4.3, 10.4.4, 9.3.2).
//
// It supports the subset MCP tool schemas use in practice: type, enum,
// const, properties, required, additionalProperties, items, string and
// number bounds, and $ref to local definitions. It is deliberately strict:
//
//   - $ref is resolved only within the schema document ("#/..."). Network
//     and file references are never dereferenced, and a schema that relies
//     on one is rejected rather than treated as permissive (10.4.14, 10.4.15).
//   - Schemas are bounded in depth and size before use, and validation is
//     bounded in steps (10.4.13).
package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Limits bound the work spent on one schema.
type Limits struct {
	MaxDepth int // nesting depth of the schema document
	MaxNodes int // total number of subschemas
	MaxSteps int // validation steps, including $ref expansions
}

// DefaultLimits are generous for real tool schemas and small enough that a
// hostile schema cannot stall the gateway.
var DefaultLimits = Limits{MaxDepth: 64, MaxNodes: 2000, MaxSteps: 20000}

// ErrSchema marks a problem with the schema itself rather than the value.
var ErrSchema = errors.New("invalid tool schema")

// Validate checks value against schema. A nil schema accepts anything.
func Validate(schema map[string]any, value any, lim Limits) error {
	if schema == nil {
		return nil
	}
	if err := Check(schema, lim); err != nil {
		return err
	}
	v := &validator{root: schema, steps: lim.MaxSteps}
	return v.validate(schema, value, "$")
}

// Check verifies that a schema is within limits and has no external or
// unresolved $ref, without validating any value.
func Check(schema map[string]any, lim Limits) error {
	nodes := 0
	var walk func(x any, depth int) error
	walk = func(x any, depth int) error {
		switch t := x.(type) {
		case map[string]any:
			if depth > lim.MaxDepth {
				return fmt.Errorf("%w: nested deeper than %d levels", ErrSchema, lim.MaxDepth)
			}
			if nodes++; nodes > lim.MaxNodes {
				return fmt.Errorf("%w: more than %d elements", ErrSchema, lim.MaxNodes)
			}
			if ref, ok := t["$ref"]; ok {
				s, _ := ref.(string)
				if !strings.HasPrefix(s, "#") {
					return fmt.Errorf("%w: external $ref %q is not resolved", ErrSchema, s)
				}
				if _, err := resolve(schema, s); err != nil {
					return err
				}
			}
			for k, c := range t {
				if k == "enum" || k == "const" || k == "default" || k == "examples" {
					continue // values, not subschemas
				}
				if err := walk(c, depth+1); err != nil {
					return err
				}
			}
		case []any:
			for _, c := range t {
				if err := walk(c, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(schema, 0)
}

// resolve follows a local JSON Pointer such as "#/$defs/user".
func resolve(root map[string]any, ref string) (map[string]any, error) {
	ptr := strings.TrimPrefix(ref, "#")
	var cur any = root
	if ptr != "" {
		for _, tok := range strings.Split(strings.TrimPrefix(ptr, "/"), "/") {
			tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%w: unresolved $ref %q", ErrSchema, ref)
			}
			if cur, ok = m[tok]; !ok {
				return nil, fmt.Errorf("%w: unresolved $ref %q", ErrSchema, ref)
			}
		}
	}
	m, ok := cur.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: $ref %q is not a schema", ErrSchema, ref)
	}
	return m, nil
}

type validator struct {
	root  map[string]any
	steps int
}

func (v *validator) validate(s map[string]any, x any, at string) error {
	if v.steps--; v.steps < 0 {
		return fmt.Errorf("%w: validation step budget exceeded", ErrSchema)
	}
	if ref, ok := s["$ref"].(string); ok {
		target, err := resolve(v.root, ref)
		if err != nil {
			return err
		}
		if err := v.validate(target, x, at); err != nil {
			return err
		}
	}
	if t, ok := s["type"]; ok && !typeMatches(t, x) {
		return fmt.Errorf("%s: expected type %v, got %s", at, t, typeName(x))
	}
	if enum, ok := s["enum"].([]any); ok && !contains(enum, x) {
		return fmt.Errorf("%s: value not in enum", at)
	}
	if c, ok := s["const"]; ok && !equal(c, x) {
		return fmt.Errorf("%s: value does not match const", at)
	}
	switch t := x.(type) {
	case string:
		n := utf8.RuneCountInString(t)
		if m, ok := num(s["maxLength"]); ok && float64(n) > m {
			return fmt.Errorf("%s: string longer than maxLength %v", at, m)
		}
		if m, ok := num(s["minLength"]); ok && float64(n) < m {
			return fmt.Errorf("%s: string shorter than minLength %v", at, m)
		}
	case map[string]any:
		return v.object(s, t, at)
	case []any:
		if m, ok := num(s["maxItems"]); ok && float64(len(t)) > m {
			return fmt.Errorf("%s: more than maxItems %v", at, m)
		}
		if m, ok := num(s["minItems"]); ok && float64(len(t)) < m {
			return fmt.Errorf("%s: fewer than minItems %v", at, m)
		}
		if items, ok := s["items"].(map[string]any); ok {
			for i, e := range t {
				if err := v.validate(items, e, at+"["+strconv.Itoa(i)+"]"); err != nil {
					return err
				}
			}
		}
	default:
		if f, ok := num(x); ok {
			if m, ok := num(s["maximum"]); ok && f > m {
				return fmt.Errorf("%s: above maximum %v", at, m)
			}
			if m, ok := num(s["minimum"]); ok && f < m {
				return fmt.Errorf("%s: below minimum %v", at, m)
			}
		}
	}
	return nil
}

func (v *validator) object(s map[string]any, o map[string]any, at string) error {
	props, _ := s["properties"].(map[string]any)
	if req, ok := s["required"].([]any); ok {
		for _, r := range req {
			name, _ := r.(string)
			if _, ok := o[name]; !ok {
				return fmt.Errorf("%s: missing required property %q", at, name)
			}
		}
	}
	for k, val := range o {
		if ps, ok := props[k].(map[string]any); ok {
			if err := v.validate(ps, val, at+"."+k); err != nil {
				return err
			}
			continue
		}
		switch ap := s["additionalProperties"].(type) {
		case bool:
			if !ap {
				return fmt.Errorf("%s: unrecognized property %q", at, k)
			}
		case map[string]any:
			if err := v.validate(ap, val, at+"."+k); err != nil {
				return err
			}
		}
	}
	return nil
}

func typeMatches(t any, x any) bool {
	switch tt := t.(type) {
	case string:
		return isType(tt, x)
	case []any:
		for _, e := range tt {
			if s, ok := e.(string); ok && isType(s, x) {
				return true
			}
		}
	}
	return false
}

func isType(t string, x any) bool {
	switch t {
	case "object":
		_, ok := x.(map[string]any)
		return ok
	case "array":
		_, ok := x.([]any)
		return ok
	case "string":
		_, ok := x.(string)
		return ok
	case "boolean":
		_, ok := x.(bool)
		return ok
	case "null":
		return x == nil
	case "number":
		_, ok := num(x)
		return ok
	case "integer":
		f, ok := num(x)
		return ok && f == math.Trunc(f)
	}
	return false
}

func typeName(x any) string {
	switch x.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "boolean"
	case nil:
		return "null"
	}
	if _, ok := num(x); ok {
		return "number"
	}
	return fmt.Sprintf("%T", x)
}

func num(x any) (float64, bool) {
	switch n := x.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func contains(list []any, x any) bool {
	for _, e := range list {
		if equal(e, x) {
			return true
		}
	}
	return false
}

func equal(a, b any) bool {
	if fa, ok := num(a); ok {
		fb, ok := num(b)
		return ok && fa == fb
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}
