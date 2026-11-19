package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

// --- Mirrored request headers (SEP-2243; AISVS 10.3.6, 10.4.11, 10.4.12) ---

// protocolMirrored is the first MCP revision whose clients mirror request
// body fields into Mcp-Method, Mcp-Name and Mcp-Param-* headers.
const protocolMirrored = "2026-07-28"

// codeHeaderMismatch is HEADER_MISMATCH in the 2026-07-28 schema.
const codeHeaderMismatch = -32020

const paramPrefix = "Mcp-Param-"

// mirroredVersion reports whether the request's protocol version requires
// header-body validation. MCP versions are dates, so they compare as strings.
func mirroredVersion(r *http.Request) bool {
	v := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version"))
	return len(v) == len(protocolMirrored) && v >= protocolMirrored
}

// stripMirrored removes mirrored headers that cannot be trusted because the
// protocol version predates header-body validation. They are never
// forwarded, and the gateway never decides anything from them.
func stripMirrored(r *http.Request) {
	for k := range r.Header {
		if strings.EqualFold(k, "Mcp-Method") || strings.EqualFold(k, "Mcp-Name") || hasParamPrefix(k) {
			r.Header.Del(k)
		}
	}
}

func hasParamPrefix(k string) bool {
	return len(k) > len(paramPrefix) && strings.EqualFold(k[:len(paramPrefix)], paramPrefix)
}

// checkStandardHeaders validates Mcp-Method and Mcp-Name against one message.
func checkStandardHeaders(r *http.Request, m msg) string {
	method, _ := m["method"].(string)
	if method == "" {
		return "" // a response to a server request carries no method
	}
	hm, ok := headerValue(r, "Mcp-Method")
	if !ok {
		return "missing required Mcp-Method header"
	}
	if hm != method {
		return fmt.Sprintf("Mcp-Method header %q does not match body method %q", hm, method)
	}
	params, _ := m["params"].(map[string]any)
	var want string
	switch method {
	case "tools/call", "prompts/get":
		want, _ = params["name"].(string)
	case "resources/read":
		want, _ = params["uri"].(string)
	default:
		if _, ok := headerValue(r, "Mcp-Name"); ok {
			return "Mcp-Name header is not expected for " + method
		}
		return ""
	}
	hn, ok := headerValue(r, "Mcp-Name")
	if !ok {
		return "missing required Mcp-Name header"
	}
	if hn != want {
		return fmt.Sprintf("Mcp-Name header %q does not match body value %q", hn, want)
	}
	return ""
}

// checkParamHeaders validates Mcp-Param-* headers against a tools/call's
// arguments, using the x-mcp-header annotations in the tool's inputSchema.
// Every annotated argument that is present and non-null needs a matching
// header, and every Mcp-Param-* header needs a matching argument.
func checkParamHeaders(r *http.Request, method string, inputSchema map[string]any, args map[string]any) string {
	declared := map[string]string{} // lower-case header name -> property
	if method == "tools/call" {
		var err error
		if declared, err = headerAnnotations(inputSchema); err != nil {
			return err.Error()
		}
	}
	for k := range r.Header {
		if !hasParamPrefix(k) {
			continue
		}
		if _, ok := declared[strings.ToLower(k[len(paramPrefix):])]; !ok {
			return k + " header has no corresponding annotated argument"
		}
	}
	for hn, prop := range declared {
		v, present := args[prop]
		hv, sent := headerValue(r, paramPrefix+hn)
		switch {
		case !present || v == nil:
			if sent {
				return fmt.Sprintf("%s%s header sent but argument %q is absent", paramPrefix, hn, prop)
			}
		case !sent:
			return fmt.Sprintf("missing %s%s header for argument %q", paramPrefix, hn, prop)
		default:
			decoded, err := decodeHeaderValue(hv)
			if err != nil {
				return fmt.Sprintf("%s%s header: %v", paramPrefix, hn, err)
			}
			if !headerMatches(decoded, v) {
				return fmt.Sprintf("%s%s header does not match argument %q", paramPrefix, hn, prop)
			}
		}
	}
	return ""
}

// headerValue returns the single trimmed value of a header, rejecting
// characters RFC 9110 forbids in field values (Go already refuses CR, LF and
// NUL; this also refuses other controls and non-ASCII bytes).
func headerValue(r *http.Request, name string) (string, bool) {
	vs := r.Header.Values(name)
	if len(vs) == 0 {
		return "", false
	}
	if len(vs) > 1 {
		return "\x00duplicate", true // never matches a body value
	}
	v := strings.Trim(vs[0], " \t")
	for i := 0; i < len(v); i++ {
		if c := v[i]; c != '\t' && (c < 0x20 || c > 0x7e) {
			return "\x00invalid", true
		}
	}
	return v, true
}

func decodeHeaderValue(v string) (string, error) {
	if strings.HasPrefix(v, "\x00") {
		return "", fmt.Errorf("invalid characters or duplicate header")
	}
	inner, ok := strings.CutPrefix(v, "=?base64?")
	if !ok || !strings.HasSuffix(inner, "?=") {
		return v, nil // literal value
	}
	b, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(inner, "?="))
	if err != nil {
		return "", fmt.Errorf("invalid Base64 value")
	}
	if !utf8.Valid(b) {
		return "", fmt.Errorf("Base64 value is not UTF-8")
	}
	return string(b), nil
}

// headerMatches compares a decoded header value with a body value.
// Integers compare numerically (42.0 matches 42).
func headerMatches(h string, v any) bool {
	switch t := v.(type) {
	case string:
		return h == t
	case bool:
		return h == strconv.FormatBool(t)
	}
	want, ok := num(v)
	if !ok {
		return false
	}
	got, err := strconv.ParseFloat(h, 64)
	return err == nil && got == want
}

// headerAnnotations validates a tool's x-mcp-header annotations and returns
// lower-case header name -> property name. Annotations must sit on
// top-level string, integer or boolean properties and carry unique,
// non-empty HTTP token names (AISVS 10.4.11).
func headerAnnotations(inputSchema map[string]any) (map[string]string, error) {
	out := map[string]string{}
	props, _ := inputSchema["properties"].(map[string]any)
	for prop, raw := range props {
		ps, _ := raw.(map[string]any)
		hv, ok := ps["x-mcp-header"]
		if !ok {
			continue
		}
		name, _ := hv.(string)
		if !isToken(name) {
			return nil, fmt.Errorf("x-mcp-header %q on %q is not a valid header name", name, prop)
		}
		switch t, _ := ps["type"].(string); t {
		case "string", "integer", "boolean":
		default:
			return nil, fmt.Errorf("x-mcp-header on %q requires a string, integer or boolean property", prop)
		}
		key := strings.ToLower(name)
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("x-mcp-header %q is not unique", name)
		}
		out[key] = prop
	}
	// Annotations anywhere else (nested properties, items, $defs) are invalid.
	var nested func(x any, top bool) bool
	nested = func(x any, top bool) bool {
		switch t := x.(type) {
		case map[string]any:
			for k, c := range t {
				if k == "x-mcp-header" && !top {
					return true
				}
				if k == "enum" || k == "const" || k == "default" || k == "examples" {
					continue
				}
				if nested(c, false) {
					return true
				}
			}
		case []any:
			for _, c := range t {
				if nested(c, false) {
					return true
				}
			}
		}
		return false
	}
	for prop, raw := range props {
		ps, _ := raw.(map[string]any)
		for k, c := range ps {
			if k != "x-mcp-header" && nested(c, false) {
				return nil, fmt.Errorf("x-mcp-header nested inside %q is not allowed", prop)
			}
		}
	}
	for k, c := range inputSchema {
		if k != "properties" && nested(c, false) {
			return nil, fmt.Errorf("x-mcp-header outside top-level properties is not allowed")
		}
	}
	return out, nil
}

// isToken reports whether s is an RFC 9110 token (1*tchar).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// dropBadAnnotations removes tools whose x-mcp-header annotations are
// invalid, keeping the rest of the list (AISVS 10.4.11).
func (g *Gateway) dropBadAnnotations(res map[string]any) {
	items, ok := res["tools"].([]any)
	if !ok {
		return
	}
	kept := items[:0:0]
	for _, it := range items {
		obj, _ := it.(map[string]any)
		in, _ := obj["inputSchema"].(map[string]any)
		if _, err := headerAnnotations(in); err != nil {
			g.opt.Logger.Warn("tool_header_annotation_invalid", "tool", obj["name"], "err", err.Error())
			continue
		}
		kept = append(kept, it)
	}
	res["tools"] = kept
}

func num(x any) (float64, bool) {
	switch n := x.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}
