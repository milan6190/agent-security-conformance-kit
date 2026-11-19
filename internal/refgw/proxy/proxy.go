// Package proxy implements the MCP Guard reverse proxy for the MCP
// Streamable HTTP transport (JSON-RPC 2.0 over POST, with JSON or SSE replies).
package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw/auth"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw/policy"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw/redact"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw/schema"
)

// JSON-RPC error codes used by the gateway.
const (
	codeParseError = -32700
	codeForbidden  = -32001
	codeBadResult  = -32002
)

// Methods that are always permitted once a caller is authenticated.
// Capability-bearing methods (tools/call, resources/read, prompts/get)
// are checked against policy; anything else is denied.
var safeMethods = map[string]bool{
	"initialize":               true,
	"ping":                     true,
	"tools/list":               true,
	"resources/list":           true,
	"resources/templates/list": true,
	"prompts/list":             true,
	"completion/complete":      true,
	"logging/setLevel":         true,
}

// Options configures a Gateway.
type Options struct {
	Upstream           *url.URL
	UpstreamAuthHeader string // optional Authorization value sent upstream
	Auth               *auth.Authenticator
	Policy             *policy.Policy
	Redactor           *redact.Redactor
	RedactRequests     bool
	RedactResponses    bool
	MaxBodyBytes       int64
	RatePerMinute      int
	Logger             *slog.Logger
	Client             *http.Client

	// AllowedOrigins / AllowedHosts guard against DNS rebinding (AISVS 10.3.3).
	// A request carrying an Origin not listed, or a Host not listed, is refused.
	AllowedOrigins []string
	AllowedHosts   []string
	// ScreenInjection withholds tool results and tool descriptions that look
	// like prompt injection (AISVS 10.4.2).
	ScreenInjection bool
	// PinTools records each tool's definition the first time it is seen and
	// refuses tools whose definition later changes (AISVS 10.4.8).
	PinTools bool
	// ValidateSchemas checks tools/call arguments against the tool's
	// inputSchema before forwarding (AISVS 10.4.3, 10.4.4) and structured
	// results against its outputSchema before returning them (10.4.1, 9.3.2).
	// Schemas with external or unresolved $ref, or beyond size limits, are
	// refused (10.4.13, 10.4.14, 10.4.15).
	ValidateSchemas bool
}

// Gateway is an http.Handler that guards one upstream MCP server.
type Gateway struct {
	opt     Options
	limiter *limiter
	Metrics *Metrics
	pins    *pinStore
}

func New(opt Options) *Gateway {
	if opt.MaxBodyBytes == 0 {
		opt.MaxBodyBytes = 1 << 20
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.Client == nil {
		opt.Client = &http.Client{} // no timeout: SSE streams are long-lived
	}
	return &Gateway{opt: opt, limiter: newLimiter(opt.RatePerMinute), Metrics: &Metrics{}, pins: newPinStore()}
}

type msg = map[string]any

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.Metrics.Requests.Add(1)
	if reason := g.checkTransport(r); reason != "" {
		g.opt.Logger.Warn("transport_rejected", "remote", r.RemoteAddr, "reason", reason)
		http.Error(w, reason, http.StatusForbidden)
		return
	}
	p, err := g.opt.Auth.Authenticate(r)
	if err != nil {
		g.Metrics.AuthFailures.Add(1)
		g.opt.Logger.Warn("auth_failed", "remote", r.RemoteAddr, "err", err.Error())
		w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-guard"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !g.limiter.allow(p.Subject) {
		g.Metrics.RateLimited.Add(1)
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	switch r.Method {
	case http.MethodPost:
		g.handlePost(w, r, p)
	case http.MethodGet, http.MethodDelete:
		// GET opens a server->client SSE stream; DELETE ends a session.
		g.forward(w, r, p, nil, nil)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (g *Gateway) handlePost(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	body, err := io.ReadAll(io.LimitReader(r.Body, g.opt.MaxBodyBytes+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > g.opt.MaxBodyBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	msgs, batch, err := decodeMessages(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, rpcError(nil, codeParseError, "parse error"))
		return
	}

	var denials []msg
	deniedAny := false
	outSchemas := map[string]map[string]any{} // rpc id -> outputSchema
	for _, m := range msgs {
		dec, kind, target := g.authorize(p, m)
		if dec.Allowed && kind == policy.Tool && (g.opt.PinTools || g.opt.ValidateSchemas) {
			dec = g.checkTool(r, m, target, outSchemas)
		}
		counts := redact.Counts{}
		if dec.Allowed && g.opt.RedactRequests {
			g.redactRequest(m, counts)
		}
		g.audit(p, m, kind, target, dec, counts, "request")
		if !dec.Allowed {
			deniedAny = true
			g.Metrics.Denied.Add(1)
			if id, ok := m["id"]; ok {
				denials = append(denials, rpcError(id, codeForbidden, "Forbidden by MCP Guard: "+dec.Reason))
			}
		}
	}
	// Any denial rejects the whole batch: partial forwarding would let a
	// caller probe policy and complicates response correlation.
	if deniedAny {
		if len(denials) == 0 {
			w.WriteHeader(http.StatusAccepted) // denied notifications only
			return
		}
		if batch {
			writeJSON(w, http.StatusOK, denials)
		} else {
			writeJSON(w, http.StatusOK, denials[0])
		}
		return
	}

	var out []byte
	if batch {
		out, _ = json.Marshal(msgs)
	} else {
		out, _ = json.Marshal(msgs[0])
	}
	g.forward(w, r, p, out, outSchemas)
}

// checkTool runs the definition-dependent checks for one tools/call: the
// pin (10.4.8) and argument validation (10.4.3, 10.4.4). It records the
// tool's outputSchema so the result can be validated on the way back.
func (g *Gateway) checkTool(r *http.Request, m msg, name string, outSchemas map[string]map[string]any) policy.Decision {
	def, reason := g.fetchTool(r, name)
	if reason != "" {
		return policy.Decision{Allowed: false, Reason: reason}
	}
	if g.opt.PinTools && !g.pins.observe(name, toolHash(def)) {
		return policy.Decision{Allowed: false, Reason: "tool definition changed since it was approved; re-approval required"}
	}
	if !g.opt.ValidateSchemas {
		return policy.Decision{Allowed: true, Reason: "allowed"}
	}
	in, _ := def["inputSchema"].(map[string]any)
	if in == nil {
		return policy.Decision{Allowed: false, Reason: "tool declares no inputSchema"}
	}
	params, _ := m["params"].(map[string]any)
	args, ok := params["arguments"]
	if !ok {
		args = map[string]any{}
	}
	if err := schema.Validate(in, args, schema.DefaultLimits); err != nil {
		return policy.Decision{Allowed: false, Reason: "arguments rejected: " + err.Error()}
	}
	if out, ok := def["outputSchema"].(map[string]any); ok {
		if err := schema.Check(out, schema.DefaultLimits); err != nil {
			return policy.Decision{Allowed: false, Reason: "output schema rejected: " + err.Error()}
		}
		if id, ok := m["id"]; ok {
			outSchemas[fmt.Sprint(id)] = out
		}
	}
	return policy.Decision{Allowed: true, Reason: "allowed"}
}

// authorize returns the policy decision for a single client->server message.
func (g *Gateway) authorize(p *auth.Principal, m msg) (policy.Decision, policy.Kind, string) {
	method, _ := m["method"].(string)
	if method == "" {
		// A response to a server-initiated request (sampling, elicitation).
		return policy.Decision{Allowed: true, Reason: "client response"}, "", ""
	}
	params, _ := m["params"].(map[string]any)
	str := func(k string) string { s, _ := params[k].(string); return s }

	switch method {
	case "tools/call":
		args, _ := params["arguments"].(map[string]any)
		return g.opt.Policy.CheckCall(p.Roles, str("name"), args), policy.Tool, str("name")
	case "resources/read", "resources/subscribe", "resources/unsubscribe":
		return g.opt.Policy.Check(p.Roles, policy.Resource, str("uri")), policy.Resource, str("uri")
	case "prompts/get":
		return g.opt.Policy.Check(p.Roles, policy.Prompt, str("name")), policy.Prompt, str("name")
	}
	if safeMethods[method] || strings.HasPrefix(method, "notifications/") {
		return policy.Decision{Allowed: true, Reason: "safe method"}, "", ""
	}
	return policy.Decision{Allowed: false, Reason: "method not permitted: " + method}, "", ""
}

func (g *Gateway) redactRequest(m msg, c redact.Counts) {
	if g.opt.Redactor == nil {
		return
	}
	params, ok := m["params"].(map[string]any)
	if !ok {
		return
	}
	if args, ok := params["arguments"]; ok {
		params["arguments"] = g.opt.Redactor.Value(args, c)
	}
	g.Metrics.Redactions.Add(int64(c.Total()))
}

// processResponse filters list results by policy and redacts payloads.
func (g *Gateway) processResponse(p *auth.Principal, m msg, outSchemas map[string]map[string]any) {
	if out, ok := outSchemas[fmt.Sprint(m["id"])]; ok {
		if reason := checkResult(m, out); reason != "" {
			g.opt.Logger.Warn("tool_result_rejected", "subject", p.Subject, "reason", reason)
			delete(m, "result")
			m["error"] = map[string]any{"code": codeBadResult, "message": "Tool result rejected by MCP Guard: " + reason}
		}
	}
	if res, ok := m["result"].(map[string]any); ok {
		if g.opt.PinTools {
			g.dropChangedTools(res)
		}
		g.filterList(p, res, "tools", "name", policy.Tool)
		g.filterList(p, res, "resources", "uri", policy.Resource)
		g.filterList(p, res, "prompts", "name", policy.Prompt)
		if g.opt.ScreenInjection {
			if n := screenResult(res); n > 0 {
				g.opt.Logger.Warn("injection_screened", "subject", p.Subject, "items", n)
			}
		}
	}
	if !g.opt.RedactResponses || g.opt.Redactor == nil {
		return
	}
	c := redact.Counts{}
	for _, k := range []string{"result", "params", "error"} {
		if v, ok := m[k]; ok {
			m[k] = g.opt.Redactor.Value(v, c)
		}
	}
	if c.Total() > 0 {
		g.Metrics.Redactions.Add(int64(c.Total()))
		g.audit(p, m, "", "", policy.Decision{Allowed: true, Reason: "response"}, c, "response")
	}
}

// filterList hides capabilities the caller cannot use, so the model never
// sees (and cannot be steered toward) tools outside its grant.
func (g *Gateway) filterList(p *auth.Principal, res map[string]any, key, field string, kind policy.Kind) {
	items, ok := res[key].([]any)
	if !ok {
		return
	}
	kept := make([]any, 0, len(items))
	for _, it := range items {
		obj, _ := it.(map[string]any)
		name, _ := obj[field].(string)
		if g.opt.Policy.Check(p.Roles, kind, name).Allowed {
			kept = append(kept, it)
		}
	}
	res[key] = kept
}

var forwardHeaders = []string{"Accept", "Content-Type", "Mcp-Session-Id", "Mcp-Protocol-Version", "Last-Event-Id"}

// checkResult validates a tools/call result against the tool's outputSchema.
// A tool that declares one must return conforming structuredContent.
func checkResult(m msg, out map[string]any) string {
	res, ok := m["result"].(map[string]any)
	if !ok {
		return ""
	}
	if isErr, _ := res["isError"].(bool); isErr {
		return ""
	}
	sc, ok := res["structuredContent"]
	if !ok {
		return "missing structuredContent required by outputSchema"
	}
	if err := schema.Validate(out, sc, schema.DefaultLimits); err != nil {
		return "structuredContent does not match outputSchema: " + err.Error()
	}
	return ""
}

func (g *Gateway) forward(w http.ResponseWriter, r *http.Request, p *auth.Principal, body []byte, outSchemas map[string]map[string]any) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, g.opt.Upstream.String(), rd)
	if err != nil {
		http.Error(w, "bad upstream", http.StatusInternalServerError)
		return
	}
	for _, h := range forwardHeaders {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	// Client credentials are never passed through to the upstream server.
	if g.opt.UpstreamAuthHeader != "" {
		req.Header.Set("Authorization", g.opt.UpstreamAuthHeader)
	}
	req.Header.Set("X-MCP-Guard-Subject", p.Subject)

	resp, err := g.opt.Client.Do(req)
	if err != nil {
		g.Metrics.UpstreamErrors.Add(1)
		g.opt.Logger.Error("upstream_error", "err", err.Error())
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		if k == "Content-Length" || k == "Connection" || k == "Transfer-Encoding" {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	ct := resp.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "text/event-stream"):
		w.WriteHeader(resp.StatusCode)
		g.streamSSE(w, resp.Body, p, outSchemas)
	case strings.HasPrefix(ct, "application/json"):
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "upstream read error", http.StatusBadGateway)
			return
		}
		w.WriteHeader(resp.StatusCode)
		w.Write(g.rewriteJSON(p, raw, outSchemas))
	default:
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

func (g *Gateway) rewriteJSON(p *auth.Principal, raw []byte, outSchemas map[string]map[string]any) []byte {
	if len(bytes.TrimSpace(raw)) == 0 {
		return raw
	}
	msgs, batch, err := decodeMessages(raw)
	if err != nil {
		// Not JSON-RPC; redact as plain text to stay fail-safe.
		if g.opt.RedactResponses && g.opt.Redactor != nil {
			return []byte(g.opt.Redactor.String(string(raw), redact.Counts{}))
		}
		return raw
	}
	for _, m := range msgs {
		g.processResponse(p, m, outSchemas)
	}
	var out []byte
	if batch {
		out, _ = json.Marshal(msgs)
	} else {
		out, _ = json.Marshal(msgs[0])
	}
	return out
}

// streamSSE rewrites each SSE event's data payload while preserving
// event ids (for resumability) and flushing per event.
func (g *Gateway) streamSSE(w http.ResponseWriter, body io.Reader, p *auth.Principal, outSchemas map[string]map[string]any) {
	fl, _ := w.(http.Flusher)
	br := bufio.NewReaderSize(body, 64*1024)
	var fields []string
	var data []string
	emit := func() {
		if len(fields) == 0 && len(data) == 0 {
			return
		}
		var b strings.Builder
		for _, f := range fields {
			b.WriteString(f + "\n")
		}
		if len(data) > 0 {
			payload := g.rewriteJSON(p, []byte(strings.Join(data, "\n")), outSchemas)
			for _, line := range strings.Split(string(payload), "\n") {
				b.WriteString("data: " + line + "\n")
			}
		}
		b.WriteString("\n")
		io.WriteString(w, b.String())
		if fl != nil {
			fl.Flush()
		}
		fields, data = nil, nil
	}
	for {
		line, err := br.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line == "" && err == nil {
			emit()
			continue
		}
		if line != "" {
			if v, ok := strings.CutPrefix(line, "data:"); ok {
				data = append(data, strings.TrimPrefix(v, " "))
			} else {
				fields = append(fields, line)
			}
		}
		if err != nil {
			emit()
			if !errors.Is(err, io.EOF) {
				g.opt.Logger.Warn("sse_read_error", "err", err.Error())
			}
			return
		}
	}
}

func (g *Gateway) audit(p *auth.Principal, m msg, kind policy.Kind, target string, d policy.Decision, c redact.Counts, dir string) {
	method, _ := m["method"].(string)
	attrs := []any{
		"direction", dir,
		"subject", p.Subject,
		"roles", p.Roles,
		"auth", p.Method,
		"method", method,
		"allowed", d.Allowed,
		"reason", d.Reason,
	}
	if id, ok := m["id"]; ok {
		attrs = append(attrs, "rpc_id", fmt.Sprint(id))
	}
	if kind != "" {
		attrs = append(attrs, "kind", string(kind), "target", target)
	}
	if c.Total() > 0 {
		attrs = append(attrs, "redactions", map[string]int(c))
	}
	g.opt.Logger.Info("mcp_audit", attrs...)
}

func decodeMessages(b []byte) ([]msg, bool, error) {
	b = bytes.TrimSpace(b)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber() // preserve numeric ids exactly
	if len(b) > 0 && b[0] == '[' {
		var arr []msg
		if err := dec.Decode(&arr); err != nil {
			return nil, true, err
		}
		if len(arr) == 0 {
			return nil, true, errors.New("empty batch")
		}
		return arr, true, nil
	}
	var m msg
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, false, errors.New("invalid message")
	}
	return []msg{m}, false, nil
}

func rpcError(id any, code int, message string) msg {
	return msg{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
