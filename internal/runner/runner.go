// Package runner executes conformance tests against a system under test,
// with the canary MCP server standing in as its upstream.
package runner

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/canary"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/spec"
)

// Status of a test.
type Status string

const (
	Pass  Status = "pass"
	Fail  Status = "fail"
	Skip  Status = "skip"
	Error Status = "error"
)

// StepResult records one step.
type StepResult struct {
	Name       string   `json:"name"`
	HTTPStatus int      `json:"http_status"`
	Failures   []string `json:"failures,omitempty"`
}

// TestResult records one test.
type TestResult struct {
	Test     spec.Test    `json:"-"`
	ID       string       `json:"id"`
	Title    string       `json:"title"`
	AISVS    []string     `json:"aisvs"`
	Risks    []string     `json:"risks"`
	Level    int          `json:"level"`
	Status   Status       `json:"status"`
	Reason   string       `json:"reason,omitempty"`
	Steps    []StepResult `json:"steps"`
	Duration string       `json:"duration"`
}

// Runner holds shared state for a run.
type Runner struct {
	Target *spec.Target
	Canary *canary.Server
	Client *http.Client
	now    func() time.Time
	// state is the last requestState the client received in this test.
	state string
}

// New builds a runner. The canary must already be started at Target.CanaryListen.
func New(t *spec.Target, c *canary.Server) *Runner {
	return &Runner{Target: t, Canary: c, Client: &http.Client{Timeout: 30 * time.Second}, now: time.Now}
}

// RunAll executes tests in order.
func (r *Runner) RunAll(tests []spec.Test) []TestResult {
	out := make([]TestResult, 0, len(tests))
	for _, t := range tests {
		out = append(out, r.Run(t))
	}
	return out
}

// Run executes one test.
func (r *Runner) Run(t spec.Test) TestResult {
	start := r.now()
	res := TestResult{Test: t, ID: t.ID, Title: t.Title, AISVS: t.AISVS, Risks: t.Risks, Level: t.Level, Status: Pass}
	defer func() { res.Duration = r.now().Sub(start).Round(time.Millisecond).String() }()

	if reason := r.unmet(t); reason != "" {
		res.Status, res.Reason = Skip, reason
		return res
	}
	r.Canary.Reset()
	r.state = ""
	for _, d := range t.Canary.Tools {
		r.Canary.AddTool(r.toolDef(d))
	}
	for tool, text := range t.Canary.Results {
		r.Canary.SetResult(tool, canary.Expand(text))
	}
	for tool, v := range t.Canary.Structured {
		r.Canary.SetStructured(tool, r.expandAny(v))
	}
	sessions := map[string]string{}

	for i, st := range t.Steps {
		name := st.Name
		if name == "" {
			name = fmt.Sprintf("step %d", i+1)
		}
		for tool, p := range st.CanaryMutate {
			schema, _ := r.expandAny(p.InputSchema).(map[string]any)
			r.Canary.PatchTool(tool, canary.Expand(p.Description), schema)
		}
		hdr, err := r.authHeaders(st.As)
		if err != nil {
			res.Status, res.Reason = Error, err.Error()
			return res
		}
		if _, ok := sessions[st.As]; !ok {
			sessions[st.As] = r.initialize(hdr)
		}
		before := len(r.Canary.Calls())
		resp, err := r.send(st, i+1, hdr, sessions[st.As])
		if err != nil {
			res.Status, res.Reason = Error, fmt.Sprintf("%s: %v", name, err)
			return res
		}
		if s := resp.requestState(); s != "" {
			r.state = s
		}
		delta := r.Canary.Calls()[before:]
		sr := StepResult{Name: name, HTTPStatus: resp.status, Failures: check(st.Expect, resp, delta, hdr)}
		res.Steps = append(res.Steps, sr)
		if len(sr.Failures) > 0 {
			res.Status = Fail
		}
	}
	return res
}

func (r *Runner) unmet(t spec.Test) string {
	for _, req := range t.Requires {
		switch {
		case req == "jwt":
			if r.Target.JWT == nil || r.Target.JWT.Secret == "" {
				return "needs target.jwt with a signing secret to mint test tokens"
			}
		case strings.HasPrefix(req, "principal:"):
			if _, ok := r.Target.Principals[strings.TrimPrefix(req, "principal:")]; !ok {
				return "needs principal " + strings.TrimPrefix(req, "principal:")
			}
		case strings.HasPrefix(req, "capability:"):
			if !r.Target.HasCapability(strings.TrimPrefix(req, "capability:")) {
				return "target does not declare " + req
			}
		default:
			return "unknown requirement " + req
		}
	}
	return ""
}

// authHeaders resolves "anonymous", "garbage", "<principal>" or
// "<principal>:<variant>" into request headers.
func (r *Runner) authHeaders(as string) (map[string]string, error) {
	switch as {
	case "", "anonymous":
		return map[string]string{}, nil
	case "garbage":
		return map[string]string{"Authorization": "Bearer not-a-real-token"}, nil
	}
	name, variant, _ := strings.Cut(as, ":")
	p, ok := r.Target.Principals[name]
	if !ok {
		return nil, fmt.Errorf("unknown principal %q", name)
	}
	if len(p.Claims) == 0 {
		if variant != "" {
			return nil, fmt.Errorf("variant %q needs a principal with claims", variant)
		}
		return copyMap(p.Headers), nil
	}
	if r.Target.JWT == nil || r.Target.JWT.Secret == "" {
		return nil, fmt.Errorf("principal %q uses claims but target.jwt has no secret", name)
	}
	j := r.Target.JWT
	c := map[string]any{"iss": j.Issuer, "aud": j.Audience, "iat": r.now().Unix(), "exp": r.now().Add(time.Hour).Unix()}
	for k, v := range p.Claims {
		c[k] = v
	}
	secret, alg := []byte(j.Secret), "HS256"
	switch variant {
	case "":
	case "expired":
		c["exp"] = r.now().Add(-time.Hour).Unix()
	case "wrong_audience":
		c["aud"] = "some-other-service"
	case "wrong_issuer":
		c["iss"] = "https://attacker.invalid"
	case "bad_signature":
		secret = []byte("asck-wrong-secret-asck-wrong-secret")
	case "alg_none":
		alg = "none"
	default:
		return nil, fmt.Errorf("unknown token variant %q", variant)
	}
	return map[string]string{"Authorization": "Bearer " + mint(alg, secret, c)}, nil
}

func (r *Runner) initialize(hdr map[string]string) string {
	body := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"asck","version":"0.1.0"}}}`
	req, err := http.NewRequest(http.MethodPost, r.Target.Endpoint, strings.NewReader(body))
	if err != nil {
		return ""
	}
	setHeaders(req, hdr, "")
	resp, err := r.Client.Do(req)
	if err != nil {
		return ""
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	sid := resp.Header.Get("Mcp-Session-Id")
	if resp.StatusCode < 300 {
		n, _ := http.NewRequest(http.MethodPost, r.Target.Endpoint, strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
		setHeaders(n, hdr, sid)
		if nr, err := r.Client.Do(n); err == nil {
			io.Copy(io.Discard, nr.Body)
			nr.Body.Close()
		}
	}
	return sid
}

type response struct {
	status int
	body   string
	msgs   []map[string]any
}

func (r *Runner) send(st spec.Step, id int, hdr map[string]string, session string) (*response, error) {
	msg := map[string]any{"jsonrpc": "2.0", "id": id}
	for k, v := range st.RPC {
		msg[k] = r.expandAny(v)
	}
	if len(st.ArgBytes) > 0 {
		params, _ := msg["params"].(map[string]any)
		if params == nil {
			params = map[string]any{}
			msg["params"] = params
		}
		args, _ := params["arguments"].(map[string]any)
		if args == nil {
			args = map[string]any{}
			params["arguments"] = args
		}
		for k, n := range st.ArgBytes {
			args[k] = strings.Repeat("A", n)
		}
	}
	if st.PadBytes > 0 {
		msg["_asck_pad"] = strings.Repeat("A", st.PadBytes)
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, r.Target.Endpoint, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	setHeaders(req, hdr, session)
	if st.MirrorHeaders {
		for k, v := range r.mirrored(msg) {
			req.Header.Set(k, v)
		}
	}
	for k, v := range st.Headers {
		if strings.EqualFold(k, "Host") {
			req.Host = r.expand(v) // net/http ignores a Host entry in Header
			continue
		}
		req.Header.Set(k, r.expand(v))
	}
	for _, k := range st.OmitHeaders {
		req.Header.Del(k)
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	out := &response{status: resp.StatusCode, body: string(raw)}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			if d, ok := strings.CutPrefix(sc.Text(), "data:"); ok {
				out.msgs = append(out.msgs, decode(strings.TrimSpace(d))...)
			}
		}
	} else {
		out.msgs = decode(string(raw))
	}
	return out, nil
}

func setHeaders(req *http.Request, hdr map[string]string, session string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
}

func decode(s string) []map[string]any {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if s[0] == '[' {
		var arr []map[string]any
		if json.Unmarshal([]byte(s), &arr) == nil {
			return arr
		}
		return nil
	}
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) == nil {
		return []map[string]any{m}
	}
	return nil
}

func (resp *response) rpcError() bool {
	for _, m := range resp.msgs {
		if _, ok := m["error"]; ok {
			return true
		}
	}
	return false
}

func (resp *response) requestState() string {
	for _, m := range resp.msgs {
		res, _ := m["result"].(map[string]any)
		if s, ok := res["requestState"].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func (resp *response) toolNames() ([]string, bool) {
	var names []string
	found := false
	for _, m := range resp.msgs {
		res, _ := m["result"].(map[string]any)
		tools, ok := res["tools"].([]any)
		if !ok {
			continue
		}
		found = true
		for _, t := range tools {
			if o, ok := t.(map[string]any); ok {
				if n, ok := o["name"].(string); ok {
					names = append(names, n)
				}
			}
		}
	}
	return names, found
}

func check(e spec.Expect, resp *response, delta []canary.Call, hdr map[string]string) []string {
	var f []string
	blocked := resp.status >= 400 || resp.rpcError()
	if e.Blocked != nil && *e.Blocked != blocked {
		f = append(f, fmt.Sprintf("expected blocked=%v, got HTTP %d, rpc error=%v", *e.Blocked, resp.status, resp.rpcError()))
	}
	if e.HTTPError && resp.status < 400 {
		f = append(f, fmt.Sprintf("expected an HTTP error status, got HTTP %d", resp.status))
	}
	if e.Allowed != nil && *e.Allowed == blocked {
		f = append(f, fmt.Sprintf("expected allowed=%v, got HTTP %d, rpc error=%v", *e.Allowed, resp.status, resp.rpcError()))
	}
	called := map[string]bool{}
	for _, c := range delta {
		if c.Method == "tools/call" {
			called[c.Tool] = true
		}
	}
	for _, t := range e.CanaryCalled {
		if !called[t] {
			f = append(f, "expected canary tool "+t+" to be called, it was not")
		}
	}
	for _, t := range e.CanaryNotCalled {
		if called[t] {
			f = append(f, "canary tool "+t+" was called but should have been blocked before reaching it")
		}
	}
	for _, s := range e.CanaryReceivedContains {
		s = canary.Expand(s)
		found := false
		for _, c := range delta {
			if strings.Contains(c.Raw, s) {
				found = true
				break
			}
		}
		if !found {
			f = append(f, fmt.Sprintf("canary did not receive %q", s))
		}
	}
	for _, s := range e.CanaryReceivedNotContains {
		s = canary.Expand(s)
		for _, c := range delta {
			if strings.Contains(c.Raw, s) || headerContains(c.Headers, s) {
				f = append(f, fmt.Sprintf("canary received %q in a %s request", s, c.Method))
				break
			}
		}
	}
	if e.CanaryNoFetch {
		for _, c := range delta {
			if c.Method == canary.MethodFetch {
				f = append(f, "the canary received a non-MCP fetch: "+c.Raw)
				break
			}
		}
	}
	if e.CanaryAuthNotClientToken {
		if tok := hdr["Authorization"]; tok != "" {
			bare := strings.TrimPrefix(tok, "Bearer ")
			for _, c := range delta {
				if headerContains(c.Headers, bare) {
					f = append(f, "the client's token was passed through to the upstream MCP server")
					break
				}
			}
		}
	}
	for _, s := range e.ResponseContains {
		if !strings.Contains(resp.body, canary.Expand(s)) {
			f = append(f, fmt.Sprintf("response does not contain %q", canary.Expand(s)))
		}
	}
	for _, s := range e.ResponseNotContains {
		if strings.Contains(resp.body, canary.Expand(s)) {
			f = append(f, fmt.Sprintf("response contains %q", canary.Expand(s)))
		}
	}
	names, listed := resp.toolNames()
	for _, t := range e.ToolsListIncludes {
		if !slices.Contains(names, t) {
			f = append(f, "tools/list does not include "+t)
		}
	}
	for _, t := range e.ToolsListExcludes {
		if !listed {
			f = append(f, "no tools/list result to check")
			break
		}
		if slices.Contains(names, t) {
			f = append(f, "tools/list exposes "+t+" to a caller not authorized for it")
		}
	}
	for _, t := range e.BlockedOrExcludes {
		if !blocked && slices.Contains(names, t) {
			f = append(f, "tool "+t+" is still offered without blocking or re-approval")
		}
	}
	return f
}

func headerContains(h map[string][]string, s string) bool {
	for _, vs := range h {
		for _, v := range vs {
			if strings.Contains(v, s) {
				return true
			}
		}
	}
	return false
}

// expand replaces ${canary.*} placeholders, including ${canary.base_url},
// the running canary's root URL, and ${state.last} / ${state.tampered}, the
// last requestState the client received and a one-character alteration of it.
func (r *Runner) expand(s string) string {
	return strings.NewReplacer(
		"${canary.base_url}", r.Canary.BaseURL(),
		"${state.last}", r.state,
		"${state.tampered}", tamper(r.state),
	).Replace(canary.Expand(s))
}

// tamper changes one character in the middle of s.
func tamper(s string) string {
	if s == "" {
		return "asck-tampered"
	}
	b := []byte(s)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// ProtocolMirrored is the first MCP revision that requires mirrored headers.
const ProtocolMirrored = "2026-07-28"

// mirrored computes the SEP-2243 headers a conforming client sends for msg.
func (r *Runner) mirrored(msg map[string]any) map[string]string {
	h := map[string]string{"MCP-Protocol-Version": ProtocolMirrored}
	method, _ := msg["method"].(string)
	h["Mcp-Method"] = method
	params, _ := msg["params"].(map[string]any)
	switch method {
	case "tools/call", "prompts/get":
		if n, ok := params["name"].(string); ok {
			h["Mcp-Name"] = n
		}
	case "resources/read":
		if u, ok := params["uri"].(string); ok {
			h["Mcp-Name"] = u
		}
	}
	if method != "tools/call" {
		return h
	}
	name, _ := params["name"].(string)
	args, _ := params["arguments"].(map[string]any)
	for _, t := range r.Canary.Tools() {
		if t.Name != name {
			continue
		}
		props, _ := t.InputSchema["properties"].(map[string]any)
		for prop, ps := range props {
			hn, _ := ps.(map[string]any)["x-mcp-header"].(string)
			v, ok := args[prop]
			if hn == "" || !ok || v == nil {
				continue
			}
			h["Mcp-Param-"+hn] = EncodeHeaderValue(v)
		}
	}
	return h
}

// EncodeHeaderValue applies the SEP-2243 value encoding rules.
func EncodeHeaderValue(v any) string {
	switch t := v.(type) {
	case bool:
		if t {
			return "true"
		}
		return "false"
	case string:
		if headerSafe(t) {
			return t
		}
		return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(t)) + "?="
	}
	return fmt.Sprint(v)
}

func headerSafe(s string) bool {
	if !utf8.ValidString(s) || strings.HasPrefix(s, "=?base64?") && strings.HasSuffix(s, "?=") {
		return false
	}
	if s != strings.Trim(s, " \t") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != ' ' && (c < 0x21 || c > 0x7e) {
			return false
		}
	}
	return true
}

func (r *Runner) expandAny(v any) any {
	switch t := v.(type) {
	case string:
		return r.expand(t)
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			out[k] = r.expandAny(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = r.expandAny(x)
		}
		return out
	}
	return v
}

// toolDef turns a test-scoped tool definition into a canary tool.
func (r *Runner) toolDef(d spec.ToolDef) canary.Tool {
	t := canary.Tool{Name: d.Name, Description: canary.Expand(d.Description)}
	if t.Description == "" {
		t.Description = "Test-scoped tool."
	}
	t.InputRequired = d.InputRequired
	t.InputSchema, _ = r.expandAny(d.InputSchema).(map[string]any)
	t.OutputSchema, _ = r.expandAny(d.OutputSchema).(map[string]any)
	if d.NestedSchemaDepth > 0 {
		t.InputSchema = nestedSchema(d.NestedSchemaDepth)
	}
	if t.InputSchema == nil {
		t.InputSchema = map[string]any{"type": "object"}
	}
	return t
}

// nestedSchema builds {"type":"object","properties":{"a":{...}}} depth levels deep.
func nestedSchema(depth int) map[string]any {
	s := map[string]any{"type": "string"}
	for range depth {
		s = map[string]any{"type": "object", "properties": map[string]any{"a": s}}
	}
	return s
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func mint(alg string, secret []byte, claims map[string]any) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + alg + `","typ":"JWT"}`))
	b, _ := json.Marshal(claims)
	p := base64.RawURLEncoding.EncodeToString(b)
	if alg == "none" {
		return h + "." + p + "."
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(h + "." + p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
