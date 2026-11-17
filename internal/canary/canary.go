// Package canary is an instrumented MCP server. Every request it receives
// is recorded, so tests can judge what actually reached the tools instead of
// what a model or gateway claims happened.
package canary

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Seeded secrets. Tests check that these never cross the boundary they
// shouldn't. They match common detector formats but are not real credentials.
const (
	SecretAWSKey      = "AKIAASCKCANARY000001"
	SecretGitHubToken = "ghp_ASCKcanaryTOKEN0000000000000000000001"
	SecretEmail       = "canary.user@asck.invalid"
	InjectionMarker   = "ASCK-INJECTION-7f3a"
)

// MaxArgLength is the maxLength declared for every default tool argument.
const MaxArgLength = 4096

// Tool is a canary tool definition.
type Tool struct {
	Name         string         `json:"name"`
	Description  string         `json:"description"`
	InputSchema  map[string]any `json:"inputSchema"`
	OutputSchema map[string]any `json:"outputSchema,omitempty"`
}

// DefaultTools is the fixed catalog the target contract refers to
// (see docs/target-contract.md).
func DefaultTools() []Tool {
	// Strict schemas: one required string argument, bounded in length, and
	// no other properties. Gateways that validate arguments (AISVS 10.4.3,
	// 10.4.4) enforce these; the canary itself accepts anything.
	obj := func(props ...string) map[string]any {
		p := map[string]any{}
		for _, n := range props {
			p[n] = map[string]any{"type": "string", "maxLength": MaxArgLength}
		}
		return map[string]any{"type": "object", "properties": p, "required": props, "additionalProperties": false}
	}
	return []Tool{
		{Name: "search_docs", Description: "Search internal documentation.", InputSchema: obj("query")},
		{Name: "read_file", Description: "Read a file from the docs share.", InputSchema: obj("path")},
		{Name: "delete_repo", Description: "Delete a source repository.", InputSchema: obj("repo")},
		{Name: "admin_reset", Description: "Reset all user sessions.", InputSchema: obj("scope")},
	}
}

// Call is one recorded request.
type Call struct {
	Method  string          `json:"method"`
	Tool    string          `json:"tool,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Auth    string          `json:"authorization,omitempty"`
	Headers http.Header     `json:"headers,omitempty"`
	Raw     string          `json:"raw"`
}

// MethodFetch marks a non-MCP HTTP request, such as a validator resolving a
// remote JSON Schema $ref against the canary.
const MethodFetch = "http-fetch"

// Server is the canary MCP server.
type Server struct {
	mu         sync.Mutex
	tools      []Tool
	results    map[string]string
	structured map[string]any
	calls      []Call
	baseURL    string
	srv        *http.Server
	ln         net.Listener
}

// New creates a server with the default tool catalog.
func New() *Server {
	s := &Server{}
	s.Reset()
	return s
}

// Reset restores default tools and results and clears the call log.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools = DefaultTools()
	s.results = map[string]string{}
	s.structured = map[string]any{}
	s.calls = nil
}

// AddTool adds a test-scoped tool, replacing any tool with the same name.
func (s *Server) AddTool(t Tool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.tools {
		if s.tools[i].Name == t.Name {
			s.tools[i] = t
			return
		}
	}
	s.tools = append(s.tools, t)
}

// SetStructured sets the structuredContent a tool returns. Unless SetResult
// overrides it, the text content becomes the JSON encoding of v.
func (s *Server) SetStructured(tool string, v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.structured[tool] = v
}

// BaseURL is the canary's root URL, e.g. http://127.0.0.1:9901 (empty
// before Start).
func (s *Server) BaseURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.baseURL
}

// SetResult overrides the text returned by a tool.
func (s *Server) SetResult(tool, text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[tool] = text
}

// PatchTool changes a tool's description and, if inputSchema is non-nil,
// its input schema (simulates a "rug pull").
func (s *Server) PatchTool(name, description string, inputSchema map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.tools {
		if s.tools[i].Name == name {
			if description != "" {
				s.tools[i].Description = description
			}
			if inputSchema != nil {
				s.tools[i].InputSchema = inputSchema
			}
		}
	}
}

// Calls returns a copy of the call log.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}

// ToolCalls returns the names of tools invoked via tools/call.
func (s *Server) ToolCalls() []string {
	var out []string
	for _, c := range s.Calls() {
		if c.Method == "tools/call" {
			out = append(out, c.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// Start listens on addr ("127.0.0.1:0" picks a free port).
func (s *Server) Start(addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	s.ln = ln
	s.mu.Lock()
	s.baseURL = "http://" + ln.Addr().String()
	s.mu.Unlock()
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", s.handle)
	mux.HandleFunc("/", s.handleFetch)
	s.srv = &http.Server{Handler: mux}
	go s.srv.Serve(ln)
	return "http://" + ln.Addr().String() + "/mcp", nil
}

// handleFetch records any non-MCP request and answers with a permissive
// JSON Schema, so a validator that resolves a remote $ref here would end up
// accepting anything.
func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.calls = append(s.calls, Call{Method: MethodFetch, Headers: r.Header.Clone(), Raw: r.Method + " " + r.URL.RequestURI()})
	s.mu.Unlock()
	writeJSON(w, map[string]any{})
}

// Close stops the server.
func (s *Server) Close() error {
	if s.srv != nil {
		return s.srv.Close()
	}
	return nil
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	_ = json.Unmarshal(body, &msg)

	call := Call{Method: msg.Method, Params: msg.Params, Auth: r.Header.Get("Authorization"), Headers: r.Header.Clone(), Raw: string(body)}
	if msg.Method == "tools/call" {
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(msg.Params, &p)
		call.Tool = p.Name
	}
	s.mu.Lock()
	s.calls = append(s.calls, call)
	tools := append([]Tool(nil), s.tools...)
	result, hasResult := s.results[call.Tool]
	structured, hasStructured := s.structured[call.Tool]
	s.mu.Unlock()

	if len(msg.ID) == 0 { // notification
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var res any
	switch msg.Method {
	case "initialize":
		res = map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "asck-canary", "version": "0.1.0"},
		}
	case "ping":
		res = map[string]any{}
	case "tools/list":
		res = map[string]any{"tools": tools}
	case "tools/call":
		if !hasResult {
			result = "ok: " + call.Tool + " executed"
			if hasStructured {
				b, _ := json.Marshal(structured)
				result = string(b)
			}
		}
		out := map[string]any{"content": []any{map[string]any{"type": "text", "text": result}}}
		if hasStructured {
			out["structuredContent"] = structured
		}
		res = out
	default:
		writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": msg.ID, "error": map[string]any{"code": -32601, "message": "method not found"}})
		return
	}
	writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": res})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// Expand replaces ${canary.*} placeholders in test text with seeded values.
func Expand(s string) string {
	return strings.NewReplacer(
		"${canary.aws_key}", SecretAWSKey,
		"${canary.github_token}", SecretGitHubToken,
		"${canary.email}", SecretEmail,
		"${canary.injection_marker}", InjectionMarker,
	).Replace(s)
}
