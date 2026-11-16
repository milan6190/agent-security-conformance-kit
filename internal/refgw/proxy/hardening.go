package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// checkTransport validates Origin and Host independently (AISVS 10.3.3).
func (g *Gateway) checkTransport(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" && !slices.Contains(g.opt.AllowedOrigins, o) {
		return "origin not allowed"
	}
	if len(g.opt.AllowedHosts) > 0 && !slices.Contains(g.opt.AllowedHosts, r.Host) {
		return "host not allowed"
	}
	return ""
}

// --- Tool definition pinning (AISVS 10.4.8) ---

type pinStore struct {
	mu   sync.Mutex
	pins map[string]string
}

func newPinStore() *pinStore { return &pinStore{pins: map[string]string{}} }

// observe pins a first-seen definition and reports whether it still matches.
func (s *pinStore) observe(name, hash string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	pinned, ok := s.pins[name]
	if !ok {
		s.pins[name] = hash
		return true
	}
	return pinned == hash
}

func toolHash(tool map[string]any) string {
	b, _ := json.Marshal(map[string]any{
		"description": tool["description"],
		"inputSchema": tool["inputSchema"],
		"annotations": tool["annotations"],
	})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// dropChangedTools removes tools whose definition differs from the pin.
func (g *Gateway) dropChangedTools(res map[string]any) {
	items, ok := res["tools"].([]any)
	if !ok {
		return
	}
	kept := items[:0:0]
	for _, it := range items {
		obj, _ := it.(map[string]any)
		name, _ := obj["name"].(string)
		if g.pins.observe(name, toolHash(obj)) {
			kept = append(kept, it)
		} else {
			g.opt.Logger.Warn("tool_definition_changed", "tool", name)
		}
	}
	res["tools"] = kept
}

// verifyPinned fetches the upstream definition of a tool before it is
// invoked, so a definition swapped after approval cannot be called even if
// the client never re-lists tools.
func (g *Gateway) verifyPinned(r *http.Request, name string) string {
	body := []byte(`{"jsonrpc":"2.0","id":"mcp-guard-pin","method":"tools/list"}`)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, g.opt.Upstream.String(), bytes.NewReader(body))
	if err != nil {
		return "tool definition check failed"
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	if g.opt.UpstreamAuthHeader != "" {
		req.Header.Set("Authorization", g.opt.UpstreamAuthHeader)
	}
	resp, err := g.opt.Client.Do(req)
	if err != nil {
		return "tool definition check failed"
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		for _, line := range strings.Split(string(raw), "\n") {
			if d, ok := strings.CutPrefix(line, "data:"); ok {
				raw = []byte(strings.TrimSpace(d))
				break
			}
		}
	}
	var m struct {
		Result struct {
			Tools []map[string]any `json:"tools"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return "tool definition check failed"
	}
	for _, t := range m.Result.Tools {
		if t["name"] == name {
			if !g.pins.observe(name, toolHash(t)) {
				return "tool definition changed since it was approved; re-approval required"
			}
			return ""
		}
	}
	return "tool not offered by upstream"
}

// --- Prompt-injection screening (AISVS 10.4.2) ---

var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore (all |any )?(previous|prior|above) (instructions|prompts)`),
	regexp.MustCompile(`(?i)disregard (all |any )?(previous|prior|your) (instructions|rules)`),
	regexp.MustCompile(`(?i)<\s*(important|system|instructions?)\s*>`),
	regexp.MustCompile(`(?i)you (must|should) now (call|invoke|run|use) `),
	regexp.MustCompile(`(?i)do not (tell|inform|mention (this )?to) the user`),
}

func looksInjected(s string) bool {
	for _, re := range injectionPatterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

const withheld = "[withheld by gateway: possible prompt injection]"

// screenResult replaces suspicious text content and drops tools whose
// descriptions carry instructions. It is a heuristic baseline, not a
// guarantee; it exists so the reference target meets AISVS 10.4.2.
func screenResult(res map[string]any) int {
	n := 0
	if content, ok := res["content"].([]any); ok {
		for _, c := range content {
			if obj, ok := c.(map[string]any); ok {
				if txt, ok := obj["text"].(string); ok && looksInjected(txt) {
					obj["text"] = withheld
					n++
				}
			}
		}
	}
	if items, ok := res["tools"].([]any); ok {
		kept := items[:0:0]
		for _, it := range items {
			obj, _ := it.(map[string]any)
			d, _ := obj["description"].(string)
			if looksInjected(d) {
				n++
				continue
			}
			kept = append(kept, it)
		}
		res["tools"] = kept
	}
	return n
}
