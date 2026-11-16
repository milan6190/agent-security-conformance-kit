// Package refgw is the kit's known-good reference target: a small MCP
// security gateway that is expected to pass every v0.1 protocol test.
// It exists to validate the tests, not as a production gateway.
package refgw

import (
	"log/slog"
	"net/http"

	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw/auth"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw/config"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw/proxy"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw/redact"
)

// Handler builds the gateway's HTTP handler from a loaded config.
func Handler(cfg *config.Config, log *slog.Logger) (http.Handler, error) {
	red, err := redact.New(cfg.Redaction.Detectors, cfg.Redaction.Custom)
	if err != nil {
		return nil, err
	}
	gw := proxy.New(proxy.Options{
		Upstream:           cfg.UpstreamURL,
		UpstreamAuthHeader: cfg.UpstreamAuthHeader,
		Auth:               auth.New(cfg.Auth.Config),
		Policy:             &cfg.Policy,
		Redactor:           red,
		RedactRequests:     cfg.Redaction.Requests,
		RedactResponses:    cfg.Redaction.Responses,
		MaxBodyBytes:       cfg.Limits.MaxBodyBytes,
		RatePerMinute:      cfg.Limits.RatePerMinute,
		Logger:             log,
		AllowedOrigins:     cfg.Hardening.AllowedOrigins,
		AllowedHosts:       cfg.Hardening.AllowedHosts,
		ScreenInjection:    cfg.Hardening.ScreenInjection,
		PinTools:           cfg.Hardening.PinTools,
	})
	mux := http.NewServeMux()
	mux.Handle("/mcp", gw)
	mux.Handle("GET /metrics", gw.Metrics)
	mux.HandleFunc("GET /healthz", proxy.Healthz)
	return mux, nil
}

// NaiveHandler is the known-bad reference target: a pass-through proxy with
// no authentication, authorization, screening or limits. It forwards the
// client's headers, including Authorization, unchanged.
func NaiveHandler(upstream string) http.Handler {
	client := &http.Client{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		req.Header = r.Header.Clone()
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	})
}
