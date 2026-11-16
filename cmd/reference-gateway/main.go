// Command reference-gateway runs the kit's known-good reference target.
package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw/config"
)

func main() {
	path := flag.String("config", "targets/reference-gateway/config.json", "gateway config (JSON)")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "reference-gateway")
	cfg, err := config.Load(*path)
	if err != nil {
		log.Error("config", "err", err.Error())
		os.Exit(1)
	}
	h, err := refgw.Handler(cfg, log)
	if err != nil {
		log.Error("init", "err", err.Error())
		os.Exit(1)
	}
	log.Info("listening", "addr", cfg.Listen, "upstream", cfg.UpstreamURL.String())
	srv := &http.Server{Addr: cfg.Listen, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Error("server", "err", err.Error())
		os.Exit(1)
	}
}
