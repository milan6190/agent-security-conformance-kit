// Command naive-proxy runs the kit's known-bad reference target: a
// pass-through MCP proxy with no security controls. Never deploy it.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/refgw"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8081", "listen address")
	upstream := flag.String("upstream", "http://127.0.0.1:9901/mcp", "upstream MCP endpoint")
	flag.Parse()
	mux := http.NewServeMux()
	mux.Handle("/mcp", refgw.NaiveHandler(*upstream))
	log.Printf("naive-proxy (INSECURE, for testing) on %s -> %s", *listen, *upstream)
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
