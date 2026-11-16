// Command asck runs the OWASP Agentic Security Conformance Kit.
//
//	asck run -target targets/my-gateway.yaml -tests tests/ -out reports/
//	asck list -tests tests/
//	asck canary -listen 127.0.0.1:9901
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/aisvs"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/canary"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/report"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/runner"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/spec"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "list":
		err = cmdList(os.Args[2:])
	case "canary":
		err = cmdCanary(os.Args[2:])
	case "version":
		fmt.Printf("asck %s (AISVS %s)\n", report.Version, aisvs.Version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "asck:", err)
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: asck run|list|canary|version [flags]")
	os.Exit(2)
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	targetPath := fs.String("target", "", "target profile (YAML)")
	testsDir := fs.String("tests", "tests", "directory of test cases")
	outDir := fs.String("out", "asck-report", "output directory for report.json, report.sarif, report.md")
	only := fs.String("only", "", "comma-separated test ID prefixes to run")
	fs.Parse(args)
	if *targetPath == "" {
		return fmt.Errorf("-target is required")
	}
	target, err := spec.LoadTarget(*targetPath)
	if err != nil {
		return err
	}
	tests, err := spec.LoadTests(*testsDir)
	if err != nil {
		return err
	}
	tests = filter(tests, *only)

	c := canary.New()
	url, err := c.Start(target.CanaryListen)
	if err != nil {
		return fmt.Errorf("start canary: %w", err)
	}
	defer c.Close()
	fmt.Fprintf(os.Stderr, "canary MCP server at %s\ntesting %s (%d tests)\n", url, target.Endpoint, len(tests))

	started := time.Now()
	results := runner.New(target, c).RunAll(tests)
	rep := report.Build(target.Name, started, results)

	for _, r := range results {
		fmt.Fprintf(os.Stderr, "  %-5s %s %s\n", strings.ToUpper(string(r.Status)), r.ID, r.Title)
	}
	if err := writeReports(rep, *outDir); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\n%d passed, %d failed, %d skipped, %d errors. Reports in %s\n",
		rep.Summary["pass"], rep.Summary["fail"], rep.Summary["skip"], rep.Summary["error"], *outDir)
	if rep.Failed() {
		os.Exit(1)
	}
	return nil
}

func writeReports(rep *report.Run, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, write := range map[string]func(*os.File) error{
		"report.json":  func(f *os.File) error { return rep.JSON(f) },
		"report.sarif": func(f *os.File) error { return rep.SARIF(f) },
		"report.md":    func(f *os.File) error { rep.Markdown(f); return nil },
	} {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if err := write(f); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	testsDir := fs.String("tests", "tests", "directory of test cases")
	fs.Parse(args)
	tests, err := spec.LoadTests(*testsDir)
	if err != nil {
		return err
	}
	for _, t := range tests {
		fmt.Printf("%-24s L%d  AISVS %-16s %-14s %s\n", t.ID, t.Level, strings.Join(t.AISVS, ","), strings.Join(t.Risks, ","), t.Title)
	}
	return nil
}

// cmdCanary runs the canary alone, for wiring up a target by hand.
func cmdCanary(args []string) error {
	fs := flag.NewFlagSet("canary", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:9901", "listen address")
	fs.Parse(args)
	c := canary.New()
	url, err := c.Start(*listen)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "canary MCP server at", url, "(Ctrl-C to stop)")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	return c.Close()
}

func filter(tests []spec.Test, only string) []spec.Test {
	if only == "" {
		return tests
	}
	var out []spec.Test
	for _, t := range tests {
		for _, p := range strings.Split(only, ",") {
			if strings.HasPrefix(t.ID, strings.TrimSpace(p)) {
				out = append(out, t)
				break
			}
		}
	}
	return out
}
