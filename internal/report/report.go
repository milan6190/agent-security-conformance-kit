// Package report renders run results as JSON, SARIF 2.1.0 and Markdown.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/aisvs"
	"github.com/OWASP/www-project-agentic-security-conformance-kit/internal/runner"
)

// Version of the kit, set at build time.
var Version = "0.1.0-dev"

// Coverage is the verdict for one AISVS requirement.
type Coverage struct {
	ID      string   `json:"id"`
	Level   int      `json:"level"`
	Section string   `json:"section"`
	Verdict string   `json:"verdict"` // pass, fail, skipped, not_covered
	Tests   []string `json:"tests,omitempty"`
}

// Run is the full report.
type Run struct {
	Tool         string              `json:"tool"`
	Version      string              `json:"version"`
	AISVSVersion string              `json:"aisvs_version"`
	Target       string              `json:"target"`
	Started      time.Time           `json:"started"`
	Summary      map[string]int      `json:"summary"`
	Results      []runner.TestResult `json:"results"`
	Coverage     []Coverage          `json:"coverage"`
}

// Build aggregates results into a report.
func Build(target string, started time.Time, results []runner.TestResult) *Run {
	run := &Run{Tool: "asck", Version: Version, AISVSVersion: aisvs.Version, Target: target, Started: started, Results: results, Summary: map[string]int{}}
	byReq := map[string][]runner.TestResult{}
	for _, r := range results {
		run.Summary[string(r.Status)]++
		for _, id := range r.AISVS {
			byReq[id] = append(byReq[id], r)
		}
	}
	for _, req := range aisvs.All() {
		c := Coverage{ID: req.ID, Level: req.Level, Section: req.Section, Verdict: "not_covered"}
		rs := byReq[req.ID]
		if len(rs) > 0 {
			c.Verdict = "pass"
			skipped := 0
			for _, r := range rs {
				c.Tests = append(c.Tests, r.ID)
				switch r.Status {
				case runner.Fail, runner.Error:
					c.Verdict = "fail"
				case runner.Skip:
					skipped++
				}
			}
			if c.Verdict == "pass" && skipped == len(rs) {
				c.Verdict = "skipped"
			}
		}
		run.Coverage = append(run.Coverage, c)
	}
	return run
}

// Failed reports whether any test failed or errored.
func (r *Run) Failed() bool { return r.Summary["fail"]+r.Summary["error"] > 0 }

// JSON writes the report as JSON.
func (r *Run) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// SARIF writes failed and errored tests as SARIF 2.1.0 results.
func (r *Run) SARIF(w io.Writer) error {
	type msg struct {
		Text string `json:"text"`
	}
	var rules []map[string]any
	var results []map[string]any
	for _, t := range r.Results {
		rules = append(rules, map[string]any{
			"id":               t.ID,
			"name":             strings.ReplaceAll(t.ID, "-", ""),
			"shortDescription": msg{t.Title},
			"helpUri":          "https://github.com/OWASP/AISVS",
			"properties": map[string]any{
				"tags":  append(prefixed("AISVS-", t.AISVS), t.Risks...),
				"level": t.Level,
			},
		})
		if t.Status != runner.Fail && t.Status != runner.Error {
			continue
		}
		var detail []string
		for _, s := range t.Steps {
			for _, f := range s.Failures {
				detail = append(detail, s.Name+": "+f)
			}
		}
		if t.Reason != "" {
			detail = append(detail, t.Reason)
		}
		results = append(results, map[string]any{
			"ruleId":  t.ID,
			"level":   "error",
			"message": msg{fmt.Sprintf("%s (AISVS %s). %s", t.Title, strings.Join(t.AISVS, ", "), strings.Join(detail, "; "))},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": t.Test.File},
			}}},
		})
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "OWASP Agentic Security Conformance Kit", "version": r.Version,
				"informationUri": "https://github.com/OWASP/www-project-agentic-security-conformance-kit",
				"rules":          rules,
			}},
			"results": nonNil(results),
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// Markdown writes a human summary with the AISVS coverage map.
func (r *Run) Markdown(w io.Writer) {
	fmt.Fprintf(w, "# Conformance report: %s\n\n", r.Target)
	fmt.Fprintf(w, "asck %s · AISVS %s · %s\n\n", r.Version, r.AISVSVersion, r.Started.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "**%d passed, %d failed, %d skipped, %d errors**\n\n", r.Summary["pass"], r.Summary["fail"], r.Summary["skip"], r.Summary["error"])
	fmt.Fprintln(w, "## Tests\n\n| Test | AISVS | Result | Detail |\n| --- | --- | --- | --- |")
	for _, t := range r.Results {
		var d []string
		for _, s := range t.Steps {
			d = append(d, s.Failures...)
		}
		if t.Reason != "" {
			d = append(d, t.Reason)
		}
		fmt.Fprintf(w, "| %s %s | %s | %s | %s |\n", t.ID, t.Title, strings.Join(t.AISVS, ", "), icon(string(t.Status)), esc(strings.Join(d, "; ")))
	}
	counts := map[string]int{}
	for _, c := range r.Coverage {
		counts[c.Verdict]++
	}
	fmt.Fprintf(w, "\n## AISVS C9/C10 coverage\n\n%d of %d requirements have at least one test: %d pass, %d fail, %d skipped.\n\n",
		len(r.Coverage)-counts["not_covered"], len(r.Coverage), counts["pass"], counts["fail"], counts["skipped"])
	fmt.Fprintln(w, "| Requirement | Level | Section | Verdict | Tests |\n| --- | --- | --- | --- | --- |")
	cov := append([]Coverage(nil), r.Coverage...)
	sort.SliceStable(cov, func(i, j int) bool { return rank(cov[i].Verdict) < rank(cov[j].Verdict) })
	for _, c := range cov {
		fmt.Fprintf(w, "| %s | L%d | %s | %s | %s |\n", c.ID, c.Level, c.Section, icon(c.Verdict), strings.Join(c.Tests, ", "))
	}
}

func rank(v string) int {
	return map[string]int{"fail": 0, "pass": 1, "skipped": 2, "not_covered": 3}[v]
}

func icon(s string) string {
	return map[string]string{"pass": "PASS", "fail": "FAIL", "skip": "skip", "skipped": "skip", "error": "ERROR", "not_covered": "not covered"}[s]
}

func esc(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func prefixed(p string, xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = p + x
	}
	return out
}

func nonNil(x []map[string]any) []map[string]any {
	if x == nil {
		return []map[string]any{}
	}
	return x
}
