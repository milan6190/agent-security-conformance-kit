// Package redact masks PII and secrets in arbitrary JSON values.
package redact

import (
	"regexp"
	"strings"
)

type rule struct {
	name     string
	re       *regexp.Regexp
	validate func(string) bool
}

// Redactor applies a set of detectors to strings.
type Redactor struct {
	rules []rule
}

var builtins = map[string]rule{
	"email":        {name: "EMAIL", re: regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)},
	"ssn":          {name: "SSN", re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	"credit_card":  {name: "CARD", re: regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`), validate: luhn},
	"phone_us":     {name: "PHONE", re: regexp.MustCompile(`(?:\+1[ .\-]?)?\(?\b\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}\b`)},
	"aws_key":      {name: "AWS_KEY", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	"github_token": {name: "GITHUB_TOKEN", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	"jwt":          {name: "JWT", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`)},
	"private_key":  {name: "PRIVATE_KEY", re: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)},
}

// Builtins lists detector names that can be enabled.
func Builtins() []string {
	out := make([]string, 0, len(builtins))
	for k := range builtins {
		out = append(out, k)
	}
	return out
}

// New builds a Redactor from detector names plus optional custom patterns
// (name -> regex). Unknown names are returned as an error-free skip list.
func New(detectors []string, custom map[string]string) (*Redactor, error) {
	r := &Redactor{}
	// Ordering: secrets before generic numbers so tokens aren't partially masked.
	order := []string{"private_key", "jwt", "aws_key", "github_token", "email", "ssn", "credit_card", "phone_us"}
	enabled := map[string]bool{}
	for _, d := range detectors {
		enabled[d] = true
	}
	for _, name := range order {
		if enabled[name] || enabled["all"] {
			r.rules = append(r.rules, builtins[name])
		}
	}
	for name, pat := range custom {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, err
		}
		r.rules = append(r.rules, rule{name: strings.ToUpper(name), re: re})
	}
	return r, nil
}

// Counts records how many matches each detector replaced.
type Counts map[string]int

func (c Counts) Total() int {
	n := 0
	for _, v := range c {
		n += v
	}
	return n
}

// String redacts a single string.
func (r *Redactor) String(s string, c Counts) string {
	for _, ru := range r.rules {
		s = ru.re.ReplaceAllStringFunc(s, func(m string) string {
			if ru.validate != nil && !ru.validate(m) {
				return m
			}
			c[ru.name]++
			return "[REDACTED:" + ru.name + "]"
		})
	}
	return s
}

// Value walks a decoded JSON value and redacts every string (and map key
// values, not keys themselves) in place, returning the new value.
func (r *Redactor) Value(v any, c Counts) any {
	switch t := v.(type) {
	case string:
		return r.String(t, c)
	case map[string]any:
		for k, x := range t {
			t[k] = r.Value(x, c)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = r.Value(x, c)
		}
		return t
	}
	return v
}

func luhn(s string) bool {
	sum, n, alt := 0, 0, false
	for i := len(s) - 1; i >= 0; i-- {
		ch := s[i]
		if ch < '0' || ch > '9' {
			continue
		}
		d := int(ch - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
		n++
	}
	return n >= 13 && sum%10 == 0
}
