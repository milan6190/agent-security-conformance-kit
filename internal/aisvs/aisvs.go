// Package aisvs holds the AISVS requirement catalog the kit maps tests to.
package aisvs

import (
	"sort"
	"strconv"
	"strings"
)

// Requirement is one AISVS requirement. Text is intentionally omitted;
// see Link for the authoritative wording.
type Requirement struct {
	ID      string
	Level   int
	Section string
	Removed bool
}

// Chapter returns "C9" for "9.3.1".
func (r Requirement) Chapter() string {
	return "C" + strings.SplitN(r.ID, ".", 2)[0]
}

// Link points at the chapter in the AISVS repository.
func (r Requirement) Link() string {
	switch r.Chapter() {
	case "C9":
		return "https://github.com/OWASP/AISVS/blob/main/" + Version + "/en/0x10-C09-Orchestration-and-Agentic-Action.md"
	case "C10":
		return "https://github.com/OWASP/AISVS/blob/main/" + Version + "/en/0x10-C10-MCP-Security.md"
	}
	return "https://github.com/OWASP/AISVS"
}

// All returns every active requirement in ID order.
func All() []Requirement {
	out := make([]Requirement, 0, len(catalog))
	for _, r := range catalog {
		if !r.Removed {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i].ID, out[j].ID) })
	return out
}

// Lookup finds a requirement by ID.
func Lookup(id string) (Requirement, bool) {
	for _, r := range catalog {
		if r.ID == id {
			return r, !r.Removed
		}
	}
	return Requirement{}, false
}

func less(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}
