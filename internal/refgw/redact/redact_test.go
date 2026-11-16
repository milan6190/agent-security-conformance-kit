package redact

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	r, err := New([]string{"all"}, map[string]string{"employee_id": `\bEMP-\d{6}\b`})
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]any{
		"note":  "mail jane.doe@example.com or call (214) 555-0199, SSN 078-05-1120",
		"card":  "4242 4242 4242 4242",
		"notcc": "order 1234567890123", // fails Luhn
		"keys":  []any{"AKIAIOSFODNN7EXAMPLE", "EMP-123456"},
	}
	c := Counts{}
	out := r.Value(in, c).(map[string]any)
	s := out["note"].(string) + out["card"].(string) + strings.Join([]string{out["keys"].([]any)[0].(string), out["keys"].([]any)[1].(string)}, " ")
	for _, leak := range []string{"jane.doe", "555-0199", "078-05-1120", "4242", "AKIA", "EMP-123456"} {
		if strings.Contains(s, leak) {
			t.Errorf("leaked %q in %q", leak, s)
		}
	}
	if out["notcc"] != "order 1234567890123" {
		t.Errorf("non-Luhn number was redacted: %v", out["notcc"])
	}
	if c.Total() != 6 {
		t.Errorf("counts = %v", c)
	}
}
