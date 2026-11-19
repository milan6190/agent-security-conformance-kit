package schema

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func parse(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestValidate(t *testing.T) {
	s := parse(t, `{"type":"object","properties":{"q":{"type":"string","maxLength":5},"n":{"type":"integer","minimum":1},
		"tags":{"type":"array","items":{"$ref":"#/$defs/tag"}}},"required":["q"],"additionalProperties":false,
		"$defs":{"tag":{"type":"string","enum":["a","b"]}}}`)
	cases := []struct {
		val  string
		fail string
	}{
		{`{"q":"hi"}`, ""},
		{`{"q":"hi","n":3,"tags":["a","b"]}`, ""},
		{`{}`, "missing required"},
		{`{"q":"hi","extra":1}`, "unrecognized property"},
		{`{"q":123}`, "expected type"},
		{`{"q":"toolong"}`, "maxLength"},
		{`{"q":"hi","n":1.5}`, "expected type"},
		{`{"q":"hi","n":0}`, "minimum"},
		{`{"q":"hi","tags":["c"]}`, "enum"},
	}
	for _, c := range cases {
		var v any
		json.Unmarshal([]byte(c.val), &v)
		err := Validate(s, v, DefaultLimits)
		switch {
		case c.fail == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.val, err)
		case c.fail != "" && (err == nil || !strings.Contains(err.Error(), c.fail)):
			t.Errorf("%s: got %v, want error containing %q", c.val, err, c.fail)
		}
	}
}

func TestSchemaRejected(t *testing.T) {
	deep := `{"type":"string"}`
	for range 100 {
		deep = `{"type":"object","properties":{"a":` + deep + `}}`
	}
	for name, s := range map[string]string{
		"remote ref":     `{"type":"object","properties":{"q":{"$ref":"http://127.0.0.1:9/q.json"}}}`,
		"file ref":       `{"$ref":"file:///etc/passwd"}`,
		"unresolved ref": `{"$ref":"#/$defs/missing"}`,
		"too deep":       deep,
	} {
		err := Validate(parse(t, s), map[string]any{}, DefaultLimits)
		if !errors.Is(err, ErrSchema) {
			t.Errorf("%s: got %v, want ErrSchema", name, err)
		}
	}
}

func TestRecursiveRefIsBounded(t *testing.T) {
	s := parse(t, `{"$ref":"#"}`)
	if err := Validate(s, "x", DefaultLimits); !errors.Is(err, ErrSchema) {
		t.Fatalf("got %v, want step budget error", err)
	}
}
