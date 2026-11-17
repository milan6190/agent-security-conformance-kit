package policy

import "testing"

func TestCheck(t *testing.T) {
	p := Policy{Rules: []Rule{
		{Role: "dev", AllowTools: []string{"github.*"}, DenyTools: []string{"github.delete_*"}, AllowResources: []string{"file:///srv/docs/*"}},
		{Role: "admin", AllowTools: []string{"*"}},
		{Role: "*", AllowPrompts: []string{"summarize"}},
	}}
	cases := []struct {
		roles []string
		kind  Kind
		name  string
		want  bool
	}{
		{[]string{"dev"}, Tool, "github.create_issue", true},
		{[]string{"dev"}, Tool, "github.delete_repo", false},
		{[]string{"dev"}, Tool, "slack.post", false},
		{[]string{"dev", "admin"}, Tool, "github.delete_repo", false}, // deny wins
		{[]string{"admin"}, Tool, "anything", true},
		{[]string{"dev"}, Resource, "file:///srv/docs/a.md", true},
		{[]string{"dev"}, Resource, "file:///etc/passwd", false},
		{nil, Prompt, "summarize", true},
		{nil, Tool, "github.create_issue", false},
	}
	for _, c := range cases {
		if got := p.Check(c.roles, c.kind, c.name).Allowed; got != c.want {
			t.Errorf("%v %s %s: got %v want %v", c.roles, c.kind, c.name, got, c.want)
		}
	}
}

func TestCheckCallArgs(t *testing.T) {
	p := Policy{Rules: []Rule{
		{Role: "reader", AllowTools: []string{"read_file"}, ArgRules: []ArgRule{{Tool: "read_file", Arg: "path", Allow: []string{"docs/*"}}}},
		{Role: "admin", AllowTools: []string{"*"}},
	}}
	cases := []struct {
		roles []string
		path  any
		want  bool
	}{
		{[]string{"reader"}, "docs/handbook.md", true},
		{[]string{"reader"}, "secrets/prod.env", false},
		{[]string{"reader"}, "/etc/passwd", false},
		{[]string{"reader"}, "docs/../secrets/prod.env", false},
		{[]string{"reader"}, "docs/./a.md", false},
		{[]string{"reader"}, "docs\\..\\x", false},
		{[]string{"reader"}, 42, false},
		{[]string{"reader"}, nil, false},
		{[]string{"admin"}, "/etc/passwd", true},
		{[]string{"reader", "admin"}, "/etc/passwd", true}, // admin grant has no arg rule
	}
	for _, c := range cases {
		args := map[string]any{}
		if c.path != nil {
			args["path"] = c.path
		}
		if got := p.CheckCall(c.roles, "read_file", args).Allowed; got != c.want {
			t.Errorf("%v %v: got %v want %v", c.roles, c.path, got, c.want)
		}
	}
}
