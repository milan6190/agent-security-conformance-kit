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
