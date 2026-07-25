package oauth

import (
	"strings"
	"testing"
)

func TestExtractPrincipalID_EscapedJSON(t *testing.T) {
	// Shape seen in accounts.x.ai consent_debug.html React Query payload.
	html := `],"queries":[{"state":{"data":{"user":{\"userId\":\"56f924f3-2ffd-4eeb-931a-dc4db062d1d3\",\"email\":\"mailocxgtnb2ys3w@edu.dock.dpdns.org\"}}}}]`
	// Actual file uses single-backslash escapes inside a JS string: \"userId\":\"uuid\"
	html = `data\":{\"user\":{\"userId\":\"56f924f3-2ffd-4eeb-931a-dc4db062d1d3\",\"email\":\"x@y.z\"}}}`
	got := extractPrincipalID(html)
	want := "56f924f3-2ffd-4eeb-931a-dc4db062d1d3"
	if got != want {
		t.Fatalf("extractPrincipalID = %q, want %q", got, want)
	}
}

func TestExtractPrincipalID_PlainJSON(t *testing.T) {
	html := `{"user":{"userId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","email":"a@b.c"}}`
	got := extractPrincipalID(html)
	want := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if got != want {
		t.Fatalf("extractPrincipalID = %q, want %q", got, want)
	}
}

func TestExtractPrincipalID_Empty(t *testing.T) {
	if got := extractPrincipalID(`<form><input name="principal_id" value=""/></form>`); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestPrincipalFromSSO_SessionOnly(t *testing.T) {
	// Real SSO shape: only session_id, no user principal.
	sso := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzZXNzaW9uX2lkIjoiOTEzYmRhMzAtNzBmYy00NTNjLTkxNjctMmRkOTk0MDJkYmY4In0.2dxHO-3JRewOOot3LJoiCcDpaZ01wD74a_S4wFoM4UU"
	if pid := principalFromSSO(sso); pid != "" {
		t.Fatalf("session-only SSO should not yield principal, got %q", pid)
	}
}

func TestSanitizeSessionCookies(t *testing.T) {
	in := "sso=abc.def.ghi; mp_0b4055a12491884bcb6f34a5aa2718b6_mixpanel=x; __cf_bm=y; sso-rw=z"
	got := sanitizeSessionCookies(in)
	if !strings.Contains(got, "sso=abc.def.ghi") {
		t.Fatalf("missing sso: %q", got)
	}
	if strings.Contains(got, "__cf_bm") || strings.Contains(got, "mixpanel") {
		t.Fatalf("analytics/cf leaked: %q", got)
	}
	if !strings.Contains(got, "sso-rw=z") {
		t.Fatalf("missing sso-rw: %q", got)
	}
}
