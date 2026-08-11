package sub2api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grok-free-register/grok-reg/internal/cpa"
)

func TestParseGroupIDs(t *testing.T) {
	cases := []struct {
		in   string
		want []int64
	}{
		{"", nil},
		{"3", []int64{3}},
		{"3,5,12", []int64{3, 5, 12}},
		{" 3 , 5 , abc , 12 ", []int64{3, 5, 12}},
		{"abc", nil},
	}
	for _, c := range cases {
		got := parseGroupIDs(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("parseGroupIDs(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("parseGroupIDs(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	}
}

func TestImportDocumentBatchWithGroups(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	u := NewUploader(Config{
		Enabled:    true,
		BaseURL:    srv.URL,
		Key:        "testkey",
		Path:       "/api/v1/admin/accounts/batch",
		TimeoutSec: 10,
		Retries:    0,
		GroupIDs:   "3, 5",
	}, func(string, ...any) {})

	doc := cpa.Document{Email: "a@b.c", Sub: "sub1", AccessToken: "at", RefreshToken: "rt", IDToken: "it", ExpiresIn: 3600}
	res := u.ImportDocument(doc)
	if !res.OK {
		t.Fatalf("import failed: %+v", res)
	}

	var payload struct {
		Accounts []map[string]any `json:"accounts"`
	}
	if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
		t.Fatalf("bad batch json %q: %v", gotBody, err)
	}
	if len(payload.Accounts) != 1 {
		t.Fatalf("expected 1 account, got %d (body=%s)", len(payload.Accounts), gotBody)
	}
	acct := payload.Accounts[0]
	gids, ok := acct["group_ids"].([]any)
	if !ok {
		t.Fatalf("group_ids missing or wrong type (body=%s)", gotBody)
	}
	if len(gids) != 2 || gids[0].(float64) != 3 || gids[1].(float64) != 5 {
		t.Fatalf("group_ids = %v, want [3 5]", gids)
	}
	if acct["email"] != "a@b.c" || acct["platform"] != "grok" {
		t.Fatalf("unexpected account fields: %v", acct)
	}
}

func TestImportDocumentLegacyNoGroups(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	u := NewUploader(Config{
		Enabled:    true,
		BaseURL:    srv.URL,
		Key:        "testkey",
		Path:       "/api/v1/admin/accounts/import",
		TimeoutSec: 10,
		Retries:    0,
	}, func(string, ...any) {})

	doc := cpa.Document{Email: "a@b.c", Sub: "sub1"}
	u.ImportDocument(doc)

	if strings.Contains(gotBody, "accounts") {
		t.Fatalf("legacy path should send single object, got: %s", gotBody)
	}
	if strings.Contains(gotBody, "group_ids") {
		t.Fatalf("legacy path with no GroupIDs should not send group_ids, got: %s", gotBody)
	}
}
