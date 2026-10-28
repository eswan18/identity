package internal

import (
	"database/sql"
	"reflect"
	"strings"
	"testing"
)

func TestParseResourceScopes(t *testing.T) {
	got, err := ParseResourceScopes([]string{
		"sensibility:read=Read your accounts, balances and cash flows",
		" sensibility:write = Change your accounts ",
	})
	if err != nil {
		t.Fatalf("ParseResourceScopes: %v", err)
	}
	want := map[string]string{
		"sensibility:read":  "Read your accounts, balances and cash flows",
		"sensibility:write": "Change your accounts",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseResourceScopes = %v, want %v", got, want)
	}

	empty, err := ParseResourceScopes(nil)
	if err != nil || len(empty) != 0 {
		t.Errorf("ParseResourceScopes(nil) = %v, %v; want an empty map", empty, err)
	}
}

func TestParseResourceScopesRefuses(t *testing.T) {
	cases := map[string][]string{
		"no description":     {"read"},
		"empty description":  {"read="},
		"empty name":         {"=Read things"},
		"whitespace in name": {"read all=Read things"},
		"duplicate":          {"read=Read", "read=Read again"},
		"openid":             {"openid=Sign in"},
		"offline_access":     {"offline_access=Stay signed in"},
		"admin scope":        {"admin:users:read=Read users"},
	}
	for name, flags := range cases {
		if got, err := ParseResourceScopes(flags); err == nil {
			t.Errorf("%s: ParseResourceScopes(%q) = %v, want an error", name, flags, got)
		}
	}
}

func TestScopesJSON(t *testing.T) {
	raw, err := ScopesJSON(nil)
	if err != nil || string(raw) != "{}" {
		t.Errorf("ScopesJSON(nil) = %s, %v; want {} (the column must hold an object)", raw, err)
	}
	raw, err = ScopesJSON(map[string]string{"a:read": "Read"})
	if err != nil || string(raw) != `{"a:read":"Read"}` {
		t.Errorf("ScopesJSON = %s, %v", raw, err)
	}
}

func TestDefaultResourceValue(t *testing.T) {
	if got := DefaultResourceValue(sql.NullString{String: "ethanswan:fitness", Valid: true}); got != "ethanswan:fitness" {
		t.Errorf("DefaultResourceValue = %q", got)
	}
	if got := DefaultResourceValue(sql.NullString{}); !strings.Contains(got, "none") {
		t.Errorf("DefaultResourceValue(NULL) = %q, want it to say none", got)
	}
}
