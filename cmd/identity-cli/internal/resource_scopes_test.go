package internal

import (
	"reflect"
	"testing"
)

func TestMergeAndRemoveScopes(t *testing.T) {
	current := map[string]string{"a:read": "Read A", "a:write": "Write A"}

	merged := MergeScopes(current, map[string]string{"a:write": "Change A", "a:admin": "Manage A"})
	want := map[string]string{"a:read": "Read A", "a:write": "Change A", "a:admin": "Manage A"}
	if !reflect.DeepEqual(merged, want) {
		t.Errorf("MergeScopes = %v, want %v", merged, want)
	}
	if current["a:write"] != "Write A" || len(current) != 2 {
		t.Errorf("MergeScopes modified its input: %v", current)
	}

	removed, notFound := RemoveScopes(current, []string{"a:write"})
	if !reflect.DeepEqual(removed, map[string]string{"a:read": "Read A"}) || len(notFound) != 0 {
		t.Errorf("RemoveScopes = %v, %v", removed, notFound)
	}
	_, notFound = RemoveScopes(current, []string{"a:read", "a:typo", "a:typo"})
	if !reflect.DeepEqual(notFound, []string{"a:typo"}) {
		t.Errorf("notFound = %v, want [a:typo] once", notFound)
	}
	if len(current) != 2 {
		t.Errorf("RemoveScopes modified its input: %v", current)
	}
}

func TestParseScopes(t *testing.T) {
	parsed, err := ParseScopes([]byte(`{"a:read":"Read A"}`))
	if err != nil || !reflect.DeepEqual(parsed, map[string]string{"a:read": "Read A"}) {
		t.Errorf("ParseScopes = %v, %v", parsed, err)
	}
	if _, err := ParseScopes([]byte(`[1]`)); err == nil {
		t.Error("ParseScopes accepted a non-object")
	}
}
