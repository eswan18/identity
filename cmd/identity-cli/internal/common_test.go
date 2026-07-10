package internal

import (
	"reflect"
	"testing"
)

func TestAppendUnique(t *testing.T) {
	tests := []struct {
		name      string
		existing  []string
		additions []string
		want      []string
	}{
		{
			name:      "appends new values in order",
			existing:  []string{"https://a.example/callback"},
			additions: []string{"https://a.example/", "https://b.example/"},
			want:      []string{"https://a.example/callback", "https://a.example/", "https://b.example/"},
		},
		{
			name:      "skips values already present",
			existing:  []string{"https://a.example/callback", "https://a.example/"},
			additions: []string{"https://a.example/"},
			want:      []string{"https://a.example/callback", "https://a.example/"},
		},
		{
			name:      "skips duplicates within the additions themselves",
			existing:  []string{},
			additions: []string{"https://a.example/", "https://a.example/"},
			want:      []string{"https://a.example/"},
		},
		{
			name:      "no additions returns existing unchanged",
			existing:  []string{"https://a.example/callback"},
			additions: []string{},
			want:      []string{"https://a.example/callback"},
		},
		{
			// Trailing slashes are significant: the logout handler exact-matches
			// post_logout_redirect_uri against this list.
			name:      "treats trailing-slash variants as distinct",
			existing:  []string{"https://a.example"},
			additions: []string{"https://a.example/"},
			want:      []string{"https://a.example", "https://a.example/"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AppendUnique(tt.existing, tt.additions)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AppendUnique(%v, %v) = %v, want %v", tt.existing, tt.additions, got, tt.want)
			}
		})
	}
}

func TestParseList(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty string", "", []string{}},
		{"single value", "a", []string{"a"}},
		{"trims whitespace and drops empties", " a , , b ", []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseList(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseList(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
