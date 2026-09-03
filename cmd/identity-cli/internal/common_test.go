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

func TestRemoveValues(t *testing.T) {
	tests := []struct {
		name         string
		existing     []string
		removals     []string
		want         []string
		wantNotFound []string
	}{
		{
			name:         "removes a value and preserves the order of the rest",
			existing:     []string{"https://a.example/cb", "https://b.example/cb", "https://c.example/cb"},
			removals:     []string{"https://b.example/cb"},
			want:         []string{"https://a.example/cb", "https://c.example/cb"},
			wantNotFound: []string{},
		},
		{
			name:         "removes several values in one call",
			existing:     []string{"https://a.example/cb", "https://b.example/cb", "https://c.example/cb"},
			removals:     []string{"https://a.example/cb", "https://c.example/cb"},
			want:         []string{"https://b.example/cb"},
			wantNotFound: []string{},
		},
		{
			name:         "reports values that are not present",
			existing:     []string{"https://a.example/cb"},
			removals:     []string{"https://nope.example/cb"},
			want:         []string{"https://a.example/cb"},
			wantNotFound: []string{"https://nope.example/cb"},
		},
		{
			// A partial match must not silently remove the ones it found:
			// the caller aborts the whole update when notFound is non-empty.
			name:         "reports only the missing values when some match",
			existing:     []string{"https://a.example/cb", "https://b.example/cb"},
			removals:     []string{"https://a.example/cb", "https://nope.example/cb"},
			want:         []string{"https://b.example/cb"},
			wantNotFound: []string{"https://nope.example/cb"},
		},
		{
			// Trailing slashes are significant: the logout handler exact-matches
			// post_logout_redirect_uri against this list.
			name:         "treats trailing-slash variants as distinct",
			existing:     []string{"https://a.example"},
			removals:     []string{"https://a.example/"},
			want:         []string{"https://a.example"},
			wantNotFound: []string{"https://a.example/"},
		},
		{
			name:         "no removals returns existing unchanged",
			existing:     []string{"https://a.example/cb"},
			removals:     []string{},
			want:         []string{"https://a.example/cb"},
			wantNotFound: []string{},
		},
		{
			name:         "removing every value yields an empty list",
			existing:     []string{"https://a.example/cb"},
			removals:     []string{"https://a.example/cb"},
			want:         []string{},
			wantNotFound: []string{},
		},
		{
			name:         "a value repeated in removals is reported once",
			existing:     []string{"https://a.example/cb"},
			removals:     []string{"https://nope.example/cb", "https://nope.example/cb"},
			want:         []string{"https://a.example/cb"},
			wantNotFound: []string{"https://nope.example/cb"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, notFound := RemoveValues(tt.existing, tt.removals)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RemoveValues(%v, %v) result = %v, want %v", tt.existing, tt.removals, got, tt.want)
			}
			if !reflect.DeepEqual(notFound, tt.wantNotFound) {
				t.Errorf("RemoveValues(%v, %v) notFound = %v, want %v", tt.existing, tt.removals, notFound, tt.wantNotFound)
			}
		})
	}
}
