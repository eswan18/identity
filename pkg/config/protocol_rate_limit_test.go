package config

import "testing"

func TestParseProtocolRateLimit(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want int
	}{
		{"unset", "", DefaultProtocolRateLimitPerMinute},
		{"valid", "600", 600},
		{"not a number", "lots", DefaultProtocolRateLimitPerMinute},
		{"zero", "0", DefaultProtocolRateLimitPerMinute},
		{"negative", "-5", DefaultProtocolRateLimitPerMinute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PROTOCOL_RATE_LIMIT_PER_MINUTE", tt.env)
			if got := parseProtocolRateLimit(); got != tt.want {
				t.Errorf("parseProtocolRateLimit() with %q = %d, want %d", tt.env, got, tt.want)
			}
		})
	}
}
