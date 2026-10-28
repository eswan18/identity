package redirecturi

import "testing"

func TestIsLoopback(t *testing.T) {
	yes := []string{
		"http://localhost/callback",
		"http://127.0.0.1/callback",
		"http://[::1]/callback",
		"http://localhost:8080/callback",
		"http://127.0.0.1:65535/cb",
		"http://localhost",
	}
	no := []string{
		"https://localhost/callback",
		"http://LOCALHOST/callback",
		"http://127.0.0.2/callback",
		"http://localhost.:80/cb",
		"http://localhost:0/cb",
		"http://localhost:65536/cb",
		"http://u@localhost/cb",
		"http://example.com/cb",
		"footstrike://cb",
	}
	for _, u := range yes {
		if !IsLoopback(u) {
			t.Errorf("IsLoopback(%q) = false", u)
		}
	}
	for _, u := range no {
		if IsLoopback(u) {
			t.Errorf("IsLoopback(%q) = true", u)
		}
	}
}
