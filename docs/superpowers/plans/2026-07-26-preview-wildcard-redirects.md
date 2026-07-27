# Preview Wildcard Redirect URIs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an OAuth client whose registered redirect URIs include a wildcard entry (e.g. `https://*.preview.footstrike.run/auth/callback`) authorize callbacks to any single-label subdomain of that suffix, so ephemeral "preview" environments can complete OAuth without per-preview registration.

**Architecture:** Redirect validation today is one exact-match check — `slices.Contains(client.RedirectUris, redirectURI)` in `validateOAuthClientRedirect` (`pkg/httpserver/credentials.go`). We add a pure function `redirectURIAllowed` that keeps exact matching as the first check and additionally lets a registered entry whose host starts with `*.` match candidates that replace the `*` with exactly one DNS label — same scheme (https only), same port, same path, no query/fragment. The call site swaps to it. Nothing else changes: the token endpoint (`oauth.go:244`) compares against the URI stored with the authorization code, which is always a concrete URI, so it is untouched. "Preview-eligible client" is realized as "client with a wildcard entry registered" — no schema change, no flag column, and a preview-deployed identity inherits the behavior through its branched DB automatically.

**Tech Preview:** Go stdlib only (`net/url`, `strings`, `slices`); plain `testing` package tests in package `httpserver`, matching the repo's existing style.

**Context for the zero-context engineer:** This repo is a Go OAuth2/OIDC identity provider (chi router, sqlc for DB). You only touch `pkg/httpserver/`. Design spec: `~/Develop/ibormeith/bifrost/docs/superpowers/specs/2026-07-26-preview-environments-design.md` (section "Identity / auth"). Verification commands run from the repo root: `make test`, `make lint`.

## Global Constraints

- Wildcard matching applies **only** to registered entries whose host begins with `*.` — behavior for all other entries must remain byte-for-byte exact match.
- Wildcard entries match **https candidates only**, exactly **one** non-empty DNS label in place of `*`, identical path and port, and candidates must carry no query string or fragment.
- A `*` anywhere else in a registered entry (e.g. `https://api-*.preview.footstrike.run/cb`) must match nothing.
- Host comparison is case-insensitive (DNS semantics); path comparison stays case-sensitive.
- No new dependencies; stdlib only.
- Registering actual wildcard URIs on the staging footstrike clients is **out of scope** here (happens in the later wiring/provisioning plan, via `identity-cli`).

---

### Task 1: `redirectURIAllowed` matching function

**Files:**
- Create: `pkg/httpserver/redirect_match.go`
- Test: `pkg/httpserver/redirect_match_test.go`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `func redirectURIAllowed(registered []string, candidate string) bool` (package-private, package `httpserver`) — Task 2's call site depends on exactly this name and signature.

- [ ] **Step 1: Write the failing tests**

Create `pkg/httpserver/redirect_match_test.go`:

```go
package httpserver

import "testing"

func TestRedirectURIAllowed(t *testing.T) {
	wild := "https://*.preview.footstrike.run/auth/callback"
	exact := "https://staging.footstrike.run/auth/callback"

	tests := []struct {
		name       string
		registered []string
		candidate  string
		want       bool
	}{
		{"exact match still works", []string{exact}, exact, true},
		{"unregistered candidate rejected", []string{exact}, "https://evil.example.com/auth/callback", false},
		{"wildcard matches single label", []string{wild}, "https://hae-cadence.preview.footstrike.run/auth/callback", true},
		{"wildcard alongside exact entries", []string{exact, wild}, "https://api-x.preview.footstrike.run/auth/callback", true},
		{"wildcard rejects multi-label", []string{wild}, "https://a.b.preview.footstrike.run/auth/callback", false},
		{"wildcard rejects bare suffix", []string{wild}, "https://preview.footstrike.run/auth/callback", false},
		{"wildcard rejects empty label", []string{wild}, "https://.preview.footstrike.run/auth/callback", false},
		{"wildcard rejects cousin domain", []string{wild}, "https://xpreview.footstrike.run/auth/callback", false},
		{"wildcard rejects wrong path", []string{wild}, "https://x.preview.footstrike.run/other", false},
		{"wildcard rejects http candidate", []string{wild}, "http://x.preview.footstrike.run/auth/callback", false},
		{"http wildcard entry matches nothing", []string{"http://*.preview.footstrike.run/auth/callback"}, "http://x.preview.footstrike.run/auth/callback", false},
		{"wildcard rejects query string", []string{wild}, "https://x.preview.footstrike.run/auth/callback?a=b", false},
		{"wildcard rejects fragment", []string{wild}, "https://x.preview.footstrike.run/auth/callback#f", false},
		{"wildcard rejects explicit port mismatch", []string{wild}, "https://x.preview.footstrike.run:8443/auth/callback", false},
		{"host match is case-insensitive", []string{wild}, "https://X.Previews.Footstrike.Run/auth/callback", true},
		{"mid-label wildcard entry matches nothing", []string{"https://api-*.preview.footstrike.run/auth/callback"}, "https://api-x.preview.footstrike.run/auth/callback", false},
		{"literal wildcard candidate passes only via the exact branch", []string{wild}, "https://*.preview.footstrike.run/auth/callback", true},
		{"empty registered list rejects", nil, exact, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redirectURIAllowed(tt.registered, tt.candidate); got != tt.want {
				t.Errorf("redirectURIAllowed(%v, %q) = %v, want %v", tt.registered, tt.candidate, got, tt.want)
			}
		})
	}
}
```

Note on the `"literal wildcard candidate"` case: the candidate `https://*.previews...` equals the registered string byte-for-byte, so it passes via the *exact* branch — correct and harmless (no browser sends a literal `*` host); the case documents the behavior.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/httpserver/ -run TestRedirectURIAllowed -v`
Expected: compile error — `undefined: redirectURIAllowed`.

- [ ] **Step 3: Implement the function**

Create `pkg/httpserver/redirect_match.go`:

```go
package httpserver

import (
	"net/url"
	"slices"
	"strings"
)

// redirectURIAllowed reports whether candidate is allowed by a client's
// registered redirect URIs. An entry allows the candidate if it matches
// exactly, or if the entry's host begins with "*." and the candidate differs
// only by replacing the "*" with exactly one non-empty DNS label. Wildcard
// entries match https candidates only, require identical path and port, and
// refuse candidates carrying a query string or fragment. This exists so
// ephemeral preview environments (https://<app>-<tag>.preview.footstrike.run)
// can complete OAuth without per-preview registration.
func redirectURIAllowed(registered []string, candidate string) bool {
	if slices.Contains(registered, candidate) {
		return true
	}
	cand, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(registered, func(entry string) bool {
		return wildcardRedirectMatch(entry, cand)
	})
}

func wildcardRedirectMatch(entry string, cand *url.URL) bool {
	pat, err := url.Parse(entry)
	if err != nil || pat.Scheme != "https" || !strings.HasPrefix(pat.Host, "*.") {
		return false
	}
	if cand.Scheme != "https" || cand.Path != pat.Path || cand.Port() != pat.Port() {
		return false
	}
	if cand.RawQuery != "" || cand.Fragment != "" {
		return false
	}
	dotSuffix := "." + strings.ToLower(strings.TrimPrefix(pat.Hostname(), "*."))
	candHost := strings.ToLower(cand.Hostname())
	label, ok := strings.CutSuffix(candHost, dotSuffix)
	return ok && label != "" && !strings.ContainsAny(label, ".*")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/httpserver/ -run TestRedirectURIAllowed -v`
Expected: PASS, all subtests.

- [ ] **Step 5: Commit**

```bash
git add pkg/httpserver/redirect_match.go pkg/httpserver/redirect_match_test.go
git commit -m "Add wildcard-aware redirect URI matching for preview environments"
```

---

### Task 2: Use `redirectURIAllowed` in the authorize flow

**Files:**
- Modify: `pkg/httpserver/credentials.go` (function `validateOAuthClientRedirect`, the `slices.Contains` check at ~line 121)

**Interfaces:**
- Consumes: `redirectURIAllowed(registered []string, candidate string) bool` from Task 1.
- Produces: no new symbols; `validateOAuthClientRedirect` keeps its exact signature `func (s *Server) validateOAuthClientRedirect(ctx context.Context, clientID, redirectURI string) (db.OauthClient, error)`.

- [ ] **Step 1: Swap the check**

In `validateOAuthClientRedirect`, replace:

```go
	if !slices.Contains(client.RedirectUris, redirectURI) {
```

with:

```go
	if !redirectURIAllowed(client.RedirectUris, redirectURI) {
```

Then check whether `slices` is still used elsewhere in `credentials.go`; if not, remove it from the imports (the compiler will tell you: `imported and not used`).

- [ ] **Step 2: Run the full suite and linter**

Run: `make test && make lint`
Expected: all packages PASS, lint clean. The existing authorize-flow tests (`login_test.go`, `authorize_params_test.go`, `credentials_test.go`) exercise `validateOAuthClientRedirect`'s exact-match and failure paths and must pass unchanged — if any of them fail, the wildcard branch has altered exact-match behavior, which is a bug in Task 1, not something to fix by editing those tests.

- [ ] **Step 3: Commit**

```bash
git add pkg/httpserver/credentials.go
git commit -m "Accept wildcard redirect matches in the authorize flow"
```

---

## Self-review notes

- **Spec coverage:** implements the spec's "Identity / auth" bullet 1 in full; bullet 2 (identity-in-preview) needs no code — it is a consequence of the data living in the branched DB. Registration of wildcard URIs on real clients is deliberately deferred to the wiring plan, per Global Constraints.
- **Deliberate semantic choice:** "preview-eligible client" = "client with a wildcard entry registered" (data), not a schema flag. Admin-only client registration (identity-cli) is the gate.
- **Untouched on purpose:** token-endpoint check (`oauth.go:244`, exact match against the code's stored URI), `authCode` storage, identity-cli (stores strings verbatim; a wildcard entry needs no CLI change).
