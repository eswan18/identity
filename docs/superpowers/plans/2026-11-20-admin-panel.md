# Local Admin Panel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `identity-cli --env staging|prod` finds its own database URL, and `identity-cli ui` serves a localhost panel for OAuth clients and resources that enforces exactly the CLI's rules.

**Architecture:** The create/update/delete logic moves out of the cobra handlers into `cmd/identity-cli/internal/ops`. The CLI and a new `cmd/identity-cli/internal/ui` package (chi + templ + its own embedded Tailwind/daisyUI stylesheet) both call it. The identity server (`auth-service`) is not touched.

**Tech Stack:** Go 1.27, cobra, chi, templ v0.3.1100, sqlc-generated `pkg/db`, Tailwind 4 + daisyUI (npm, already in repo), testcontainers Postgres for integration tests.

**Spec:** `docs/superpowers/specs/2026-11-19-admin-panel-design.md`

## Global Constraints

- No change to `auth-service` or `pkg/httpserver`: no HTTP endpoint on the identity server edits clients or resources.
- Secret name: `identity_<env>_database_url`, project `ethans-services`, fetched with `gcloud secrets versions access latest --secret=<name> --project=ethans-services`.
- `--env` accepts exactly `staging` or `prod`. `--env` and `--database-url` are mutually exclusive.
- `ui` ignores `ENV`, `.env.<env>` and `DATABASE_URL`. Its sources are `--env` (default `staging`) or `--database-url` (banner "CUSTOM: <host>").
- `ui` listens on `127.0.0.1`, default port `8765`.
- Existing `cmd/identity-cli/cmd` integration tests (`TestCLIResourcesAndAllowLists` etc.) pass unchanged.
- New integration tests are named `TestCLI...` and their packages are added to the integration step in `.github/workflows/pull_request.yaml`.
- Generated `*_templ.go` and the UI stylesheet are committed (run `templ generate`, `make css`).
- Per the user: **no commits** until they have tested locally. Work on branch `admin-panel`.

## Review Focus

1. **Stale confirm:** a client's allow-list changes (no `updated_at` bump) between review and confirm. Expect refusal. The fingerprint must include the allow-list. Test in Task 2.
2. **Client IDs with URL characters:** CIMD client_ids are URLs and registered ones contain `-`, `_`, `=`. Expect them to round-trip through links and forms. Test in Task 4 (query parameter, escaped).
3. **Empty textarea lines and trailing whitespace** in redirect URIs and scopes. Expect them to be ignored, not stored as `""`. Test in Task 4.
4. **Cross-origin POST** from another site to `127.0.0.1:8765`. Expect a 403 even with the cookie, because the CSRF token is missing. Test in Task 3.
5. **gcloud missing or not logged in.** Expect an error naming `gcloud auth login`, not a raw exec error. Test in Task 1.

---

### Task 1: Database target resolution (`--env`, `--database-url`)

**Files:**
- Create: `cmd/identity-cli/internal/target.go`, `cmd/identity-cli/internal/target_test.go`
- Modify: `cmd/identity-cli/internal/common.go` (`GetDatastore`), `cmd/identity-cli/cmd/root.go`, `cmd/identity-cli/cmd/client.go` (`openDatastore`)

**Interfaces:**
- Produces:
  - `type Target struct { Name string; Source string; URL string }`. Name is `"staging"`, `"prod"`, `"custom"` or `"ENV=<value>"`.
  - `func (t Target) IsProd() bool`, `func (t Target) Host() string` (hostname only, never credentials), `func (t Target) Describe() string`, e.g. `env: prod (secret identity_prod_database_url, host ep-x.neon.tech)`.
  - `func ResolveTarget(ctx context.Context, env, databaseURL string, allowLegacy bool) (Target, error)`
  - `var AccessSecret func(ctx context.Context, name string) (string, error)`, a package var so tests can stub it.
  - `func GetDatastore(t Target) (*store.Store, error)`, which replaces the no-arg version and no longer calls `config.NewFromEnv`.
  - Root persistent flags `--env` and `--database-url` (vars `flagEnv`, `flagDatabaseURL` in package `cmd`).

- [ ] **Step 1: Failing tests `TestResolveTarget*` in `target_test.go`**, with `AccessSecret` stubbed:
  - env `"staging"` asks for `identity_staging_database_url`; `Target{Name:"staging"}`; `IsProd()==false`
  - env `"prod"` gives `IsProd()==true`; `Describe()` contains `identity_prod_database_url` and the host, and does not contain the password from `postgres://u:secret@h.example/db`
  - env `"dev"` gives an error containing `staging or prod`
  - env and databaseURL both set gives an error
  - databaseURL only gives `Name=="custom"`
  - neither, allowLegacy=true, `DATABASE_URL` set via `t.Setenv` gives `Name=="ENV=local"` (`ENV` unset)
  - neither, allowLegacy=false gives an error (callers default the env first)
  - `AccessSecret` returning `exec.ErrNotFound` gives an error containing `gcloud`, and a non-zero exit gives one containing `gcloud auth login`
  - the trailing newline is trimmed from the secret value
- [ ] **Step 2:** `go test ./cmd/identity-cli/internal/ -run TestResolveTarget`. Expect a FAIL (undefined).
- [ ] **Step 3: Implement.** The default `AccessSecret` uses `exec.CommandContext("gcloud", "secrets", "versions", "access", "latest", "--secret="+name, "--project=ethans-services")` and maps errors as tested. The legacy path calls `godotenv.Load(".env."+ENV or "local")`, which does not override, then reads `DATABASE_URL`. `GetDatastore(t)` calls `store.New(t.URL)`.
- [ ] **Step 4: Wire the CLI.**
  - Add the root persistent flags.
  - `openDatastore` calls `ResolveTarget(cmd.Context() or Background, flagEnv, flagDatabaseURL, true)`, prints `Describe()` to stderr, then `GetDatastore`.
  - Store the target in package var `target` for later use.
- [ ] **Step 5:** `go test ./cmd/identity-cli/...` and `go test -tags integration -run TestCLI ./cmd/identity-cli/cmd/`. Expect PASS; the existing test still works through the legacy `DATABASE_URL` path.

### Task 2: Shared operations layer

**Files:**
- Create: `cmd/identity-cli/internal/ops/clients.go`, `ops/resources.go`, `ops/fingerprint.go`, `ops/ops_integration_test.go`
- Modify: `cmd/identity-cli/cmd/client_create.go`, `client_update.go`, `client_delete.go`, `client_get.go`, `client_resources.go` (helpers move to ops), `resource.go`, `resource_edit.go`; `.github/workflows/pull_request.yaml` (add `./cmd/identity-cli/internal/ops/`)

**Interfaces:**
- Consumes: `internal.ValidateRedirectURIs`, `ValidateAdminScopes`, `ValidateTrustable`, `ParseResourceScopes`, `MergeScopes`, `RemoveScopes`, `ScopesJSON`, `ParseScopes`, `AppendUnique`, `RemoveValues`, `GenerateRandomString`; `resourceuri.ValidateNew/Canonicalize`; `auth.HashClientSecret`.
- Produces (package `ops`):
  - `var ErrStale = errors.New("changed since it was reviewed")`
  - `type EditMode int` with consts `Keep, Replace, Add, Remove`; `type ListEdit struct { Mode EditMode; Values []string }`
  - `type ClientDetail struct { Client db.OauthClient; Resources []db.OauthResource }` and `func (d ClientDetail) Fingerprint() string`: sha256 hex over JSON of name, redirect_uris, allowed_scopes, is_confidential, trusted, default_resource, kind, and the sorted allow-list URIs.
  - `type ClientCreate struct { Name string; RedirectURIs, Scopes, Resources []string; Confidential, Trusted bool; DefaultResource string }`
  - `func CreateClient(ctx, s *store.Store, in ClientCreate) (ClientDetail, string /*plaintext secret or ""*/, error)`
  - `type ClientUpdate struct { Name *string; RedirectURIs ListEdit; Scopes *[]string; Confidential *bool; Trusted *bool; DefaultResource *string /* "" clears */; Resources ListEdit; ExpectFingerprint string /* "" = no check */ }`
  - `func UpdateClient(ctx, s, clientID string, u ClientUpdate) (ClientDetail, error)`
  - `func GetClient(ctx, s, clientID string) (ClientDetail, error)`, `func ListClients(ctx, s) ([]db.OauthClient, error)`, `func DeleteClient(ctx, s, clientID string) error`
  - `type ResourceDetail struct { Resource db.OauthResource; Scopes map[string]string; UsedBy []db.ListClientsReferencingResourceRow }` and `func (d ResourceDetail) Fingerprint() string`: name, scopes, dynamic_clients.
  - `func CreateResource(ctx, s, uri, name string, scopes map[string]string, dynamic bool) (ResourceDetail, error)`
  - `type ScopeEdit struct { Mode EditMode; Set map[string]string; Remove []string }`
  - `type ResourceUpdate struct { Name *string; Scopes ScopeEdit; DynamicClients *bool; ExpectFingerprint string }`
  - `func UpdateResource(ctx, s, uri string, u ResourceUpdate) (ResourceDetail, error)`, `GetResource`, `ListResources`, `func DeleteResource(ctx, s, uri string) error` (refuses while `UsedBy` is non-empty, naming the users)
  - `func FindResource(ctx, q *db.Queries, what, raw string) (db.OauthResource, error)`, moved from `cmd/resource.go` unchanged

- [ ] **Step 1: Failing integration tests in `ops_integration_test.go`** (`//go:build integration`, testcontainers set up as in `cmd/resources_cli_integration_test.go`):
  - `TestCLIOpsStaleClientUpdate`: take the fingerprint; add a resource to the allow-list directly via `q.AddClientResource`; `UpdateClient` with that fingerprint and a new Name returns `errors.Is(err, ErrStale)`; the name is unchanged.
  - `TestCLIOpsStaleResourceUpdate`: same shape, with a scope changed directly via `q.UpdateOAuthResource`.
  - `TestCLIOpsClientUpdateReplaceAll`: Replace redirect URIs and resources plus `ExpectFingerprint` = current gives exactly the given lists.
  - `TestCLIOpsTrustRules`: Trusted=true plus a wildcard URI gives an error containing `wildcard`, and nothing is written.
  - `TestCLIOpsDeleteResourceInUse`: the error contains the client's name.
- [ ] **Step 2:** `go test -tags integration -run TestCLIOps ./cmd/identity-cli/internal/ops/`. Expect a FAIL (undefined).
- [ ] **Step 3: Implement ops.**
  - `UpdateClient` and `UpdateResource` run in one transaction.
  - Clients are read with `GetOAuthClientByClientIDForUpdate` and resources locked with `tx.ExecContext("SELECT 1 FROM oauth_resources WHERE uri = $1 FOR UPDATE", uri)`.
  - Then the current detail is re-read inside the transaction and the fingerprint compared, then the existing rules applied in the existing order (from `runClientUpdate`/`runResourceUpdate`).
  - Error texts that named a flag now name the field (`default resource`, `resources`). Messages from `internal.Validate*` are unchanged.
- [ ] **Step 4: Rewire the cobra handlers** to build `ClientCreate`/`ClientUpdate`/`ResourceUpdate` from flags and print the result as before. The CLI-only messages stay in `cmd`: `--default-resource cannot be empty...` and the `nothing was changed` suffixes.
- [ ] **Step 5:** `go vet ./... && go test ./... && go test -tags integration -run 'TestCLI' ./cmd/identity-cli/...`. Expect PASS, including the unchanged `TestCLIResourcesAndAllowLists`.
- [ ] **Step 6:** Add `./cmd/identity-cli/internal/ops/` to the integration step's package list.

### Task 3: UI server shell, security and styling

**Files:**
- Create: `cmd/identity-cli/cmd/ui.go`; `cmd/identity-cli/internal/ui/server.go`, `ui/security.go`, `ui/security_test.go`, `ui/views/layout.templ`, `ui/assets/input.css`, `ui/assets/style.css` (generated), `ui/assets/embed.go`
- Modify: `Makefile` (`css` also builds `ui/assets/style.css`), `.github/workflows/pull_request.yaml` (add `./cmd/identity-cli/internal/ui/`)

**Interfaces:**
- Consumes: `internal.Target`, `internal.ResolveTarget`, `internal.GetDatastore`.
- Produces:
  - `func New(s *store.Store, t internal.Target, port int) (*Server, error)`. It generates `token` and `csrf`, each 32 random bytes as base64url.
  - `func (s *Server) Handler() http.Handler`, `func (s *Server) StartURL() string` (`http://127.0.0.1:<port>/?token=<token>`).
  - The `views.Layout(env EnvBanner, title string, csrf string)` templ component, where `type EnvBanner struct { Label string; Prod bool; Custom bool }`.
  - Cookie name `identity_ui_<port>`; hidden form field and check `csrf`.
  - `identity-cli ui [--port 8765]` honours root `--env`/`--database-url`, defaults `--env staging` when both are empty, calls `ResolveTarget(..., allowLegacy=false)`, prints `Describe()` and the start URL, runs `open <url>` on darwin, and serves until interrupted.

- [ ] **Step 1: Failing tests `TestUISecurity*`** (unit, no DB; wrap a stub handler with the middleware):
  - Host `evil.example:8765` gives 403, even with a valid cookie.
  - With no cookie and no token, GET `/clients` gives 403.
  - GET `/?token=<right>` gives a 303 to `/` and sets an `HttpOnly`, `SameSite=Strict` cookie.
  - A wrong token gives 403.
  - A POST with the cookie but without `csrf`, or with a wrong one, gives 403; with both it gives 200.
  - Hosts `localhost:8765` and `127.0.0.1:8765` are accepted.
- [ ] **Step 2:** `go test ./cmd/identity-cli/internal/ui/ -run TestUISecurity`. Expect a FAIL.
- [ ] **Step 3: Implement the middleware**, comparing tokens with `subtle.ConstantTimeCompare`. Then the layout:
  - The top bar shows the env badge: red `PROD`, amber `STAGING`, grey `CUSTOM: <host>`.
  - The `<title>` is prefixed `[PROD] ` in prod.
  - Nav links: Clients, Resources.
  - The stylesheet is served from `/assets/style.css` (embedded).
  - `ui/assets/input.css`: `@import "tailwindcss"; @plugin "daisyui" { themes: light --default, dark --prefersdark; } @source "../views";`. The body layout must not be centred: this is a full-width admin layout, unlike `static/input.css`.
- [ ] **Step 4:** `templ generate && make css && go test ./cmd/identity-cli/internal/ui/ && go build ./cmd/identity-cli`. Expect PASS.

### Task 4: Client pages

**Files:**
- Create: `ui/clients.go`, `ui/diff.go`, `ui/diff_test.go`, `ui/form.go` (parsing helpers), `ui/views/clients.templ`, `ui/ui_integration_test.go`

**Interfaces:**
- Consumes: Task 2 `ops` client functions and `ErrStale`; Task 3 `Layout`, middleware and `csrf` field.
- Produces:
  - Routes: `GET /` redirects to `/clients`; `GET /clients`; `GET /clients/new`; `POST /clients/new`; `GET /client?id=`; `POST /client/review?id=`; `POST /client/apply?id=`; `GET /client/delete?id=`; `POST /client/delete?id=`.
  - `type Change struct { Field string; Before, After string; Added, Removed []string }`
  - `func DiffClient(cur ops.ClientDetail, u ops.ClientUpdate) []Change`
  - `func ParseLines(s string) []string`: splits on newlines and commas, trims, drops empties, dedupes, keeps order.

- [ ] **Step 1: Failing unit tests**:
  - `TestDiffClient`: redirect URIs `[a,b]` replaced by `[b,c]` give a change with `Added=[c]`, `Removed=[a]`; a name change gives `Before`/`After`; an unchanged form gives no changes.
  - `TestParseLines`: `"a\n\n b ,a\r\n"` gives `[a b]`.
- [ ] **Step 2: Failing integration tests in `ui_integration_test.go`** (`TestCLIUI...`; testcontainers; `httptest` with the real `Handler()`; a helper does the token login and carries the cookie and `csrf`):
  - `TestCLIUIClientEditFlow`: POST review with a changed name and one redirect URI removed. The response shows both and the DB is unchanged. POST apply with the hidden fields from that page. The DB matches.
  - `TestCLIUIStaleApply`: review, then change the allow-list directly in the DB, then apply. The response contains `changed since you reviewed it`, and the name is unchanged.
  - `TestCLIUICreateConfidentialShowsSecret`: the response contains the secret once, and `GetClient` has `ClientSecret.Valid`.
  - `TestCLIUICIMDReadOnly`: `GET /client?id=<cimd url>` has no edit form, and POST review gives 400.
  - `TestCLIUIProdDeleteNeedsName`: with a server whose `Target.Name=="prod"`, delete without the typed name keeps the client; with it, the client is deleted.
- [ ] **Step 3: Implement.**
  - The edit form fields follow spec §4.
  - The review handler builds an `ops.ClientUpdate` with Replace edits and pointers only for the fields that differ, renders the diff, and carries the proposed values plus `ExpectFingerprint` as hidden fields.
  - Apply re-parses the hidden fields and calls `ops.UpdateClient`. On `ErrStale` it re-renders review against the current record with the banner "This client changed since you reviewed it — check the changes again." A validation error re-renders the form with the message.
  - Trusted checkbox help text: "Only for apps you build and control, with exact non-loopback redirect URIs. Never MCP/AI or third-party clients." plus a link to README#trusted-first-party-clients on GitHub.
  - Confidential is read-only on edit. The secret is shown once after create, with "Save this now — it cannot be retrieved later."
- [ ] **Step 4:** `templ generate && make css && go test ./cmd/identity-cli/internal/ui/ && go test -tags integration -run TestCLIUI ./cmd/identity-cli/internal/ui/`. Expect PASS.

### Task 5: Resource pages

**Files:**
- Create: `ui/resources.go`, `ui/views/resources.templ`; extend `ui/diff.go`, `diff_test.go`, `ui_integration_test.go`

**Interfaces:**
- Consumes: Task 2 resource ops; Task 4 `Change`, `ParseLines` and the review/apply pattern.
- Produces:
  - Routes: `GET /resources`, `GET|POST /resources/new`, `GET /resource?uri=`, `POST /resource/review?uri=`, `POST /resource/apply?uri=`, `POST /resource/delete?uri=`.
  - `func DiffResource(cur ops.ResourceDetail, u ops.ResourceUpdate) []Change`. Scopes are listed as `name: description` strings in Added/Removed; a changed description counts as one removed and one added.

- [ ] **Step 1: Failing tests**:
  - `TestDiffResource` covers the scope add/remove/redescribe cases.
  - `TestCLIUIResourceEditFlow` covers adding a scope row and removing one, then review, then apply.
  - `TestCLIUIResourceDeleteInUse`: the response names the client, and the resource still exists.
- [ ] **Step 2:** Run them and expect a FAIL.
- [ ] **Step 3: Implement.**
  - The scopes editor is N rows of `scope_name[]`/`scope_desc[]` inputs plus 3 blank rows; blank rows are ignored.
  - The URI is read-only after create.
  - The "Used by" list links to each client.
  - The review and apply flow is the same as for clients, with `ops.ScopeEdit{Mode: Replace}`.
- [ ] **Step 4:** Run as in Task 4 Step 4. Expect PASS.

### Task 6: Docs and full verification

**Files:** Modify `README.md` (an "Admin panel" subsection under OAuth Client Management; `--env` in the CLI examples), `CLAUDE.md` (Conventions: `identity-cli ui` is the panel, and rules go in `internal/ops`).

- [ ] **Step 1:** Write the docs.
- [ ] **Step 2:** Run `make lint && make test && go test -tags integration -run 'TestCLI' ./cmd/identity-cli/... && templ generate && git status`. Expect everything to PASS, and no stray drift beyond the intended files.
- [ ] **Step 3:** Smoke test against a testcontainer or local DB: `go run ./cmd/identity-cli --database-url <url> ui`. Load it in a browser and create, edit, review and apply a client and a resource. Hand over to the user for staging testing.
