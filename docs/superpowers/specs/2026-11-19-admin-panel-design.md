# Local admin panel for clients and resources

Status: design, 2026-11-19

## Why

Managing OAuth clients and resources means running `identity-cli` with long
flag lists (`client update <id> --add-resources ... --remove-redirect-uris ...`)
and, before every session, copying the right database URL into
`DATABASE_URL` by hand. Both are tedious, and the second puts the prod
connection string on the clipboard and in shell history. The operator wants a
small UI for this, used from their own laptop.

## Goals

- A browser UI, started from `identity-cli`, for listing, creating, editing
  and deleting OAuth clients and resources in staging or prod.
- No more copying database URLs: the CLI finds the URL for an environment
  itself, for the UI and for every existing subcommand.
- The UI and the CLI enforce exactly the same rules (trusted-client checks,
  wildcard validation, admin-scope check, resource-URI canonicalisation,
  "refuse to delete a resource that's still in use"). The rules live in one
  place.

## Non-goals

- Hosting the panel anywhere, using it from a phone, or any login. It is a
  local process run by someone who already has database access.
- Users, tokens, consents. Clients and resources only.
- Syncing or copying a client between staging and prod. (Possible follow-up;
  staging's DB is periodically replaced by a copy of prod's, so client IDs
  often match, but not for clients created separately in each.)
- Features the CLI does not have today, such as rotating a client secret or
  turning a public client into a confidential one.

## Anti-goals (a failure even if it works)

- Any HTTP endpoint on the identity **server** that edits clients or
  resources. The rule in CLAUDE.md and the README ("OAuth clients are created
  and edited only with identity-cli; no HTTP endpoint edits them", and only the
  CLI sets `trusted`) stays true. The panel is part of `identity-cli`, not of
  `auth-service`.
- A second copy of the validation rules that can drift from the CLI's.
- A localhost server that any web page the operator visits can drive (CSRF or
  DNS rebinding against `127.0.0.1`).
- A prod edit that is easy to make by accident, or a change whose effect isn't
  shown before it is written (for example, a redirect URI quietly removed
  because a textarea was edited).

## Approaches considered

1. **A local panel in `identity-cli` (chosen).** `identity-cli ui` serves on
   localhost, talks to the database directly as the CLI does, and reuses the
   CLI's validation. Nothing new faces the internet and the server-side rule
   is untouched. It only works from the operator's laptop, which is fine for
   this.
2. **A hosted admin console** in the identity server, on a second
   tailnet-only listener (the Keycloak/Hydra pattern), with login through
   identity. It would work from a phone, but it needs an admin-user concept,
   reverses the "no HTTP endpoint edits clients" rule, adds attack surface on
   the most sensitive service, and wants an audit log. Too much for removing
   some typing.
3. **Only fix the friction**: add `--env` to the CLI. Small, but the flag
   lists remain, which is half the complaint. It is included in approach 1
   anyway.

## Design

### 1. Database URL by environment (all subcommands)

- New persistent flag on the root command: `--env staging|prod`.
- With `--env`, the CLI gets the URL by running
  `gcloud secrets versions access latest --secret=identity_<env>_database_url`
  (project `ethans-services`). It uses the operator's existing gcloud login and
  adds no Go dependency. If gcloud is missing or not logged in, the error says
  so and says what to run.
- Without `--env`, behaviour is unchanged: `DATABASE_URL` (with the existing
  `ENV` / `.env.<env>` loading) is used. Local development and the existing
  integration tests keep working.
- `internal.GetDatastore` currently goes through `config.NewFromEnv()`, which
  `log.Fatal`s without `HTTP_ADDRESS`, `JWT_PRIVATE_KEY` and `JWT_ISSUER`, none
  of which the CLI needs. The CLI should read only the database URL.
- Every command prints which database it is using (to stderr) before doing
  anything, so it is always visible whether a command hit prod: `env: prod
  (secret identity_prod_database_url, host <host>)` with `--env`, or `env:
  ENV=<value or unset> (DATABASE_URL, host <host>)` without it.

### 2. One shared implementation of the operations

Today the mutation logic sits inside the cobra `RunE` functions
(`runClientCreate`, `runClientUpdate`, `runResourceUpdate`, ...) and reads flag
globals and `cmd.Flags().Changed`. Move it into a package both front ends call,
under `cmd/identity-cli/internal/` (for example `internal/ops`). It should
have typed inputs where "unset" means "leave alone":

- `CreateClient(ctx, store, ClientCreate) (Client, plaintextSecret, error)`
- `UpdateClient(ctx, store, clientID, ClientUpdate) (Client, error)`. Each field
  is optional. Redirect URIs, allowed scopes and allowed resources are each
  either replaced or edited by add/remove, as with the flags. The default
  resource can be set, cleared, or left alone.
- `DeleteClient`, `GetClient` (including allowed resources), `ListClients`
- `CreateResource`, `UpdateResource`, `DeleteResource` (refuses while in use),
  `GetResource` (including "used by"), `ListResources`

The CLI becomes a thin layer that turns flags into these inputs and prints the
results. Its behaviour and error messages stay the same, and the existing
`TestCLI...` integration tests must pass unchanged. That is how the refactor
is checked. Messages that name a flag (for example `--default-resource "x": no
resource is registered...`) can name a field instead. The CLI passes the flag
name in, and the UI passes a field label.

### 3. `identity-cli ui`

- `identity-cli ui [--env staging|prod] [--port N]`. Listens on `127.0.0.1`
  only. The default port is fixed (8765) so the URL is predictable. It prints
  the URL and opens the browser (`open` on macOS; otherwise it just prints).
- **Environment.** The panel opens one environment per run, `--env`
  defaulting to staging. Switching means stopping and rerunning with
  `--env prod`, which keeps one connection per process and makes it hard to
  be in prod by accident. Prod pages have an unmistakable banner (a red bar
  saying "PROD") on every page and in the tab title.
  *(Builder-check call)* `ui` **ignores `ENV`, `.env.<env>` files and
  `DATABASE_URL`**, because `.env.prod` exists locally and would let a prod
  session run without the banner. The only other source is an explicit
  `--database-url <url>` (for a local or test database), which gets a neutral
  "CUSTOM: <host>" banner. "Is this prod" is decided in one place, from how the
  URL was chosen, never guessed from the host.
- **Local-server safety.**
  - Startup generates a random token. The printed URL carries it once
    (`/?token=...`), and the server swaps it for an `HttpOnly`, `SameSite=Strict`
    cookie and redirects to the bare URL. Every request without the cookie gets
    a 403. This is the Jupyter model.
  - Requests whose `Host` is not `127.0.0.1:<port>` or `localhost:<port>` are
    refused, which stops DNS rebinding.
  - Every POST also carries a CSRF form token.
- **Rendering.** Server-rendered with templ, styled with the existing
  Tailwind + daisyUI build (`static/style.css`), embedded in the binary so
  `identity-cli` stays one self-contained file. No JavaScript framework.

### 4. Pages

**Clients list**: name, client_id, kind (registered / cimd), public or
confidential, trusted, default resource. CIMD clients are shown but read-only
(their metadata comes from their published document).

**Client form** (create and edit):
- Name.
- Redirect URIs, one per line.
- Allowed scopes, free text, space- or comma-separated.
- Confidential: settable on create; shown read-only on edit. *(Builder-check
  call)* The CLI can make a confidential client public (`--confidential=false`,
  which keeps the old secret hash) but not the reverse. The shared layer keeps
  that ability so the CLI is unchanged, but the panel does not offer it: it is
  rare, it breaks the client's token exchange until the client is
  reconfigured, and it can be added later.
- Default resource: a dropdown of registered resources, plus "identity itself".
- Allowed resources: a checkbox per registered resource.
- Trusted: a checkbox next to a short form of the README's "Trust a client
  only if..." text and a link to that section.

**Review before writing.** Submitting an edit shows a confirmation page with
exactly what will change: each field before and after, redirect URIs added
and removed, resources added and removed. Nothing is written until the
operator confirms. Validation errors appear on this page or the form, using
the shared layer's messages.
*(Builder-check call)* If the record changed between the review and the
confirm (for example the CLI in another terminal, or staging's DB being
replaced), **confirming is refused**: the panel shows "this changed since you
reviewed it" and a fresh review against the current record. The pending
change carries the version it was diffed against (its `updated_at`, or a hash
of its contents if that is not reliable), and the write checks it in the same
transaction. Underneath, the panel applies the diff as explicit replacements
of exactly the reviewed values. The stale check is what makes that safe.
Creating a client or a resource has no review step (there is nothing to
overwrite), but it still validates through the shared layer. Creating a client shows the client_id and, if
confidential, the secret once, with the CLI's "save it now" warning.

**Delete client**: a confirmation page, typing the client's name to confirm in
prod.

**Resources list and form**: URI (set on create, read-only after), name, scopes
as editable name/description rows (add, remove, redescribe), dynamic clients
(a checkbox with a one-line explanation), and "used by" (the clients that
reference it and how). Edits go through the same review page. Delete is
refused, with the list of users, while any client still references the
resource.

### 5. Docs

- README: a short "Admin panel" subsection under OAuth Client Management, and
  `--env` in the CLI examples (in place of `ENV=dev`).
- CLAUDE.md: the "clients are edited only with identity-cli" rule still holds,
  but mention that `identity-cli ui` is the panel and that it shares the
  CLI's operations layer, so a new rule goes there and not in a handler or a
  flag parser.

### 6. Tests

- The existing CLI integration tests stay green, unchanged.
- Integration tests for the shared operations layer against Postgres
  (testcontainers). Name them `TestCLI...`, **and add the new package path to
  the integration-test step in `.github/workflows/pull_request.yaml`**. That
  step lists packages explicitly (`./pkg/httpserver/ ./db/migrations/
  ./cmd/identity-cli/cmd/`), so tests anywhere else silently never run in CI.
- A test that a stale confirm is refused and writes nothing.
- Handler tests for the UI: token/cookie gate, Host check, CSRF, the review
  page's diff, and that confirming applies exactly what was shown.

## Left to the builder

- Exact package layout and type names for the operations layer.
- How the embedded stylesheet is wired in (for example a small `static` Go
  package with `//go:embed style.css`, plus an `@source` line in
  `static/input.css` for the new templ files).
- Whether the review page carries the proposed change as hidden form fields
  or as a server-side pending change keyed by a nonce.
- Page layout and visual detail within the existing daisyUI look.
