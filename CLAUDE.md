# CLAUDE.md

identity is a Go OAuth 2.0 / OpenID Connect provider (chi, Postgres via sqlc,
server-rendered templ pages) for the operator's own apps and for MCP/AI clients.
`README.md` is the operator manual; `docs/client-integration.md` is for client
authors; designs live in `docs/superpowers/specs/`.

> **Creating or editing an OAuth client? Read README → [Trusted (first-party)
> clients](README.md#trusted-first-party-clients) before setting `--trusted`.**
> The default is untrusted. Never trust a third-party client, an MCP/AI client
> (even one registered by hand), or a dynamic/metadata-document (CIMD) client.
> A trusted client gets user data with no consent screen and is hidden from the
> user's Connected Apps page.

## Commands (see the Makefile)

```bash
make build            # identity + identity-cli binaries (also runs docs + css)
make lint             # go vet ./...
make test             # unit tests
make test-integration # -tags integration; needs Docker (testcontainers)
make templ            # after editing pkg/views/*.templ; *_templ.go are committed
make css              # after adding Tailwind classes; static/style.css is committed
make sqlc             # after changing db/migrations or db/queries; pkg/db is committed
make sqlc-check       # what CI runs: fails if pkg/db is stale
```

CI (`.github/workflows/pull_request.yaml`) checks templ output, `make
sqlc-check`, `go vet`, unit tests, and integration tests matching
`TestOAuthFlowSuite|TestAvatarFlowSuite|TestUpAgainstPostgres|TestCLI`; name new
integration tests to match one of those.

## Schema changes

- New migration: `make migrate-new name=...` writes
  `db/migrations/NNNNNN_name.{up,down}.sql`. Write both directions, keep them
  safe while the previous release is still serving, and add a
  `TestUpAgainstPostgres...` test in `db/migrations/` covering up, down and up.
- The server never migrates on startup; it refuses to start against a schema
  at the wrong version (README → Migrations).
- sqlc reads `db/migrations` directly. `oauth_clients` queries list their
  columns explicitly, in table order (see the comment in `db/queries/auth.sql`).
  Run `make sqlc` and commit `pkg/db`.

## Conventions

- Code-issuance preconditions live in `checkCodeIssuance`
  (`pkg/httpserver/code_issuance.go`), shared by authorize and consent; never
  add one to just a handler.
- OAuth clients are created and edited only with `identity-cli`
  (`cmd/identity-cli`); no HTTP endpoint edits them.
