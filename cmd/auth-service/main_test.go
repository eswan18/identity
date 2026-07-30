package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests build the real binary and run it, because the thing under test is
// argv handling in main() — which of the two paths a given command line takes.
// Both paths are pointed at an unreachable database so neither can do anything;
// what each assertion looks for is the log line that only one path can produce:
//
//	serve path   -> "Failed to create datastore" (config, then store.New)
//	migrate path -> "Applying migrations up to version"
//
// The k8s Deployments run the binary bare, so the bare case is the one that
// must not drift.

const testJWTPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICQMNHONu2Sud2tu6jgOZs3LIj5yOZr89NBMLYiyqBK/oAoGCCqGSM49
AwEHoUQDQgAERCHWHrX20emk31HypGNgptwBjdZOyBybV/9BLTbJPj8UsZ/46ri5
/eFKkRfNApxFU/5lk1RGQJqt8t0GvkkJdw==
-----END EC PRIVATE KEY-----`

const (
	serveMarker   = "Failed to create datastore"
	migrateMarker = "Applying migrations up to version"
)

// buildAuthService compiles this package into a temporary binary.
func buildAuthService(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "auth-service")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// unreachableDatabaseURL returns a Postgres URL pointing at a local port that
// was just closed, so connecting fails immediately rather than hanging.
func unreachableDatabaseURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a closed port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("closing reserved port: %v", err)
	}
	return "postgres://identity:identity@" + addr + "/identity?sslmode=disable&connect_timeout=2"
}

// runAuthService runs the built binary with a fully explicit environment (so
// nothing leaks in from the developer's shell) and an empty working directory
// (so no .env file is picked up), and returns its combined output.
func runAuthService(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = t.TempDir()
	cmd.Env = []string{
		"HTTP_ADDRESS=:8080",
		"DATABASE_URL=" + unreachableDatabaseURL(t),
		"JWT_PRIVATE_KEY=" + testJWTPrivateKey,
		"JWT_ISSUER=http://localhost:8080",
		"PATH=" + os.Getenv("PATH"),
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestBareInvocationTakesServePath is the regression guard for the default
// behavior: adding subcommand handling must not change what happens when the
// binary is run with no arguments, which is how prod and staging run it.
func TestBareInvocationTakesServePath(t *testing.T) {
	out, err := runAuthService(t, buildAuthService(t))
	if err == nil {
		t.Fatalf("expected a nonzero exit against an unreachable database, got success\n%s", out)
	}
	if !strings.Contains(out, serveMarker) {
		t.Errorf("bare invocation did not take the serve path; want output containing %q, got:\n%s", serveMarker, out)
	}
	if strings.Contains(out, migrateMarker) {
		t.Errorf("bare invocation must never apply migrations, but output contains %q:\n%s", migrateMarker, out)
	}
}

// TestMigrateSubcommandTakesMigratePath confirms `migrate` runs the migration
// runner and nothing else — in particular it never starts the server.
func TestMigrateSubcommandTakesMigratePath(t *testing.T) {
	out, err := runAuthService(t, buildAuthService(t), "migrate")
	if err == nil {
		t.Fatalf("expected a nonzero exit against an unreachable database, got success\n%s", out)
	}
	if !strings.Contains(out, migrateMarker) {
		t.Errorf("`migrate` did not take the migrate path; want output containing %q, got:\n%s", migrateMarker, out)
	}
	if !strings.Contains(out, "Migration failed") {
		t.Errorf("`migrate` should report a clear failure against an unreachable database, got:\n%s", out)
	}
	if strings.Contains(out, serveMarker) {
		t.Errorf("`migrate` must not fall through to the serve path, but output contains %q:\n%s", serveMarker, out)
	}
}

// TestUnknownArgumentsFail keeps a typo or a stale argument from silently
// starting the server (or silently doing nothing) instead of being reported.
func TestUnknownArgumentsFail(t *testing.T) {
	bin := buildAuthService(t)

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"unknown subcommand":       {args: []string{"serve"}, want: "Unknown command"},
		"extra args after migrate": {args: []string{"migrate", "--all"}, want: "Unexpected arguments"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := runAuthService(t, bin, tc.args...)
			if err == nil {
				t.Fatalf("expected a nonzero exit for %v, got success\n%s", tc.args, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("want output containing %q, got:\n%s", tc.want, out)
			}
			if strings.Contains(out, serveMarker) || strings.Contains(out, migrateMarker) {
				t.Errorf("%v should be rejected, not run, got:\n%s", tc.args, out)
			}
		})
	}
}
