package internal

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/joho/godotenv"
)

// gcpProject is the project that holds identity's Secret Manager secrets.
const gcpProject = "ethans-services"

// Target is the database a command works on, and how it was chosen. How it
// was chosen is what decides whether it is prod: never a guess from the host.
type Target struct {
	// Name is "staging" or "prod" (from --env), "custom" (from
	// --database-url), or "ENV=<value>" (the legacy DATABASE_URL path).
	Name string
	// Source says where the URL came from, for display.
	Source string
	// URL is the connection string. Never print it: it holds the password.
	URL string
}

// IsProd reports whether this target is prod, chosen with --env prod.
func (t Target) IsProd() bool { return t.Name == "prod" }

// Host returns the database host, without credentials, for display.
func (t Target) Host() string {
	u, err := url.Parse(t.URL)
	if err != nil || u.Hostname() == "" {
		return "(unknown host)"
	}
	return u.Hostname()
}

// Describe is the one-line "which database is this" notice every command
// prints before doing anything.
func (t Target) Describe() string {
	return fmt.Sprintf("env: %s (%s, host %s)", t.Name, t.Source, t.Host())
}

// AccessSecret reads the latest version of a Secret Manager secret using the
// operator's own gcloud login. A variable so tests can replace it.
var AccessSecret = func(ctx context.Context, name string) (string, error) {
	out, err := exec.CommandContext(ctx, "gcloud", "secrets", "versions", "access", "latest",
		"--secret="+name, "--project="+gcpProject).Output()
	return string(out), err
}

var errEmptySecret = errors.New("secret is empty")

// ResolveTarget decides which database a command uses.
//
//   - env ("staging" or "prod") reads identity_<env>_database_url from Secret
//     Manager.
//   - databaseURL is used as given.
//   - With neither, and allowLegacy, DATABASE_URL is read the way the CLI
//     always has (after loading .env.<ENV>, default "local"). Without
//     allowLegacy (identity-cli ui) that is an error: the panel must know
//     whether it is in prod, and .env.prod would let it reach prod unlabelled.
func ResolveTarget(ctx context.Context, env, databaseURL string, allowLegacy bool) (Target, error) {
	if env != "" && databaseURL != "" {
		return Target{}, errors.New("use either --env or --database-url, not both")
	}
	switch {
	case env != "":
		if env != "staging" && env != "prod" {
			return Target{}, fmt.Errorf("--env %q: must be staging or prod", env)
		}
		secret := "identity_" + env + "_database_url"
		raw, err := AccessSecret(ctx, secret)
		if err != nil {
			return Target{}, secretError(secret, err)
		}
		value := strings.TrimSpace(raw)
		if value == "" {
			return Target{}, fmt.Errorf("reading %s: %w", secret, errEmptySecret)
		}
		return Target{Name: env, Source: "secret " + secret, URL: value}, nil
	case databaseURL != "":
		return Target{Name: "custom", Source: "--database-url", URL: databaseURL}, nil
	case allowLegacy:
		envName := os.Getenv("ENV")
		if envName == "" {
			envName = "local"
		}
		_ = godotenv.Load(".env." + envName) // does not override variables already set
		value := os.Getenv("DATABASE_URL")
		if value == "" {
			return Target{}, errors.New("no database: pass --env staging|prod, or --database-url, or set DATABASE_URL")
		}
		return Target{Name: "ENV=" + envName, Source: "DATABASE_URL", URL: value}, nil
	default:
		return Target{}, errors.New("no database: pass --env staging|prod or --database-url")
	}
}

// secretError turns a failed gcloud call into an error that says what to do.
func secretError(secret string, err error) error {
	var exitErr *exec.ExitError
	switch {
	case errors.Is(err, exec.ErrNotFound):
		return fmt.Errorf("reading %s: the gcloud CLI is not installed or not on PATH", secret)
	case errors.As(err, &exitErr):
		detail := ""
		if len(exitErr.Stderr) > 0 {
			detail = ": " + strings.TrimSpace(string(exitErr.Stderr))
		}
		return fmt.Errorf("reading %s with gcloud failed%s - if you are not logged in, run `gcloud auth login`", secret, detail)
	default:
		return fmt.Errorf("reading %s: %w", secret, err)
	}
}
