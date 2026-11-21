package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/eswan18/identity/cmd/identity-cli/internal"
	"github.com/eswan18/identity/cmd/identity-cli/internal/ui"
	"github.com/spf13/cobra"
)

var (
	uiPort      int
	uiNoBrowser bool
)

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Open a local admin panel for OAuth clients and resources",
	Long: `Serve an admin panel for OAuth clients and resources on 127.0.0.1 and open
it in the browser. It makes the same changes, with the same rules, as the
client and resource commands; every edit is shown for review before it is
written.

The panel works on one database per run: --env staging (the default) or
--env prod, read from Secret Manager with your gcloud login, or an explicit
--database-url. It ignores ENV, .env files and DATABASE_URL, so a prod session
always says PROD. Run it twice (different --port) to have both open.

Only the browser that opens the printed URL can use it: the URL carries a
one-time token that becomes a session cookie.`,
	Example: `  identity-cli ui
  identity-cli ui --env prod --port 8766
  identity-cli ui --database-url postgres://postgres:postgres@localhost:5432/identity`,
	Args: cobra.NoArgs,
	RunE: runUI,
}

func init() {
	uiCmd.Flags().IntVar(&uiPort, "port", 8765, "Port to listen on (127.0.0.1 only)")
	uiCmd.Flags().BoolVar(&uiNoBrowser, "no-browser", false, "Print the URL without opening a browser")
	rootCmd.AddCommand(uiCmd)
}

func runUI(cmd *cobra.Command, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	env := flagEnv
	if env == "" && flagDatabaseURL == "" {
		env = "staging"
	}
	t, err := internal.ResolveTarget(ctx, env, flagDatabaseURL, false)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, t.Describe())
	ds, err := internal.GetDatastore(t)
	if err != nil {
		return err
	}
	defer ds.DB.Close()
	if err := ds.DB.PingContext(ctx); err != nil {
		return fmt.Errorf("connecting to the database: %w", err)
	}

	panel, err := ui.New(ds, t, uiPort)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(uiPort)))
	if err != nil {
		return fmt.Errorf("listening on 127.0.0.1:%d (try --port): %w", uiPort, err)
	}
	srv := &http.Server{Handler: panel.Handler(), ReadHeaderTimeout: 10 * time.Second}

	fmt.Fprintf(os.Stderr, "\nAdmin panel: %s\n(Ctrl-C to stop)\n\n", panel.StartURL())
	if runtime.GOOS == "darwin" && !uiNoBrowser {
		_ = exec.Command("open", panel.StartURL()).Start()
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
