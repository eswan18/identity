package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "identity-cli",
	Short: "Identity service CLI for managing OAuth clients and other resources",
	Long: `Identity service CLI provides commands for managing OAuth clients,
users, tokens, and other resources in the identity service database.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}

// The database every subcommand works on (see internal.ResolveTarget).
var (
	flagEnv         string
	flagDatabaseURL string
)

func init() {
	rootCmd.PersistentFlags().StringVar(&flagEnv, "env", "",
		"Database to use: staging or prod (reads identity_<env>_database_url from Secret Manager with your gcloud login)")
	rootCmd.PersistentFlags().StringVar(&flagDatabaseURL, "database-url", "",
		"Database URL to use instead of --env (default: DATABASE_URL, after loading .env.<ENV>)")

	// Add client command
	rootCmd.AddCommand(clientCmd)
	rootCmd.AddCommand(resourceCmd)
}
