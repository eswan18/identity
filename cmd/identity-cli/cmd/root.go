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

func init() {
	// Add client command
	rootCmd.AddCommand(clientCmd)
}
