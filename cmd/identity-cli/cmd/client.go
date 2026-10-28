package cmd

import (
	"fmt"

	"github.com/eswan18/identity/cmd/identity-cli/internal"
	"github.com/eswan18/identity/pkg/store"
	"github.com/spf13/cobra"
)

// datastore is shared across all client and resource subcommands
var datastore *store.Store

var clientCmd = &cobra.Command{
	Use:                "client",
	Short:              "Manage OAuth clients",
	Long:               `Create, list, get, update, and delete OAuth clients.`,
	PersistentPreRunE:  openDatastore,
	PersistentPostRunE: closeDatastore,
}

// openDatastore connects the shared datastore before a subcommand runs.
func openDatastore(cmd *cobra.Command, args []string) error {
	var err error
	datastore, err = internal.GetDatastore()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	return nil
}

// closeDatastore closes the shared datastore after a subcommand runs.
func closeDatastore(cmd *cobra.Command, args []string) error {
	if datastore != nil {
		return datastore.DB.Close()
	}
	return nil
}

// getDatastore returns the shared datastore instance
func getDatastore() *store.Store {
	return datastore
}

func init() {
	clientCmd.AddCommand(clientCreateCmd)
	clientCmd.AddCommand(clientListCmd)
	clientCmd.AddCommand(clientGetCmd)
	clientCmd.AddCommand(clientUpdateCmd)
	clientCmd.AddCommand(clientDeleteCmd)
}
