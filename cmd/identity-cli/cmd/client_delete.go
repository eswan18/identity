package cmd

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	deleteForce bool
)

var clientDeleteCmd = &cobra.Command{
	Use:   "delete <client-id>",
	Short: "Delete an OAuth client",
	Long:  `Delete an OAuth client from the identity service database.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runClientDelete,
	Example: `  # Delete a client (with confirmation)
  identity-client client delete abc123

  # Delete a client without confirmation
  identity-client client delete abc123 --force`,
}

func init() {
	clientDeleteCmd.Flags().BoolVar(&deleteForce, "force", false, "Skip confirmation prompt")
}

func runClientDelete(cmd *cobra.Command, args []string) error {
	clientID := args[0]

	datastore := getDatastore()
	if datastore == nil {
		log.Fatal("Failed to get database connection")
	}

	ctx := context.Background()

	// Get client to show what we're deleting
	client, err := datastore.Q.GetOAuthClientByClientID(ctx, clientID)
	if err != nil {
		log.Fatalf("Failed to get OAuth client: %v", err)
	}

	// Confirm deletion unless --force
	if !deleteForce {
		fmt.Printf("Are you sure you want to delete client '%s' (%s)? [y/N]: ", client.Name, clientID)
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Failed to read input: %v", err)
		}
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Deletion cancelled.")
			return nil
		}
	}

	// Delete the client
	err = datastore.Q.DeleteOAuthClient(ctx, clientID)
	if err != nil {
		log.Fatalf("Failed to delete OAuth client: %v", err)
	}

	fmt.Printf("\n✅ OAuth client '%s' (%s) deleted successfully!\n\n", client.Name, clientID)
	return nil
}
