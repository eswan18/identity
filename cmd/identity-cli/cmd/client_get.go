package cmd

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/spf13/cobra"
)

var clientGetCmd = &cobra.Command{
	Use:   "get <client-id>",
	Short: "Get details of an OAuth client",
	Long:  `Get detailed information about a specific OAuth client by its client_id.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runClientGet,
}

func runClientGet(cmd *cobra.Command, args []string) error {
	clientID := args[0]

	datastore := getDatastore()
	if datastore == nil {
		log.Fatal("Failed to get database connection")
	}

	ctx := context.Background()
	client, err := datastore.Q.GetOAuthClientByClientID(ctx, clientID)
	if err != nil {
		log.Fatalf("Failed to get OAuth client: %v", err)
	}

	fmt.Println("\nClient Details:")
	fmt.Printf("  ID:             %s\n", client.ID)
	fmt.Printf("  Client ID:      %s\n", client.ClientID)
	fmt.Printf("  Name:           %s\n", client.Name)
	if client.ClientSecret.Valid {
		fmt.Println("  Client Secret:  (hidden - cannot be retrieved)")
	} else {
		fmt.Println("  Client Secret:  (none - public client)")
	}
	fmt.Printf("  Redirect URIs:  %s\n", strings.Join(client.RedirectUris, ", "))
	fmt.Printf("  Allowed Scopes: %s\n", strings.Join(client.AllowedScopes, ", "))
	fmt.Printf("  Audience:       %s\n", client.Audience)
	fmt.Printf("  Confidential:   %v\n", client.IsConfidential)
	fmt.Printf("  Created:        %s\n", client.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Updated:        %s\n", client.UpdatedAt.Format("2006-01-02 15:04:05"))
	fmt.Println()

	return nil
}
