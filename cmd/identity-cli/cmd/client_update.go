package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/eswan18/identity/cmd/identity-cli/internal"
	"github.com/eswan18/identity/pkg/db"
	"github.com/spf13/cobra"
)

var (
	updateName            string
	updateRedirectURIs    string
	updateAddRedirectURIs string
	updateAllowedScopes   string
	updateIsConfidential  bool
	updateAudience        string
)

var clientUpdateCmd = &cobra.Command{
	Use:   "update <client-id>",
	Short: "Update an OAuth client",
	Long: `Update an OAuth client. Only provided fields will be updated.
Use --confidential=true or --confidential=false to change confidentiality status.
--redirect-uris REPLACES the client's full redirect-URI list; use
--add-redirect-uris to append to it instead (already-present URIs are skipped).`,
	Args: cobra.ExactArgs(1),
	RunE: runClientUpdate,
	Example: `  # Update client name
  identity-client client update abc123 --name "New Name"

  # Replace the full redirect-URI list
  identity-client client update abc123 --redirect-uris "https://example.com/callback"

  # Append redirect URIs, keeping the existing ones
  identity-client client update abc123 --add-redirect-uris "https://example.com/"

  # Update multiple fields
  identity-client client update abc123 --name "New Name" --scopes "openid,profile"`,
}

func init() {
	clientUpdateCmd.Flags().StringVar(&updateName, "name", "", "Client name")
	clientUpdateCmd.Flags().StringVar(&updateRedirectURIs, "redirect-uris", "", "Comma-separated list of redirect URIs (replaces the full list)")
	clientUpdateCmd.Flags().StringVar(&updateAddRedirectURIs, "add-redirect-uris", "", "Comma-separated redirect URIs to append to the existing list")
	clientUpdateCmd.Flags().StringVar(&updateAllowedScopes, "scopes", "", "Comma-separated list of allowed scopes")
	clientUpdateCmd.Flags().BoolVar(&updateIsConfidential, "confidential", false, "Whether the client is confidential")
	clientUpdateCmd.Flags().StringVar(&updateAudience, "audience", "", "JWT audience claim for this client")
	clientUpdateCmd.MarkFlagsMutuallyExclusive("redirect-uris", "add-redirect-uris")
}

func runClientUpdate(cmd *cobra.Command, args []string) error {
	clientID := args[0]

	datastore := getDatastore()
	if datastore == nil {
		log.Fatal("Failed to get database connection")
	}

	ctx := context.Background()

	// Get current client to preserve values
	currentClient, err := datastore.Q.GetOAuthClientByClientID(ctx, clientID)
	if err != nil {
		log.Fatalf("Failed to get OAuth client: %v", err)
	}

	// Build update params - only include fields that were provided
	params := db.UpdateOAuthClientParams{
		ClientID: clientID,
	}

	// Check which flags were set
	flags := cmd.Flags()
	nameSet := flags.Changed("name")
	redirectURIsSet := flags.Changed("redirect-uris")
	addRedirectURIsSet := flags.Changed("add-redirect-uris")
	scopesSet := flags.Changed("scopes")
	confidentialSet := flags.Changed("confidential")
	audienceSet := flags.Changed("audience")

	if nameSet {
		params.Name = sql.NullString{String: updateName, Valid: true}
	} else {
		params.Name = sql.NullString{String: currentClient.Name, Valid: true}
	}

	if redirectURIsSet {
		params.RedirectUris = internal.ParseList(updateRedirectURIs)
	} else if addRedirectURIsSet {
		params.RedirectUris = internal.AppendUnique(
			currentClient.RedirectUris, internal.ParseList(updateAddRedirectURIs),
		)
	} else {
		params.RedirectUris = currentClient.RedirectUris
	}

	if scopesSet {
		params.AllowedScopes = internal.ParseList(updateAllowedScopes)
	} else {
		params.AllowedScopes = currentClient.AllowedScopes
	}

	if confidentialSet {
		params.IsConfidential = sql.NullBool{Bool: updateIsConfidential, Valid: true}
	} else {
		params.IsConfidential = sql.NullBool{Bool: currentClient.IsConfidential, Valid: true}
	}

	if audienceSet {
		params.Audience = sql.NullString{String: updateAudience, Valid: true}
	} else {
		params.Audience = sql.NullString{String: currentClient.Audience, Valid: true}
	}

	// Validate: confidential clients must have secrets
	if params.IsConfidential.Bool && !currentClient.ClientSecret.Valid {
		// Note: We can't update the secret with the current UpdateOAuthClient query
		// This would require a separate query or updating the SQL
		log.Fatalf("Cannot make a public client confidential - secret generation not yet supported in update")
	}

	updatedClient, err := datastore.Q.UpdateOAuthClient(ctx, params)
	if err != nil {
		log.Fatalf("Failed to update OAuth client: %v", err)
	}

	fmt.Println("\n✅ OAuth client updated successfully!")
	fmt.Println("\nUpdated Client Details:")
	fmt.Printf("  Client ID:      %s\n", updatedClient.ClientID)
	fmt.Printf("  Name:           %s\n", updatedClient.Name)
	fmt.Printf("  Redirect URIs:  %s\n", strings.Join(updatedClient.RedirectUris, ", "))
	fmt.Printf("  Allowed Scopes: %s\n", strings.Join(updatedClient.AllowedScopes, ", "))
	fmt.Printf("  Audience:       %s\n", updatedClient.Audience)
	fmt.Printf("  Confidential:   %v\n", updatedClient.IsConfidential)
	fmt.Printf("  Updated:        %s\n", updatedClient.UpdatedAt.Format("2006-01-02 15:04:05"))
	fmt.Println()

	return nil
}
