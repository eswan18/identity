package cmd

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/eswan18/identity/cmd/identity-cli/internal"
	"github.com/eswan18/identity/pkg/db"
	"github.com/spf13/cobra"
)

var (
	updateName               string
	updateRedirectURIs       string
	updateAddRedirectURIs    string
	updateRemoveRedirectURIs string
	updateAllowedScopes      string
	updateIsConfidential     bool
	updateDefaultResource    string
	updateClearDefaultRes    bool
)

var clientUpdateCmd = &cobra.Command{
	Use:   "update <client-id>",
	Short: "Update an OAuth client",
	Long: `Update an OAuth client. Only provided fields will be updated.
Use --confidential=true or --confidential=false to change confidentiality status.
--redirect-uris REPLACES the client's full redirect-URI list; use
--add-redirect-uris to append to it instead (already-present URIs are skipped),
or --remove-redirect-uris to drop entries from it. Removing a URI the client
does not have is an error and leaves the client unchanged, so a typo can't look
like a successful revocation.
--default-resource points the client's tokens at another registered resource;
--clear-default-resource removes the default, so its tokens are for identity
itself. Either affects tokens issued from then on: a refresh keeps the resource
the original token was issued for.`,
	Args: cobra.ExactArgs(1),
	RunE: runClientUpdate,
	Example: `  # Update client name
  identity-client client update abc123 --name "New Name"

  # Replace the full redirect-URI list
  identity-client client update abc123 --redirect-uris "https://example.com/callback"

  # Append redirect URIs, keeping the existing ones
  identity-client client update abc123 --add-redirect-uris "https://example.com/"

  # Remove redirect URIs, keeping the rest
  identity-client client update abc123 --remove-redirect-uris "https://old.example.com/callback"

  # Point the client's tokens at a registered resource, or at identity itself
  identity-client client update abc123 --default-resource "https://api.example.com"
  identity-client client update abc123 --clear-default-resource

  # Update multiple fields
  identity-client client update abc123 --name "New Name" --scopes "openid,profile"`,
}

func init() {
	clientUpdateCmd.Flags().StringVar(&updateName, "name", "", "Client name")
	clientUpdateCmd.Flags().StringVar(&updateRedirectURIs, "redirect-uris", "", "Comma-separated list of redirect URIs (replaces the full list)")
	clientUpdateCmd.Flags().StringVar(&updateAddRedirectURIs, "add-redirect-uris", "", "Comma-separated redirect URIs to append to the existing list")
	clientUpdateCmd.Flags().StringVar(&updateRemoveRedirectURIs, "remove-redirect-uris", "", "Comma-separated redirect URIs to remove from the existing list")
	clientUpdateCmd.Flags().StringVar(&updateAllowedScopes, "scopes", "", "Comma-separated list of allowed scopes")
	clientUpdateCmd.Flags().BoolVar(&updateIsConfidential, "confidential", false, "Whether the client is confidential")
	clientUpdateCmd.Flags().StringVar(&updateDefaultResource, "default-resource", "", "URI of a registered resource its tokens are for by default")
	clientUpdateCmd.Flags().BoolVar(&updateClearDefaultRes, "clear-default-resource", false, "Remove the default resource (tokens are for identity itself)")
	clientUpdateCmd.MarkFlagsMutuallyExclusive("redirect-uris", "add-redirect-uris", "remove-redirect-uris")
	clientUpdateCmd.MarkFlagsMutuallyExclusive("default-resource", "clear-default-resource")
}

func runClientUpdate(cmd *cobra.Command, args []string) error {
	clientID := args[0]

	datastore := getDatastore()

	ctx := context.Background()

	// Get current client to preserve values
	currentClient, err := datastore.Q.GetOAuthClientByClientID(ctx, clientID)
	if err != nil {
		return fmt.Errorf("failed to get OAuth client: %w", err)
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
	removeRedirectURIsSet := flags.Changed("remove-redirect-uris")
	scopesSet := flags.Changed("scopes")
	confidentialSet := flags.Changed("confidential")

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
	} else if removeRedirectURIsSet {
		remaining, notFound := internal.RemoveValues(
			currentClient.RedirectUris, internal.ParseList(updateRemoveRedirectURIs),
		)
		if len(notFound) > 0 {
			return fmt.Errorf(
				"client %s has no such redirect URI: %s - nothing was changed",
				clientID, strings.Join(notFound, ", "),
			)
		}
		params.RedirectUris = remaining
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

	// The default resource is left alone unless asked; clearing it sets NULL,
	// which is why the query takes an explicit "set" flag rather than treating
	// NULL as "unchanged" like the fields above.
	switch {
	case flags.Changed("clear-default-resource") && updateClearDefaultRes:
		params.SetDefaultResource = true
		params.DefaultResource = sql.NullString{}
	case flags.Changed("default-resource"):
		if updateDefaultResource == "" {
			return errors.New("--default-resource cannot be empty; use --clear-default-resource to remove the default")
		}
		defaultResource, err := resolveDefaultResource(ctx, updateDefaultResource)
		if err != nil {
			return err
		}
		params.SetDefaultResource = true
		params.DefaultResource = defaultResource
	}

	// Apply the same admin-scope rule as create, against the effective values
	// (a flag that was not passed keeps the client's current setting), so an
	// update cannot arrive at a combination create would have refused.
	if err := internal.ValidateAdminScopes(params.AllowedScopes, params.IsConfidential.Bool); err != nil {
		return err
	}

	// Validate: confidential clients must have secrets
	if params.IsConfidential.Bool && !currentClient.ClientSecret.Valid {
		// Note: We can't update the secret with the current UpdateOAuthClient query
		// This would require a separate query or updating the SQL
		return errors.New("cannot make a public client confidential - secret generation not yet supported in update")
	}

	// Validate redirect URIs if they were modified
	if redirectURIsSet || addRedirectURIsSet {
		if err := internal.ValidateRedirectURIs(params.RedirectUris); err != nil {
			return err
		}
	}

	updatedClient, err := datastore.Q.UpdateOAuthClient(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to update OAuth client: %w", err)
	}

	fmt.Println("\n✅ OAuth client updated successfully!")
	fmt.Println("\nUpdated Client Details:")
	fmt.Printf("  Client ID:      %s\n", updatedClient.ClientID)
	fmt.Printf("  Name:           %s\n", updatedClient.Name)
	fmt.Printf("  Redirect URIs:  %s\n", strings.Join(updatedClient.RedirectUris, ", "))
	fmt.Printf("  Allowed Scopes: %s\n", strings.Join(updatedClient.AllowedScopes, ", "))
	fmt.Printf("  Default Resource: %s\n", internal.DefaultResourceValue(updatedClient.DefaultResource))
	fmt.Printf("  Confidential:   %v\n", updatedClient.IsConfidential)
	fmt.Printf("  Updated:        %s\n", updatedClient.UpdatedAt.Format("2006-01-02 15:04:05"))
	if len(updatedClient.RedirectUris) == 0 {
		fmt.Println("\n⚠️  This client now has no redirect URIs and cannot complete an authorization flow until one is added.")
	}
	fmt.Println()

	return nil
}
