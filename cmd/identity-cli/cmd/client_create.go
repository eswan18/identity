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
	createName           string
	createRedirectURIs   string
	createAllowedScopes  string
	createIsConfidential bool
	createAudience       string
)

var clientCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new OAuth client",
	Long: `Create a new OAuth client in the identity service database.
Generates a client_id and optionally a client_secret for confidential clients.`,
	Example: `  # Register a public client (web app)
  identity-client client create --name "My Web App" --redirect-uris "http://localhost:3000/callback" --scopes "openid,profile,email" --audience "https://myapp.com"

  # Register a confidential client (backend service)
  identity-client client create --name "My Backend" --redirect-uris "http://localhost:3000/callback" --scopes "openid" --confidential --audience "https://api.myapp.com"`,
	RunE: runClientCreate,
}

func init() {
	clientCreateCmd.Flags().StringVar(&createName, "name", "", "Client name (required)")
	clientCreateCmd.Flags().StringVar(&createRedirectURIs, "redirect-uris", "", "Comma-separated list of redirect URIs (required)")
	clientCreateCmd.Flags().StringVar(&createAllowedScopes, "scopes", "openid", "Comma-separated list of allowed scopes (default: openid)")
	clientCreateCmd.Flags().BoolVar(&createIsConfidential, "confidential", false, "Whether the client is confidential (requires client_secret)")
	clientCreateCmd.Flags().StringVar(&createAudience, "audience", "", "JWT audience claim for this client (required)")

	clientCreateCmd.MarkFlagRequired("name")
	clientCreateCmd.MarkFlagRequired("redirect-uris")
	clientCreateCmd.MarkFlagRequired("audience")
}

func runClientCreate(cmd *cobra.Command, args []string) error {
	// Parse comma-separated lists
	redirectURIList := internal.ParseList(createRedirectURIs)
	scopeList := internal.ParseList(createAllowedScopes)

	// Get shared datastore
	datastore := getDatastore()
	if datastore == nil {
		log.Fatal("Failed to get database connection")
	}

	// Generate client_id (random 32-byte string, base64 encoded = 44 chars)
	clientID, err := internal.GenerateRandomString(32)
	if err != nil {
		log.Fatalf("Failed to generate client_id: %v", err)
	}

	// Generate client_secret if confidential
	var clientSecret sql.NullString
	if createIsConfidential {
		secret, err := internal.GenerateRandomString(32)
		if err != nil {
			log.Fatalf("Failed to generate client_secret: %v", err)
		}
		clientSecret = sql.NullString{String: secret, Valid: true}
	}

	// Create the client
	ctx := context.Background()
	client, err := datastore.Q.CreateOAuthClient(ctx, db.CreateOAuthClientParams{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		Name:           createName,
		RedirectUris:   redirectURIList,
		AllowedScopes:  scopeList,
		IsConfidential: createIsConfidential,
		Audience:       createAudience,
	})
	if err != nil {
		log.Fatalf("Failed to create OAuth client: %v", err)
	}

	// Output credentials
	fmt.Println("\n✅ OAuth client registered successfully!")
	fmt.Println("\nClient Details:")
	fmt.Printf("  Name:           %s\n", client.Name)
	fmt.Printf("  Client ID:      %s\n", client.ClientID)
	if client.ClientSecret.Valid {
		fmt.Printf("  Client Secret:  %s\n", client.ClientSecret.String)
		fmt.Println("\n⚠️  IMPORTANT: Save the client_secret now - it cannot be retrieved later!")
	} else {
		fmt.Println("  Client Secret:  (none - public client)")
	}
	fmt.Printf("  Redirect URIs:  %s\n", strings.Join(client.RedirectUris, ", "))
	fmt.Printf("  Allowed Scopes: %s\n", strings.Join(client.AllowedScopes, ", "))
	fmt.Printf("  Audience:       %s\n", client.Audience)
	fmt.Printf("  Confidential:   %v\n", client.IsConfidential)
	fmt.Printf("  Created:        %s\n", client.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Println()

	return nil
}
