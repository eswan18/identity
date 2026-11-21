package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/eswan18/identity/cmd/identity-cli/internal"
	"github.com/eswan18/identity/cmd/identity-cli/internal/ops"
	"github.com/spf13/cobra"
)

var (
	createName           string
	createRedirectURIs   string
	createAllowedScopes  string
	createIsConfidential bool
	createDefaultRes     string
	createResources      string
	createTrusted        bool
)

var clientCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new OAuth client",
	Long: `Create a new OAuth client in the identity service database.
Generates a client_id and optionally a client_secret for confidential clients.

--default-resource names the registered resource (see 'identity-cli resource
list') the client's access tokens are for when a request names none; it becomes
the tokens' aud. Without it, the client's access tokens are for identity itself
(aud = identity's issuer), which is right for a client that only signs users in.

--resources is the client's allow-list: other registered resources it may ask
for by name with the resource parameter (RFC 8707). Its default is always
allowed and need not be listed. A requested scope that is not one of identity's
own must be defined by the resource the request is for AND be in --scopes.

--trusted marks a first-party client: it skips the consent screen and is not
listed on users' Connected Apps page. Only for an app the identity operator
builds and controls (its code and every redirect URI) -- never a third-party,
MCP or AI client. Its redirect URIs must all be exact and not loopback (no
wildcard, no localhost/127.x/[::1]); anything else is refused. Read README,
"Trusted (first-party) clients", first. The default is untrusted.`,
	Example: `  # Register a public client (web app) whose tokens are for an API
  identity-cli client create --name "My Web App" --redirect-uris "http://localhost:3000/callback" --scopes "openid,profile,email" --default-resource "https://api.myapp.com"

  # Register Claude Code (a native app on loopback) for an MCP server
  identity-cli client create --name "Claude Code" --redirect-uris "http://localhost/callback" --scopes "sensibility:read,sensibility:write" --resources "https://sensibility.money/mcp"

  # Register the operator's own first-party web app (skips consent; read README first)
  identity-cli client create --name "My Own App" --redirect-uris "https://app.example.com/callback" --scopes "openid,profile,email" --trusted

  # Register a confidential client that only signs users in
  identity-cli client create --name "My Backend" --redirect-uris "http://localhost:3000/callback" --scopes "openid" --confidential`,
	RunE: runClientCreate,
}

func init() {
	clientCreateCmd.Flags().StringVar(&createName, "name", "", "Client name (required)")
	clientCreateCmd.Flags().StringVar(&createRedirectURIs, "redirect-uris", "", "Comma-separated list of redirect URIs (required)")
	clientCreateCmd.Flags().StringVar(&createAllowedScopes, "scopes", "openid", "Comma-separated list of allowed scopes (default: openid)")
	clientCreateCmd.Flags().BoolVar(&createIsConfidential, "confidential", false, "Whether the client is confidential (requires client_secret)")
	clientCreateCmd.Flags().StringVar(&createDefaultRes, "default-resource", "", "URI of a registered resource its tokens are for by default (omit: identity itself)")
	clientCreateCmd.Flags().StringVar(&createResources, "resources", "", "Comma-separated URIs of registered resources it may request by name (its allow-list)")

	clientCreateCmd.Flags().BoolVar(&createTrusted, "trusted", false, "First-party client: skip consent and hide from Connected Apps (README, \"Trusted (first-party) clients\")")

	clientCreateCmd.MarkFlagRequired("name")
	clientCreateCmd.MarkFlagRequired("redirect-uris")
}

func runClientCreate(cmd *cobra.Command, args []string) error {
	detail, plaintextSecret, err := ops.CreateClient(context.Background(), getDatastore(), ops.ClientCreate{
		Name:            createName,
		RedirectURIs:    internal.ParseList(createRedirectURIs),
		Scopes:          internal.ParseList(createAllowedScopes),
		Resources:       internal.ParseList(createResources),
		Confidential:    createIsConfidential,
		Trusted:         createTrusted,
		DefaultResource: createDefaultRes,
	})
	if err != nil {
		return err
	}
	client := detail.Client

	// Output credentials
	fmt.Println("\n✅ OAuth client registered successfully!")
	fmt.Println("\nClient Details:")
	fmt.Printf("  Name:           %s\n", client.Name)
	fmt.Printf("  Client ID:      %s\n", client.ClientID)
	if plaintextSecret != "" {
		// Print the plaintext secret (only the hash is stored in the database).
		fmt.Printf("  Client Secret:  %s\n", plaintextSecret)
		fmt.Println("\n⚠️  IMPORTANT: Save the client_secret now - it cannot be retrieved later!")
	} else {
		fmt.Println("  Client Secret:  (none - public client)")
	}
	fmt.Printf("  Redirect URIs:  %s\n", strings.Join(client.RedirectUris, ", "))
	fmt.Printf("  Allowed Scopes: %s\n", strings.Join(client.AllowedScopes, ", "))
	fmt.Printf("  Default Resource: %s\n", internal.DefaultResourceValue(client.DefaultResource))
	fmt.Printf("  Allowed Resources: %s\n", allowedResourcesValue(detail.Resources))
	fmt.Printf("  Confidential:   %v\n", client.IsConfidential)
	fmt.Printf("  Trusted:        %v\n", client.Trusted)
	fmt.Printf("  Created:        %s\n", client.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Println()

	return nil
}
