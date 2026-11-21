package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/eswan18/identity/cmd/identity-cli/internal"
	"github.com/eswan18/identity/cmd/identity-cli/internal/ops"
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
	updateResources          string
	updateAddResources       string
	updateRemoveResources    string
	updateTrusted            bool
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
the original token was issued for.
--resources REPLACES the client's resource allow-list (the resources it may
request by name; "" empties it), --add-resources appends to it and
--remove-resources drops entries, like the redirect-URI flags: removing a
resource the client does not have is an error and changes nothing. Removing a
resource stops new grants for it; tokens already issued keep it until they
expire, and a refresh keeps it too.
--trusted=true marks a first-party client (it skips the consent screen and is
not listed on users' Connected Apps page); --trusted=false makes it ask for
consent again. Only for an app the identity operator builds and controls --
never a third-party, MCP or AI client, and never a metadata-document (cimd)
client, which is refused. A trusted client's redirect URIs must all be exact and
not loopback: trusting a client with a wildcard or loopback URI, or adding one
to a client already trusted, is refused. Read README, "Trusted (first-party)
clients", first.`,
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

  # Let the client request another registered resource by name
  identity-client client update abc123 --add-resources "https://staging.sensibility.money/mcp"

  # Mark the operator's own first-party app trusted, or untrusted again
  identity-client client update abc123 --trusted=true
  identity-client client update abc123 --trusted=false

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
	clientUpdateCmd.Flags().StringVar(&updateResources, "resources", "", "Comma-separated resource URIs it may request by name (replaces the allow-list)")
	clientUpdateCmd.Flags().StringVar(&updateAddResources, "add-resources", "", "Comma-separated resource URIs to add to the allow-list")
	clientUpdateCmd.Flags().StringVar(&updateRemoveResources, "remove-resources", "", "Comma-separated resource URIs to remove from the allow-list")
	clientUpdateCmd.Flags().BoolVar(&updateTrusted, "trusted", false, "First-party client: skip consent and hide from Connected Apps (--trusted=true|false)")
	clientUpdateCmd.MarkFlagsMutuallyExclusive("default-resource", "clear-default-resource")
	clientUpdateCmd.MarkFlagsMutuallyExclusive("resources", "add-resources", "remove-resources")
}

func runClientUpdate(cmd *cobra.Command, args []string) error {
	clientID := args[0]
	flags := cmd.Flags()
	var u ops.ClientUpdate

	if flags.Changed("name") {
		u.Name = &updateName
	}
	switch {
	case flags.Changed("redirect-uris"):
		u.RedirectURIs = ops.ListEdit{Mode: ops.Replace, Values: internal.ParseList(updateRedirectURIs)}
	case flags.Changed("add-redirect-uris"):
		u.RedirectURIs = ops.ListEdit{Mode: ops.Add, Values: internal.ParseList(updateAddRedirectURIs)}
	case flags.Changed("remove-redirect-uris"):
		u.RedirectURIs = ops.ListEdit{Mode: ops.Remove, Values: internal.ParseList(updateRemoveRedirectURIs)}
	}
	if flags.Changed("scopes") {
		scopes := internal.ParseList(updateAllowedScopes)
		u.Scopes = &scopes
	}
	if flags.Changed("confidential") {
		u.Confidential = &updateIsConfidential
	}
	if flags.Changed("trusted") {
		u.Trusted = &updateTrusted
	}
	switch {
	case flags.Changed("clear-default-resource") && updateClearDefaultRes:
		clear := ""
		u.DefaultResource = &clear
	case flags.Changed("default-resource"):
		if updateDefaultResource == "" {
			return errors.New("--default-resource cannot be empty; use --clear-default-resource to remove the default")
		}
		u.DefaultResource = &updateDefaultResource
	}
	switch {
	case flags.Changed("resources"):
		u.Resources = ops.ListEdit{Mode: ops.Replace, Values: internal.ParseList(updateResources)}
	case flags.Changed("add-resources"):
		u.Resources = ops.ListEdit{Mode: ops.Add, Values: internal.ParseList(updateAddResources)}
	case flags.Changed("remove-resources"):
		u.Resources = ops.ListEdit{Mode: ops.Remove, Values: internal.ParseList(updateRemoveResources)}
	}

	detail, err := ops.UpdateClient(context.Background(), getDatastore(), clientID, u)
	if err != nil {
		return err
	}
	updatedClient := detail.Client

	fmt.Println("\n✅ OAuth client updated successfully!")
	fmt.Println("\nUpdated Client Details:")
	fmt.Printf("  Client ID:      %s\n", updatedClient.ClientID)
	fmt.Printf("  Name:           %s\n", updatedClient.Name)
	fmt.Printf("  Redirect URIs:  %s\n", strings.Join(updatedClient.RedirectUris, ", "))
	fmt.Printf("  Allowed Scopes: %s\n", strings.Join(updatedClient.AllowedScopes, ", "))
	fmt.Printf("  Default Resource: %s\n", internal.DefaultResourceValue(updatedClient.DefaultResource))
	fmt.Printf("  Allowed Resources: %s\n", allowedResourcesValue(detail.Resources))
	fmt.Printf("  Confidential:   %v\n", updatedClient.IsConfidential)
	fmt.Printf("  Trusted:        %v\n", updatedClient.Trusted)
	fmt.Printf("  Updated:        %s\n", updatedClient.UpdatedAt.Format("2006-01-02 15:04:05"))
	if len(updatedClient.RedirectUris) == 0 {
		fmt.Println("\n⚠️  This client now has no redirect URIs and cannot complete an authorization flow until one is added.")
	}
	fmt.Println()

	return nil
}
