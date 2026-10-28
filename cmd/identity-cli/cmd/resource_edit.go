package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/eswan18/identity/cmd/identity-cli/internal"
	"github.com/eswan18/identity/pkg/db"
	"github.com/spf13/cobra"
)

// resource get | update | delete. create and list are in resource.go.

var resourceGetCmd = &cobra.Command{
	Use:   "get <uri>",
	Short: "Show a resource and the clients that use it",
	Args:  cobra.ExactArgs(1),
	RunE:  runResourceGet,
}

var (
	resourceUpdateName           string
	resourceUpdateScopes         []string
	resourceUpdateAddScopes      []string
	resourceUpdateRemoveScopes   []string
	resourceUpdateDynamicClients bool
)

var resourceUpdateCmd = &cobra.Command{
	Use:   "update <uri>",
	Short: "Update a resource's name, scopes or dynamic-clients setting",
	Long: `Update a resource. Only the flags given change anything. The URI cannot
change: it is the aud of every token already issued for the resource.

--scope REPLACES the full set of scopes; --add-scope adds scopes (or replaces
the description of one the resource has); --remove-scope drops scopes by name.
Removing a scope the resource does not have is an error and changes nothing.
Tokens already issued keep the scopes they were granted.`,
	Example: `  identity-cli resource update https://sensibility.money/mcp --name "Sensibility"
  identity-cli resource update https://sensibility.money/mcp \
    --add-scope "sensibility:admin=Manage your workspaces"
  identity-cli resource update https://sensibility.money/mcp --remove-scope sensibility:admin
  identity-cli resource update https://sensibility.money/mcp --dynamic-clients=false`,
	Args: cobra.ExactArgs(1),
	RunE: runResourceUpdate,
}

var resourceDeleteForce bool

var resourceDeleteCmd = &cobra.Command{
	Use:   "delete <uri>",
	Short: "Delete a resource no client uses",
	Long: `Delete a resource. Refused while any client names it, as its default
resource or on its allow-list: change those clients first (client update
--default-resource / --clear-default-resource / --remove-resources).

Tokens already issued for the resource are not revoked; they keep working
until they expire.`,
	Args: cobra.ExactArgs(1),
	RunE: runResourceDelete,
}

func init() {
	resourceUpdateCmd.Flags().StringVar(&resourceUpdateName, "name", "", "Name shown on the consent screen")
	resourceUpdateCmd.Flags().StringArrayVar(&resourceUpdateScopes, "scope", nil, "The full set of scopes, as name=description (repeatable; replaces all)")
	resourceUpdateCmd.Flags().StringArrayVar(&resourceUpdateAddScopes, "add-scope", nil, "A scope to add or redescribe, as name=description (repeatable)")
	resourceUpdateCmd.Flags().StringArrayVar(&resourceUpdateRemoveScopes, "remove-scope", nil, "A scope name to remove (repeatable)")
	resourceUpdateCmd.Flags().BoolVar(&resourceUpdateDynamicClients, "dynamic-clients", false, "Whether clients identified by a metadata document (e.g. Claude) may request this resource")
	resourceUpdateCmd.MarkFlagsMutuallyExclusive("scope", "add-scope", "remove-scope")

	resourceDeleteCmd.Flags().BoolVar(&resourceDeleteForce, "force", false, "Skip confirmation prompt")

	resourceCmd.AddCommand(resourceGetCmd)
	resourceCmd.AddCommand(resourceUpdateCmd)
	resourceCmd.AddCommand(resourceDeleteCmd)
}

func runResourceGet(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	q := getDatastore().Q
	resource, err := findResource(ctx, q, "resource", args[0])
	if err != nil {
		return err
	}
	printResource(resource)

	clients, err := q.ListClientsReferencingResource(ctx, resource.Uri)
	if err != nil {
		return fmt.Errorf("listing the clients that use %s: %w", resource.Uri, err)
	}
	if len(clients) == 0 {
		fmt.Println("  Used by:         (no client)")
	} else {
		fmt.Println("  Used by:")
		for _, c := range clients {
			fmt.Printf("    %s (%s), %s\n", c.Name, c.ClientID, referenceKind(c))
		}
	}
	fmt.Println()
	return nil
}

// referenceKind says how a client names a resource.
func referenceKind(c db.ListClientsReferencingResourceRow) string {
	if c.IsDefault {
		return "as its default resource"
	}
	return "on its allow-list"
}

func runResourceUpdate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	q := getDatastore().Q
	current, err := findResource(ctx, q, "resource", args[0])
	if err != nil {
		return err
	}
	flags := cmd.Flags()

	params := db.UpdateOAuthResourceParams{
		Uri:            current.Uri,
		Name:           current.Name,
		Scopes:         current.Scopes,
		DynamicClients: current.DynamicClients,
	}

	if flags.Changed("name") {
		name := strings.TrimSpace(resourceUpdateName)
		if name == "" {
			return errors.New("--name cannot be empty")
		}
		params.Name = name
	}

	if flags.Changed("scope") || flags.Changed("add-scope") || flags.Changed("remove-scope") {
		scopes, err := internal.ParseScopes(current.Scopes)
		if err != nil {
			return fmt.Errorf("resource %s: %w", current.Uri, err)
		}
		switch {
		case flags.Changed("scope"):
			if scopes, err = internal.ParseResourceScopes(resourceUpdateScopes); err != nil {
				return err
			}
		case flags.Changed("add-scope"):
			additions, err := internal.ParseResourceScopes(resourceUpdateAddScopes)
			if err != nil {
				return err
			}
			scopes = internal.MergeScopes(scopes, additions)
		case flags.Changed("remove-scope"):
			var notFound []string
			scopes, notFound = internal.RemoveScopes(scopes, resourceUpdateRemoveScopes)
			if len(notFound) > 0 {
				return fmt.Errorf("resource %s has no such scope: %s - nothing was changed",
					current.Uri, strings.Join(notFound, ", "))
			}
		}
		if params.Scopes, err = internal.ScopesJSON(scopes); err != nil {
			return err
		}
	}

	if flags.Changed("dynamic-clients") {
		params.DynamicClients = resourceUpdateDynamicClients
	}

	updated, err := q.UpdateOAuthResource(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to update resource: %w", err)
	}
	fmt.Println("\n✅ Resource updated successfully!")
	printResource(updated)
	return nil
}

func runResourceDelete(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	q := getDatastore().Q
	resource, err := findResource(ctx, q, "resource", args[0])
	if err != nil {
		return err
	}

	clients, err := q.ListClientsReferencingResource(ctx, resource.Uri)
	if err != nil {
		return fmt.Errorf("listing the clients that use %s: %w", resource.Uri, err)
	}
	if len(clients) > 0 {
		var users []string
		for _, c := range clients {
			users = append(users, fmt.Sprintf("%s (%s) %s", c.Name, c.ClientID, referenceKind(c)))
		}
		return fmt.Errorf("resource %s is still used by: %s - change those clients first; nothing was deleted",
			resource.Uri, strings.Join(users, "; "))
	}

	if !resourceDeleteForce {
		fmt.Printf("Are you sure you want to delete resource '%s' (%s)? [y/N]: ", resource.Name, resource.Uri)
		response, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Deletion cancelled.")
			return nil
		}
	}

	// A client could have started naming it since the check above; the
	// default-resource foreign key still refuses then. An allow-list entry
	// added in that window would be removed with the resource (ON DELETE
	// CASCADE), which is the one race this does not close.
	if _, err := q.DeleteOAuthResource(ctx, resource.Uri); err != nil {
		return fmt.Errorf("failed to delete resource: %w", err)
	}
	fmt.Printf("\n✅ Resource %s deleted.\n\n", resource.Uri)
	return nil
}
