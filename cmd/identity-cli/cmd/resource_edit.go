package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/eswan18/identity/cmd/identity-cli/internal"
	"github.com/eswan18/identity/cmd/identity-cli/internal/ops"
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
	detail, err := ops.GetResource(context.Background(), getDatastore(), args[0])
	if err != nil {
		return err
	}
	printResource(detail.Resource)
	if len(detail.UsedBy) == 0 {
		fmt.Println("  Used by:         (no client)")
	} else {
		fmt.Println("  Used by:")
		for _, c := range detail.UsedBy {
			fmt.Printf("    %s (%s), %s\n", c.Name, c.ClientID, ops.ReferenceKind(c))
		}
	}
	fmt.Println()
	return nil
}

func runResourceUpdate(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()
	var u ops.ResourceUpdate
	if flags.Changed("name") {
		if strings.TrimSpace(resourceUpdateName) == "" {
			return errors.New("--name cannot be empty")
		}
		u.Name = &resourceUpdateName
	}
	switch {
	case flags.Changed("scope"):
		scopes, err := internal.ParseResourceScopes(resourceUpdateScopes)
		if err != nil {
			return err
		}
		u.Scopes = ops.ScopeEdit{Mode: ops.Replace, Set: scopes}
	case flags.Changed("add-scope"):
		additions, err := internal.ParseResourceScopes(resourceUpdateAddScopes)
		if err != nil {
			return err
		}
		u.Scopes = ops.ScopeEdit{Mode: ops.Add, Set: additions}
	case flags.Changed("remove-scope"):
		u.Scopes = ops.ScopeEdit{Mode: ops.Remove, Remove: resourceUpdateRemoveScopes}
	}
	if flags.Changed("dynamic-clients") {
		u.DynamicClients = &resourceUpdateDynamicClients
	}

	updated, err := ops.UpdateResource(context.Background(), getDatastore(), args[0], u)
	if err != nil {
		return err
	}
	fmt.Println("\n✅ Resource updated successfully!")
	printResource(updated.Resource)
	return nil
}

func runResourceDelete(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	detail, err := ops.GetResource(ctx, getDatastore(), args[0])
	if err != nil {
		return err
	}
	resource := detail.Resource
	// ops.DeleteResource refuses while any client names it; checking here too
	// means the operator is not asked to confirm a delete that will be refused.
	if len(detail.UsedBy) == 0 && !resourceDeleteForce {
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
	if err := ops.DeleteResource(ctx, getDatastore(), resource.Uri); err != nil {
		return err
	}
	fmt.Printf("\n✅ Resource %s deleted.\n\n", resource.Uri)
	return nil
}
