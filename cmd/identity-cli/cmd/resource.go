package cmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/eswan18/identity/cmd/identity-cli/internal"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/resourceuri"
	"github.com/spf13/cobra"
)

var resourceCmd = &cobra.Command{
	Use:   "resource",
	Short: "Manage OAuth resources (the APIs tokens are minted for)",
	Long: `Create, list, show, update and delete OAuth resources. A resource is an
API that identity mints access tokens for; its URI is the token's aud. A
client's default resource is what its tokens are for when a request names none;
its allow-list (client create|update --resources) is what else it may request
with the resource parameter.

Register resources in BOTH identity databases (staging's is periodically
replaced by a copy of prod's).`,
	PersistentPreRunE:  openDatastore,
	PersistentPostRunE: closeDatastore,
}

var (
	resourceCreateURI            string
	resourceCreateName           string
	resourceCreateScopes         []string
	resourceCreateDynamicClients bool
)

var resourceCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Register a new resource",
	Long: `Register a new resource. The URI must be https and is stored in canonical
form (lowercase scheme and host, no default port, no trailing slash); a
fragment is refused. Each --scope is name=description: the scopes this
resource defines, with the text the consent screen shows for each.`,
	Example: `  identity-cli resource create \
    --uri https://sensibility.money/mcp --name Sensibility \
    --scope "sensibility:read=Read your accounts and balances" \
    --scope "sensibility:write=Change your accounts and balances" \
    --dynamic-clients`,
	RunE: runResourceCreate,
}

var resourceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List resources",
	RunE:  runResourceList,
}

func init() {
	resourceCreateCmd.Flags().StringVar(&resourceCreateURI, "uri", "", "Resource URI, the tokens' aud (required, https)")
	resourceCreateCmd.Flags().StringVar(&resourceCreateName, "name", "", "Name shown on the consent screen (required)")
	resourceCreateCmd.Flags().StringArrayVar(&resourceCreateScopes, "scope", nil, "A scope this resource defines, as name=description (repeatable)")
	resourceCreateCmd.Flags().BoolVar(&resourceCreateDynamicClients, "dynamic-clients", false, "Let clients identified by a metadata document (e.g. Claude) request this resource")
	resourceCreateCmd.MarkFlagRequired("uri")
	resourceCreateCmd.MarkFlagRequired("name")

	resourceCmd.AddCommand(resourceCreateCmd)
	resourceCmd.AddCommand(resourceListCmd)
}

func runResourceCreate(cmd *cobra.Command, args []string) error {
	uri, err := resourceuri.ValidateNew(resourceCreateURI)
	if err != nil {
		return fmt.Errorf("--uri %q: %w", resourceCreateURI, err)
	}
	if strings.TrimSpace(resourceCreateName) == "" {
		return errors.New("--name cannot be empty")
	}
	scopes, err := internal.ParseResourceScopes(resourceCreateScopes)
	if err != nil {
		return err
	}
	scopesJSON, err := internal.ScopesJSON(scopes)
	if err != nil {
		return err
	}

	resource, err := getDatastore().Q.CreateOAuthResource(context.Background(), db.CreateOAuthResourceParams{
		Uri:            uri,
		Name:           strings.TrimSpace(resourceCreateName),
		Scopes:         scopesJSON,
		DynamicClients: resourceCreateDynamicClients,
	})
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	fmt.Println("\n✅ Resource registered successfully!")
	printResource(resource)
	return nil
}

func runResourceList(cmd *cobra.Command, args []string) error {
	resources, err := getDatastore().Q.ListOAuthResources(context.Background())
	if err != nil {
		return fmt.Errorf("failed to list resources: %w", err)
	}
	if len(resources) == 0 {
		fmt.Println("No resources found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "URI\tNAME\tSCOPES\tDYNAMIC CLIENTS")
	fmt.Fprintln(w, "---\t----\t------\t---------------")
	for _, r := range resources {
		dynamic := "No"
		if r.DynamicClients {
			dynamic = "Yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Uri, r.Name, strings.Join(scopeNames(r.Scopes), " "), dynamic)
	}
	return w.Flush()
}

func printResource(r db.OauthResource) {
	fmt.Println("\nResource Details:")
	fmt.Printf("  URI:             %s\n", r.Uri)
	fmt.Printf("  Name:            %s\n", r.Name)
	fmt.Printf("  Dynamic clients: %v\n", r.DynamicClients)
	var scopes map[string]string
	_ = json.Unmarshal(r.Scopes, &scopes)
	if len(scopes) == 0 {
		fmt.Println("  Scopes:          (none)")
	} else {
		fmt.Println("  Scopes:")
		for _, name := range scopeNames(r.Scopes) {
			fmt.Printf("    %s: %s\n", name, scopes[name])
		}
	}
	fmt.Println()
}

// scopeNames returns the scope names in a resource's scopes column, sorted.
func scopeNames(raw json.RawMessage) []string {
	var scopes map[string]string
	if err := json.Unmarshal(raw, &scopes); err != nil {
		return []string{"(unreadable)"}
	}
	names := make([]string, 0, len(scopes))
	for name := range scopes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// resolveDefaultResource turns a --default-resource value into the URI of a
// registered resource (see findResource). The foreign key would refuse an
// unknown URI anyway, but not with a message that says what to do.
func resolveDefaultResource(ctx context.Context, raw string) (sql.NullString, error) {
	resource, err := findResource(ctx, getDatastore().Q, "--default-resource", raw)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: resource.Uri, Valid: true}, nil
}

// findResource looks up a registered resource by a URI an operator typed. The
// value as typed is tried first, so a resource registered before the
// canonical form existed (the 000012 backfill keeps URIs byte for byte) is
// found as listed; then its canonical form, so any spelling of a registered
// https URI finds it. what names the flag or argument, for the error.
func findResource(ctx context.Context, q *db.Queries, what, raw string) (db.OauthResource, error) {
	resource, err := q.GetOAuthResourceByURI(ctx, raw)
	if err == nil {
		return resource, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return db.OauthResource{}, fmt.Errorf("looking up resource %s: %w", raw, err)
	}
	uri, err := resourceuri.Canonicalize(raw)
	if err != nil {
		return db.OauthResource{}, fmt.Errorf("%s %q: %w", what, raw, err)
	}
	resource, err = q.GetOAuthResourceByURI(ctx, uri)
	if errors.Is(err, sql.ErrNoRows) {
		return db.OauthResource{}, fmt.Errorf(
			"%s %q: no resource is registered with URI %s - register it first with `identity-cli resource create` (see `identity-cli resource list`)",
			what, raw, uri)
	}
	if err != nil {
		return db.OauthResource{}, fmt.Errorf("looking up resource %s: %w", uri, err)
	}
	return resource, nil
}
