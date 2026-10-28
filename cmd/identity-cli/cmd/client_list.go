package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var clientListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all OAuth clients",
	Long:  `List all OAuth clients in the identity service database.`,
	RunE:  runClientList,
}

func runClientList(cmd *cobra.Command, args []string) error {
	datastore := getDatastore()

	ctx := context.Background()
	clients, err := datastore.Q.ListOAuthClients(ctx)
	if err != nil {
		return fmt.Errorf("failed to list OAuth clients: %w", err)
	}

	if len(clients) == 0 {
		fmt.Println("No OAuth clients found.")
		return nil
	}

	// Print table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "CLIENT ID\tNAME\tDEFAULT RESOURCE\tALLOWED RESOURCES\tCONFIDENTIAL\tCREATED")
	fmt.Fprintln(w, "---------\t----\t----------------\t-----------------\t------------\t-------")

	for _, client := range clients {
		confidential := "No"
		if client.IsConfidential {
			confidential = "Yes"
		}
		// No default resource: the client's tokens are for identity itself.
		defaultResource := "(identity)"
		if client.DefaultResource.Valid {
			defaultResource = client.DefaultResource.String
		}
		allowed, err := datastore.Q.ListClientResources(ctx, client.ID)
		if err != nil {
			return fmt.Errorf("failed to read allowed resources of %s: %w", client.ClientID, err)
		}
		allowedURIs := "-"
		if len(allowed) > 0 {
			uris := make([]string, len(allowed))
			for i, r := range allowed {
				uris[i] = r.Uri
			}
			allowedURIs = strings.Join(uris, " ")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			client.ClientID,
			client.Name,
			defaultResource,
			allowedURIs,
			confidential,
			client.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}

	w.Flush()
	return nil
}
