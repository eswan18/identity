package cmd

import (
	"context"
	"fmt"
	"os"
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
	fmt.Fprintln(w, "CLIENT ID\tNAME\tAUDIENCE\tCONFIDENTIAL\tCREATED")
	fmt.Fprintln(w, "---------\t----\t--------\t------------\t-------")

	for _, client := range clients {
		confidential := "No"
		if client.IsConfidential {
			confidential = "Yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			client.ClientID,
			client.Name,
			client.Audience,
			confidential,
			client.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}

	w.Flush()
	return nil
}
