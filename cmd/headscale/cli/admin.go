package cli

import (
	"context"
	"fmt"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The admin console is where invitations are created, shared and revoked
// from a browser (KEM-464). It opens only with a link from this command:
// an API key that lives types.AdminLinkLife and is spent on first use.

func init() {
	rootCmd.AddCommand(adminCmd)
	adminCmd.AddCommand(adminLinkCmd)
}

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Manage invitations from a browser",
}

var adminLinkCmd = &cobra.Command{
	Use:   "link",
	Short: "Print a single-use link that opens the admin console",
	Long: `
Prints a link that opens the invitations console in a browser. The link
works once and expires in 10 minutes; the session it opens lasts 12 hours
or until the server restarts.`,
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		serverURL := viper.GetString("server_url")
		if serverURL == "" {
			return fmt.Errorf("server_url is not configured: %w", errMissingParameter)
		}

		response, err := client.CreateApiKey(ctx, &v1.CreateApiKeyRequest{
			Expiration: timestamppb.New(time.Now().Add(types.AdminLinkLife)),
		})
		if err != nil {
			return fmt.Errorf("creating admin link: %w", err)
		}

		link := types.AdminLinkURL(serverURL, response.GetApiKey())

		return printOutput(cmd, map[string]any{"url": link, "expires_in": types.AdminLinkLife.String()}, link)
	}),
}
