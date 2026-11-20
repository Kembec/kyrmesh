package cli

import (
	"context"
	"fmt"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// An invitation is a single-use, expiring pre-auth key handed out as a link
// (KEM-456). Revoking one is `headscale preauthkeys expire --id <id>`.
const defaultInviteExpiry = "24h"

func init() {
	rootCmd.AddCommand(invitesCmd)
	invitesCmd.AddCommand(createInviteCmd)
	createInviteCmd.Flags().Uint64P("user", "u", 0, "User identifier (ID) the device will belong to")
	createInviteCmd.Flags().
		StringP("expiration", "e", defaultInviteExpiry, "Human-readable expiration of the invitation (e.g. 30m, 24h)")
	createInviteCmd.Flags().StringSlice("tags", []string{}, "Tags to assign to the device instead of a user")
}

var invitesCmd = &cobra.Command{
	Use:     "invites",
	Short:   "Invite a device to join with a link, without a terminal",
	Aliases: []string{"invite"},
}

var createInviteCmd = &cobra.Command{
	Use:     "create",
	Short:   "Create a single-use invitation link",
	Aliases: []string{"c", cmdNew},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		user, _ := cmd.Flags().GetUint64("user")
		tags, _ := cmd.Flags().GetStringSlice("tags")

		if user == 0 && len(tags) == 0 {
			return fmt.Errorf("an invitation needs --user or --tags: %w", errMissingParameter)
		}

		serverURL := viper.GetString("server_url")
		if serverURL == "" {
			return fmt.Errorf("server_url is not configured: %w", errMissingParameter)
		}

		expiration, err := expirationFromFlag(cmd)
		if err != nil {
			return err
		}

		response, err := client.CreatePreAuthKey(ctx, &v1.CreatePreAuthKeyRequest{
			User:       user,
			Reusable:   false,
			Ephemeral:  false,
			AclTags:    tags,
			Expiration: expiration,
		})
		if err != nil {
			return fmt.Errorf("creating invitation: %w", err)
		}

		key := response.GetPreAuthKey()
		link := types.InviteURL(serverURL, key.GetKey())

		return printOutput(cmd, map[string]any{"id": key.GetId(), "url": link, "expiration": key.GetExpiration()}, link)
	}),
}
