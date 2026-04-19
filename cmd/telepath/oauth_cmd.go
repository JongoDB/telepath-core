package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/pkg/schema"
)

// newOAuthCmd is the operator-facing entry into the SaaS OAuth flow.
// Setup/config class — stays permanent CLI (not GUI-scaffolding) because
// an operator initiates these outside Claude Code sessions and wants a
// predictable script-friendly entry point even after the GUI ships.
func newOAuthCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "oauth",
		Short: "Connect third-party SaaS identities (M365, Google, Salesforce)",
	}
	c.AddCommand(newOAuthBeginCmd(), newOAuthStatusCmd())
	return c
}

// newOAuthBeginCmd runs the full operator flow in one command: begin +
// paste-back + complete. Matches the UX of `telepath config init`'s
// subscription-OAuth branch so the paste-back feels the same across
// flows.
func newOAuthBeginCmd() *cobra.Command {
	var tenant, clientIDOverride string
	c := &cobra.Command{
		Use:   "begin <provider>",
		Short: "Start a PKCE OAuth flow against m365 | google | salesforce",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := strings.ToLower(args[0])
			var begin schema.OAuthBeginResult
			if err := rpc(schema.MethodOAuthBegin, schema.OAuthBeginParams{
				Provider: provider,
				Tenant:   tenant,
				ClientID: clientIDOverride,
			}, &begin); err != nil {
				return err
			}

			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Open this URL in your browser to authorize telepath:")
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "  "+begin.AuthURL)
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "After signing in, paste the authorization code (or the full callback URL) below.")
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprint(cmd.OutOrStdout(), "Authorization code: ")

			reader := bufio.NewReader(os.Stdin)
			line, err := reader.ReadString('\n')
			if err != nil && line == "" {
				return fmt.Errorf("oauth: read input: %w", err)
			}
			line = strings.TrimRight(line, "\r\n ")
			if line == "" {
				return fmt.Errorf("oauth: empty input")
			}

			var done schema.OAuthCompleteResult
			if err := rpc(schema.MethodOAuthComplete, schema.OAuthCompleteParams{
				SessionID: begin.SessionID,
				Input:     line,
			}, &done); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintf(cmd.OutOrStdout(), "Connected %s (tenant=%s). Token expires at %s.\n",
				done.Provider, done.Tenant, done.ExpiresAt)
			if done.Scope != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "Scopes: %s\n", done.Scope)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Credential stored in keystore under %s\n", done.CredentialID)
			return nil
		},
	}
	c.Flags().StringVar(&tenant, "tenant", "", "tenant label for keystore isolation; default: 'default'")
	c.Flags().StringVar(&clientIDOverride, "client-id", "", "override configured client_id for this flow")
	return c
}

// newOAuthStatusCmd lists connections recorded in the keystore. Permanent
// CLI (setup/config surface), so it's worth a small-touch tabwriter for
// human legibility — unlike the scaffolding engagement list I stripped
// earlier.
func newOAuthStatusCmd() *cobra.Command {
	var provider, tenant string
	c := &cobra.Command{
		Use:   "status",
		Short: "List connected SaaS identities + their token expiries",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var res schema.OAuthStatusResult
			if err := rpc(schema.MethodOAuthStatus, schema.OAuthStatusParams{
				Provider: provider,
				Tenant:   tenant,
			}, &res); err != nil {
				return err
			}
			if len(res.Connections) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no OAuth connections recorded; run `telepath oauth begin <provider>` to create one")
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PROVIDER\tTENANT\tEXPIRES_AT\tSTATUS")
			for _, c := range res.Connections {
				status := "live"
				if c.Expired {
					status = "EXPIRED — re-run `telepath oauth begin`"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.Provider, c.Tenant, c.ExpiresAt, status)
			}
			return w.Flush()
		},
	}
	c.Flags().StringVar(&provider, "provider", "", "filter to a specific provider (m365|google|salesforce)")
	c.Flags().StringVar(&tenant, "tenant", "", "filter to a specific tenant label")
	return c
}
