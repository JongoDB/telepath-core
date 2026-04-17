package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/pkg/schema"
)

func newTransportCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "transport",
		Short: "Manage the daemon's active network transport",
	}
	c.AddCommand(newTransportUpCmd(), newTransportDownCmd(), newTransportStatusCmd())
	return c
}

func newTransportUpCmd() *cobra.Command {
	var params schema.TransportUpParams
	c := &cobra.Command{
		Use:   "up <kind>",
		Short: "Bring a transport up (direct | cloudflare-tunnel | openvpn)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Kind = args[0]
			var res schema.TransportStatusResult
			if err := rpc(schema.MethodTransportUp, params, &res); err != nil {
				return err
			}
			fmt.Printf("transport: %s (%s)\n", res.Status.Kind, res.Status.State)
			if res.Status.Detail != "" {
				fmt.Printf("  detail: %s\n", res.Status.Detail)
			}
			if res.Status.Hint != "" {
				fmt.Printf("  hint:   %s\n", res.Status.Hint)
			}
			return nil
		},
	}
	c.Flags().StringVar(&params.CloudflareAPIToken, "cloudflare-api-token", "", "cloudflare API token (cloudflare-tunnel only)")
	c.Flags().StringVar(&params.CloudflareAccountID, "cloudflare-account", "", "cloudflare account ID")
	c.Flags().StringVar(&params.CloudflareHostname, "cloudflare-hostname", "", "cloudflare tunnel hostname")
	c.Flags().StringVar(&params.OpenVPNConfigPath, "openvpn-config", "", "path to .ovpn file (openvpn only)")
	c.Flags().IntVar(&params.StartupTimeoutSeconds, "startup-timeout-seconds", 0, "seconds to wait for transport to come up")
	return c
}

func newTransportDownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Tear down the active transport",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var res schema.TransportStatusResult
			if err := rpc(schema.MethodTransportDown, nil, &res); err != nil {
				return err
			}
			fmt.Printf("transport: %s\n", res.Status.State)
			return nil
		},
	}
}

func newTransportStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the active transport's status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var res schema.TransportStatusResult
			if err := rpc(schema.MethodTransportStatus, nil, &res); err != nil {
				return err
			}
			if res.Status.State == "down" || res.Status.Kind == "" {
				fmt.Println("transport: down")
				return nil
			}
			fmt.Printf("transport: %s (%s)\n", res.Status.Kind, res.Status.State)
			if res.Status.Detail != "" {
				fmt.Printf("  detail: %s\n", res.Status.Detail)
			}
			if res.Status.Hint != "" {
				fmt.Printf("  hint:   %s\n", res.Status.Hint)
			}
			return nil
		},
	}
}
