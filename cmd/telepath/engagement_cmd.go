package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/fsc/telepath-core/pkg/schema"
)

func newEngagementCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "engagement",
		Short:   "Manage engagements (create, load, list, close)",
		Aliases: []string{"eng"},
	}
	c.AddCommand(
		newEngagementNewCmd(),
		newEngagementLoadCmd(),
		newEngagementUnloadCmd(),
		newEngagementListCmd(),
		newEngagementStatusCmd(),
		newEngagementCloseCmd(),
		newEngagementSetROECmd(),
		newEngagementExportCmd(),
	)
	return c
}

func newEngagementExportCmd() *cobra.Command {
	var outDir string
	c := &cobra.Command{
		Use:   "export <id> --out <dir>",
		Short: "Produce the deliverable bundle (findings, report, evidence, manifest, audit)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if outDir == "" {
				return fmt.Errorf("--out required")
			}
			var res schema.EngagementExportResult
			if err := rpc(schema.MethodEngagementExport, schema.EngagementExportParams{ID: args[0], OutDir: outDir}, &res); err != nil {
				return err
			}
			fmt.Printf("exported to %s\n", res.OutDir)
			for _, a := range res.Artifacts {
				fmt.Printf("  %s\n", a)
			}
			fmt.Printf("operator public key: %s\n", res.OperatorPublicKey)
			return nil
		},
	}
	c.Flags().StringVar(&outDir, "out", "", "output directory for the bundle")
	_ = c.MarkFlagRequired("out")
	return c
}

func newEngagementSetROECmd() *cobra.Command {
	var file string
	c := &cobra.Command{
		Use:   "set-roe <id> --file <path>",
		Short: "Upload or replace the engagement's rules-of-engagement YAML",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" {
				return fmt.Errorf("--file required")
			}
			data, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			var res schema.EngagementSetROEResult
			if err := rpc(schema.MethodEngagementSetROE, schema.EngagementSetROEParams{ID: args[0], YAML: string(data)}, &res); err != nil {
				return err
			}
			fmt.Printf("ROE set for %s\n", args[0])
			return nil
		},
	}
	c.Flags().StringVar(&file, "file", "", "path to roe.yaml")
	_ = c.MarkFlagRequired("file")
	return c
}

func newEngagementNewCmd() *cobra.Command {
	var p schema.EngagementCreateParams
	c := &cobra.Command{
		Use:   "new <id>",
		Short: "Create a new engagement",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p.ID = args[0]
			if p.OperatorID == "" {
				if u := os.Getenv("USER"); u != "" {
					p.OperatorID = u
				}
			}
			var res schema.EngagementCreateResult
			if err := rpc(schema.MethodEngagementCreate, p, &res); err != nil {
				return err
			}
			fmt.Printf("created %s (client=%s type=%s, status=%s)\n",
				res.Engagement.ID, res.Engagement.ClientName, res.Engagement.AssessmentType, res.Engagement.Status)
			return nil
		},
	}
	c.Flags().StringVar(&p.ClientName, "client", "", "client name (required)")
	c.Flags().StringVar(&p.AssessmentType, "type", "", "assessment type (required)")
	c.Flags().StringVar(&p.StartDate, "start", "", "start date (YYYY-MM-DD)")
	c.Flags().StringVar(&p.EndDate, "end", "", "end date (YYYY-MM-DD)")
	c.Flags().StringVar(&p.SOWReference, "sow", "", "path to SOW document")
	c.Flags().StringVar(&p.OperatorID, "operator", "", "operator identifier (default $USER)")
	c.Flags().StringVar(&p.PrimarySkill, "skill", "", "primary skill name")
	c.Flags().StringVar(&p.TransportMode, "transport", "", "planned transport mode (direct|cloudflare-tunnel|openvpn)")
	_ = c.MarkFlagRequired("client")
	_ = c.MarkFlagRequired("type")
	return c
}

func newEngagementLoadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "load <id>",
		Short: "Load an engagement, making it active in the daemon",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var res schema.EngagementLoadResult
			if err := rpc(schema.MethodEngagementLoad, schema.EngagementLoadParams{ID: args[0]}, &res); err != nil {
				return err
			}
			fmt.Printf("loaded %s (status=%s, dir=%s)\n", res.Engagement.ID, res.Engagement.Status, res.Dir)
			if res.ClaudeMDPath != "" {
				fmt.Printf("rendered CLAUDE.md -> %s\n", res.ClaudeMDPath)
			}
			return nil
		},
	}
}

func newEngagementUnloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unload",
		Short: "Unload the active engagement (flushes audit log, keeps status)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := rpc(schema.MethodEngagementUnload, nil, nil); err != nil {
				return err
			}
			fmt.Println("unloaded")
			return nil
		},
	}
}

func newEngagementListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List engagements on this host (tab-separated)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var res schema.EngagementListResult
			if err := rpc(schema.MethodEngagementList, nil, &res); err != nil {
				return err
			}
			// Tab-separated, one engagement per line. Trivial to pipe into
			// awk/cut; the GUI does its own pretty rendering off the raw RPC.
			for _, e := range res.Engagements {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\t%s\n",
					e.ID, e.ClientName, e.AssessmentType, e.Status, e.CreatedAt.Format("2006-01-02"))
			}
			return nil
		},
	}
}

func newEngagementStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report which engagement (if any) is active",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var res schema.EngagementGetResult
			if err := rpc(schema.MethodEngagementGet, nil, &res); err != nil {
				return err
			}
			if res.Engagement == nil {
				fmt.Fprintln(cmd.OutOrStdout(), "no active engagement")
				return nil
			}
			e := res.Engagement
			fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\n", e.ID, e.ClientName, e.AssessmentType, e.Status)
			return nil
		},
	}
}

func newEngagementCloseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "close <id>",
		Short: "Seal the engagement: final checkpoint, status=sealed",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var res schema.EngagementCloseResult
			if err := rpc(schema.MethodEngagementClose, schema.EngagementCloseParams{ID: args[0]}, &res); err != nil {
				return err
			}
			fmt.Printf("sealed %s at %s\n", res.Engagement.ID, res.Engagement.SealedAt.Format("2006-01-02 15:04:05 UTC"))
			return nil
		},
	}
}
