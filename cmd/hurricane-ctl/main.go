package main

import (
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/kerbos/hurricanex/internal/logger"
)

var log *zap.Logger

var rootCmd = &cobra.Command{
	Use:   "hurricane-ctl",
	Short: "HurricaneX control tool",
	Long:  "Control tool for managing HurricaneX distributed engine nodes",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		log, err = logger.New("ctl", "info")
		if err != nil {
			return err
		}
		return nil
	},
}

var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy a traffic task to engine nodes",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Info("deploy command (skeleton — not yet implemented)")
		return nil
	},
}

var scaleCmd = &cobra.Command{
	Use:   "scale",
	Short: "Scale the number of engine nodes",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Info("scale command (skeleton — not yet implemented)")
		return nil
	},
}

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Monitor engine node status and metrics",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Info("monitor command (skeleton — not yet implemented)")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(deployCmd)
	rootCmd.AddCommand(scaleCmd)
	rootCmd.AddCommand(monitorCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
	if log != nil {
		_ = log.Sync() // best-effort flush
	}
}
