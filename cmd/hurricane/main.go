package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/kerbos/hurricanex/internal/config"
	"github.com/kerbos/hurricanex/internal/logger"
	"github.com/kerbos/hurricanex/internal/preflight"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "hurricane",
	Short: "HurricaneX traffic engine",
	Long:  "HurricaneX (流量飓风) — DPDK-based distributed L7 traffic simulation engine",
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start the traffic engine",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		log, err := newLogger(cfg)
		if err != nil {
			return fmt.Errorf("init logger: %w", err)
		}
		defer log.Sync() //nolint:errcheck

		log.Info("starting engine",
			zap.String("host", cfg.Target.Host),
			zap.Int("port", cfg.Target.Port),
			zap.Bool("tls", cfg.Target.TLS),
			zap.Int("workers", cfg.Engine.Workers),
			zap.Int("connections", cfg.Engine.Connections),
		)
		log.Info("engine started (skeleton — not yet implemented)")
		return nil
	},
}

var preflightCmd = &cobra.Command{
	Use:   "preflight",
	Short: "Run environment pre-flight checks",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		log, err := newLogger(cfg)
		if err != nil {
			return fmt.Errorf("init logger: %w", err)
		}
		defer log.Sync() //nolint:errcheck

		return preflight.Run(log)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c",
		"configs/hurricane.yaml", "path to config file")
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(preflightCmd)
}

func newLogger(cfg *config.Config) (*zap.Logger, error) {
	if cfg.Log.Dev {
		return logger.NewDev("engine")
	}
	return logger.New("engine", cfg.Log.Level)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
