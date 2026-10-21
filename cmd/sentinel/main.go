package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/urfave/cli/v3"

	"github.com/JetManiack/log-sentinel/internal/board"
	"github.com/JetManiack/log-sentinel/internal/config"
	"github.com/JetManiack/log-sentinel/internal/detector"
	"github.com/JetManiack/log-sentinel/internal/digest"
	"github.com/JetManiack/log-sentinel/internal/health"
	"github.com/JetManiack/log-sentinel/internal/masker"
	"github.com/JetManiack/log-sentinel/internal/sink"
	"github.com/JetManiack/log-sentinel/internal/state"
	"github.com/JetManiack/log-sentinel/internal/triage"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := newApp().Run(ctx, os.Args); err != nil {
		slog.Error("sentinel exited with error", "error", err)
		os.Exit(1)
	}
}

func newApp() *cli.Command {
	return &cli.Command{
		Name:    "sentinel",
		Usage:   "Security-focused log sentinel: deterministic detection + optional LLM triage",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Value:   "config.yaml",
				Usage:   "path to config file",
				Sources: cli.EnvVars("SENTINEL_CONFIG"),
			},
			&cli.StringFlag{
				Name:    "listen-addr",
				Value:   ":9100",
				Usage:   "address for /livez, /readyz and /metrics",
				Sources: cli.EnvVars("LISTEN_ADDR"),
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return run(ctx, cmd.String("config"), cmd.String("listen-addr"))
		},
	}
}

func run(ctx context.Context, cfgPath, listenAddr string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	mask := masker.Default()

	db, err := state.Open(cfg.State)
	if err != nil {
		return err
	}

	runner, findings := detector.New(cfg, db, mask)
	triager := triage.New(cfg.LLM, mask)
	stdout := sink.NewStdout()
	boardClient := board.New(cfg.Sinks.Board, db)

	// Start the HTTP admin server.
	go func() {
		r := chi.NewRouter()
		r.Get("/livez", health.LivezHandler())
		r.Get("/readyz", health.ReadyzHandler(db.GORM()))
		srv := &http.Server{
			Addr:              listenAddr,
			Handler:           r,
			ReadHeaderTimeout: 5 * time.Second,
		}
		slog.Info("admin server listening", "addr", listenAddr, "version", version)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("admin server error", "err", err)
		}
	}()

	// Start the detector.
	go runner.Run(ctx)

	// Poll board threads for /quiet /benign /unquiet commands.
	go boardClient.PollCommands(ctx, cfg.Commands, db, cfg.Detector.Interval)

	// Daily digest.
	var digestBoardEmit func(context.Context, string, string)
	if boardClient != nil {
		digestBoardEmit = boardClient.EmitDigest
	}
	go digest.New(cfg.Digest, db, digestBoardEmit).Run(ctx)

	slog.Info("sentinel started", "version", version)

	// Dispatch findings.
	for {
		select {
		case <-ctx.Done():
			return nil
		case f := <-findings:
			enrichment := triager.Enrich(ctx, f, cfg.Detector.KnownBenign)
			stdout.Emit(f, enrichment)
			boardClient.Emit(ctx, f, enrichment)
		}
	}
}
