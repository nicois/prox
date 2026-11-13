package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nicois/prox/pkg/config"
	prox "github.com/nicois/prox/pkg/prox"
	"github.com/nicois/prox/pkg/version"
)

func main() {
	cfgPath := flag.String("config", "", "YAML config path (built-in defaults when empty)")
	listen := flag.String("listen", "", "override the listen address")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	flag.Parse()

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(strings.ToLower(strings.TrimSpace(*logLevel)))); err != nil {
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))

	// An unstamped binary (e.g. a plain `go build` bypassing the Makefile)
	// cannot tie its captures to a commit: refuse to run it rather than
	// record "dev" in every stream.
	if c := version.Commit; c == "" || c == version.Dev {
		slog.Error("build", "err", "unknown git commit: the binary was built without the Makefile's link-time stamp; rebuild with `make` from a git checkout")
		os.Exit(1)
	}

	cfg, err := config.Load(*cfgPath, func(c *config.Config) {
		if *listen != "" {
			c.Listen = *listen
		}
	})
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	slog.Info("starting",
		"listen", cfg.Listen,
		"ports", cfg.Ports,
		"dataroot", cfg.DataRoot,
		"cas", len(cfg.CAPaths),
		"ct_log", valueOrNone(cfg.MITM.CTLogURL),
		"isolation", cfg.Isolation,
		"build", version.Commit,
	)
	a, err := prox.New(cfg)
	if err != nil {
		slog.Error("start", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
	// The signal ctx is already cancelled — its cancellation is what
	// ended Run — so draining under it would drop every in-flight
	// connection. Use a fresh budget, intentionally independent of the
	// signal ctx. A normal stop is bounded by the drain itself (grace,
	// then force-close of what remains, then settle); this 10s only
	// bounds a pathological settle and stays well under the unit's 15s
	// TimeoutStopSec, with SIGKILL as the last backstop.
	drainCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.Shutdown(drainCtx); err != nil {
		slog.Error("shutdown", "err", err)
		os.Exit(1)
	}
	slog.Info("stopped")
}

func valueOrNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
