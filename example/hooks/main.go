// Command prox-hooks-example shows how a consumer extends the prox relay
// with pkg/hooks without touching the proxy's source: build this module,
// run it instead of the stock binary, and the registered hooks apply to
// every relayed connection.
//
// Two hooks are demonstrated:
//   - sniLogger: passive; logs each connection (SNI for TLS) at open and
//     the close reason.
//   - tokenRedactor: active; replaces a literal token in
//     client-to-server bytes with a placeholder, so the upstream (and the
//     capture) never sees the real value.
package main

import (
	"bytes"
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nicois/prox/pkg/config"
	"github.com/nicois/prox/pkg/hooks"
	prox "github.com/nicois/prox/pkg/prox"
)

// sniLogger observes connections; it never alters or blocks.
type sniLogger struct{}

func (sniLogger) Filter() hooks.Match { return hooks.Match{} }
func (sniLogger) OnOpen(c *hooks.Conn, hc *hooks.HookConn) hooks.Result {
	slog.Info("conn_open", "src", c.Src, "dst", c.Dst, "kind", c.Kind, "sni", c.SNI)
	return hooks.Result{}
}
func (sniLogger) OnData(c *hooks.Conn, dir hooks.Dir, data []byte) hooks.Result {
	return hooks.Result{}
}
func (sniLogger) OnClose(c *hooks.Conn, reason string) {
	slog.Info("conn_close", "src", c.Src, "dst", c.Dst, "kind", c.Kind, "reason", reason)
}

// tokenRedactor replaces a literal token in client-to-server data.
type tokenRedactor struct{ token, replacement []byte }

func (tokenRedactor) Filter() hooks.Match { return hooks.Match{} }
func (tokenRedactor) OnOpen(c *hooks.Conn, hc *hooks.HookConn) hooks.Result {
	return hooks.Result{}
}
func (r tokenRedactor) OnData(c *hooks.Conn, dir hooks.Dir, data []byte) hooks.Result {
	if dir != hooks.DirC2S || !bytes.Contains(data, r.token) {
		return hooks.Result{}
	}
	return hooks.Result{Data: bytes.ReplaceAll(data, r.token, r.replacement)}
}
func (tokenRedactor) OnClose(c *hooks.Conn, reason string) {}

func main() {
	cfgPath := flag.String("config", "", "YAML config path (built-in defaults when empty)")
	listen := flag.String("listen", "", "override the listen address")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	token := flag.String("token", "REDACT-ME", "literal token to redact in client-to-server bytes")
	flag.Parse()

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(strings.ToLower(strings.TrimSpace(*logLevel)))); err != nil {
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))

	cfg, err := config.Load(*cfgPath, func(c *config.Config) {
		if *listen != "" {
			c.Listen = *listen
		}
	})
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	a, err := prox.New(cfg)
	if err != nil {
		slog.Error("start", "err", err)
		os.Exit(1)
	}
	a.Register(sniLogger{})
	a.Register(tokenRedactor{token: []byte(*token), replacement: []byte("[redacted]")})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
	// The signal ctx is already cancelled — its cancellation is what
	// ended Run — so draining under it would drop every in-flight
	// connection. Use a fresh budget, intentionally independent of the
	// signal ctx. The stop itself is bounded by the drain (grace, then
	// force-close of remaining connections, then settle); the budget only
	// backstops a pathological settle, with systemd's TimeoutStopSec and
	// SIGKILL beyond it.
	drainCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.Shutdown(drainCtx); err != nil {
		slog.Error("shutdown", "err", err)
		os.Exit(1)
	}
	slog.Info("stopped")
}
