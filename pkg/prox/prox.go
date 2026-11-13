// Package prox is the transparent TLS proxy facade: it installs the TPROXY
// capture rules (pkg/rules), listens on the configured port, and runs each
// accepted connection through the connection ladder (pkg/proxy) — TLS is
// terminated with a forged per-host leaf signed by one of the configured
// intermediate CAs (pkg/tlsutil), everything else is relayed verbatim —
// while capturing each connection's bytes and events to the dataroot
// (pkg/sink).
//
// New builds the proxy from a validated config; Run installs the rules and
// serves until the context is cancelled (removing the rules on the way
// out); Shutdown closes the listener, drains in-flight connections, and
// reports the remainder if the context expires. When DataRoot is empty the
// proxy runs embedded: no capture files, no index.db, no retention, no data
// doc — the in-process capture registry still records the streams.
package prox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/nicois/prox/pkg/capture"
	"github.com/nicois/prox/pkg/config"
	"github.com/nicois/prox/pkg/hooks"
	"github.com/nicois/prox/pkg/isolation"
	"github.com/nicois/prox/pkg/proxy"
	"github.com/nicois/prox/pkg/rules"
	"github.com/nicois/prox/pkg/sink"
	"github.com/nicois/prox/pkg/store"
	"github.com/nicois/prox/pkg/tlsutil"
)

const (
	recheckTick      = time.Hour
	retentionTick    = 24 * time.Hour
	captureEvictTick = time.Hour
	captureEvictAge  = time.Hour
	// drainGraceDefault is the default Prox.DrainGrace: how long Shutdown
	// lets in-flight connections finish on their own before force-closing
	// them.
	drainGraceDefault = 2 * time.Second
)

//go:embed datamodel.md
var dataModelDoc []byte

// Prox wires the store, leaf provider, sink factory, hook pipeline, and
// ladder together and owns
// the TPROXY listener lifecycle.
type Prox struct {
	cfg     *config.Config
	Store   *store.Store
	Leaves  *tlsutil.Provider
	Ladder  *proxy.Ladder
	Capture *capture.Registry

	// DrainGrace is how long Shutdown lets in-flight connections finish on
	// their own before force-closing them (the settle phase then waits for
	// the connection goroutines' cleanup under the caller's ctx). Zero
	// takes drainGraceDefault; New sets it explicitly.
	DrainGrace time.Duration

	hooks *hooks.Pipeline

	// ruleRunner is the runner the managed-mode rule lifecycle uses for
	// the iptables/ip commands (SetRulesRunner); nil (the default) uses
	// the built-in exec runner.
	ruleRunner rules.Runner

	ln      net.Listener
	lnOnce  sync.Once
	active  atomic.Int64
	connsMu sync.Mutex
	conns   map[net.Conn]struct{} // in-flight client conns: Shutdown's force-close handles
}

// New builds the store, leaf provider, sink factory, and ladder from cfg.
func New(cfg *config.Config) (*Prox, error) {
	st := (*store.Store)(nil)
	if cfg.DataRoot != "" {
		if err := os.MkdirAll(cfg.DataRoot, fs.FileMode(cfg.Log.DirMode)); err != nil {
			return nil, fmt.Errorf("prox: dataroot: %w", err)
		}
		var err error
		st, err = store.Open(filepath.Join(cfg.DataRoot, "index.db"))
		if err != nil {
			return nil, fmt.Errorf("prox: store: %w", err)
		}
	}
	leaves, err := tlsutil.NewProvider(cfg.CAPaths, cfg.MITM)
	if err != nil {
		if st != nil {
			st.Close()
		}
		return nil, fmt.Errorf("prox: leaf provider: %w", err)
	}
	upstreamRoots, err := loadUpstreamRoots(cfg.MITM.UpstreamCAs)
	if err != nil {
		if st != nil {
			st.Close()
		}
		return nil, fmt.Errorf("prox: upstream roots: %w", err)
	}
	h := hooks.NewPipeline()
	switch cfg.Isolation {
	case "full":
		// Registered before any consumer hook (Register appends), so the
		// operator's isolation config wins the serve decision.
		h.Register(isolation.Full())
	case "readonly":
		// flag below
	}
	reg := capture.NewRegistry()
	sinkFn := func(dr, id string, mb int64) (*sink.Conn, error) {
		return sink.Open(dr, id, mb, fs.FileMode(cfg.Log.FileMode), fs.FileMode(cfg.Log.DirMode))
	}
	if cfg.DataRoot == "" {
		sinkFn = func(string, string, int64) (*sink.Conn, error) { return sink.Noop(), nil }
	}
	// The cap only applies where s2c bytes are actually delivered to the
	// client: isolation "off". readonly delivers no s2c and full no relay,
	// so the cap is structurally inapplicable there.
	s2cLimit := 0
	if cfg.Isolation == "off" {
		s2cLimit = cfg.S2cMaxPacket
	}
	return &Prox{
		cfg:        cfg,
		Store:      st,
		Leaves:     leaves,
		DrainGrace: drainGraceDefault,
		hooks:      h,
		Capture:    reg,
		Ladder: &proxy.Ladder{
			Sink:              sinkFn,
			Store:             st,
			Leaves:            leaves,
			DataRoot:          cfg.DataRoot,
			MaxBytes:          cfg.Log.PerConnMaxBytes,
			UpstreamRoots:     upstreamRoots,
			Hooks:             h,
			Capture:           reg,
			IsolationReadOnly: cfg.Isolation == "readonly",
			S2cMaxPacket:      s2cLimit,
			TunnelFallback:    cfg.MITM.TunnelFallback,
		},
	}, nil
}

// Register adds a hook to the relay (see pkg/hooks for the interface).
// Hooks may be registered before or after Run; a hook applies from the
// next connection resolved by the relay.
func (a *Prox) Register(h hooks.Hook) {
	a.hooks.Register(h)
}

// SetLeafSelector installs the consumer's leaf-selection callback (see
// proxy.Ladder.LeafSelector): it is consulted before the built-in minter
// for every TLS flow. Call before Run.
func (a *Prox) SetLeafSelector(fn func(host, dst string) (*tls.Certificate, error)) {
	a.Ladder.LeafSelector = fn
}

// SetRulesRunner sets the runner the rule lifecycle uses (managed mode).
// Call before Run; nil (the default) uses the built-in exec runner.
func (a *Prox) SetRulesRunner(r rules.Runner) { a.ruleRunner = r }

// loadUpstreamRoots builds the extra trust anchors for upstream server
// verification (vendor self-signed certs); nil = system roots only.
func loadUpstreamRoots(paths []string) (*x509.CertPool, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("%s: no certificates parsed", path)
		}
	}
	return pool, nil
}

// Run installs the TPROXY rules (managed mode; in consumer mode prox
// installs and removes nothing — the operator or embedding host owns the
// diversion), listens on cfg.Listen, and dispatches each accepted
// connection to the ladder with its original destination. It runs until
// ctx is cancelled; in managed mode the rules are removed best-effort on
// the way out.
func (a *Prox) Run(ctx context.Context) error {
	params, err := a.ruleParams()
	if err != nil {
		return err
	}
	// Converge before installing: BuildRules is not idempotent (-N DIVERT
	// and ip rule/route add fail if state from an earlier run, a reboot,
	// or a manual deploy/tproxy-setup.sh is present). Best-effort removal
	// clears exactly the prox-owned rules; foreign state is left alone and
	// Apply fails loudly on it.
	runner := a.ruleRunner
	if runner == nil {
		runner = execRunner{}
	}
	cleanup, err := a.ruleLifecycle(params, runner)
	if err != nil {
		return err
	}
	defer cleanup()

	ln, err := transparentListen(a.cfg.Listen)
	if err != nil {
		return fmt.Errorf("prox: listen: %w", err)
	}
	a.ln = ln
	defer a.closeListener()
	slog.Info("listening", "addr", a.cfg.Listen)

	if a.cfg.DataRoot != "" {
		ensureDataDoc(a.cfg.DataRoot, fs.FileMode(a.cfg.Log.DirMode))
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if a.Store != nil {
		go a.recheckLoop(ctx)
	}
	if a.cfg.DataRoot != "" {
		go a.retentionLoop(ctx)
	}

	return a.acceptLoop(ctx)
}

// acceptLoop serves each accepted connection until ctx is cancelled or a
// fatal accept error. SIGTERM cancels ctx but cannot interrupt Accept, so a
// watcher closes the listener to unblock the loop; otherwise the process
// would block until systemd's SIGKILL and skip the deferred rule cleanup
// (leaving TPROXY blackholing 80/443 with no listener).
func (a *Prox) acceptLoop(ctx context.Context) error {
	ln := a.ln
	go func() {
		<-ctx.Done()
		a.closeListener()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Error("accept", "err", err)
			return fmt.Errorf("prox: accept: %w", err)
		}
		a.trackConn(conn) // count + register before spawning: the drain must never miss the last conn
		go a.serveConn(conn)
	}
}

// trackConn records an accepted connection in the in-flight set before its
// serve goroutine starts: the counter is the drain's liveness signal, the
// registry is Shutdown's force-close handle.
func (a *Prox) trackConn(conn net.Conn) {
	a.active.Add(1)
	a.connsMu.Lock()
	if a.conns == nil {
		a.conns = make(map[net.Conn]struct{})
	}
	a.conns[conn] = struct{}{}
	a.connsMu.Unlock()
}

// untrackConn releases a finished connection — serveConn's deferred balance
// of acceptLoop's trackConn.
func (a *Prox) untrackConn(conn net.Conn) {
	a.active.Add(-1)
	a.connsMu.Lock()
	delete(a.conns, conn)
	a.connsMu.Unlock()
}

func (a *Prox) serveConn(conn net.Conn) {
	// acceptLoop's trackConn recorded the conn before this goroutine
	// starts; untrackConn balances the counter and registry on the way out.
	defer a.untrackConn(conn)
	a.Ladder.Serve(conn, originalDst(conn))
}

// Shutdown closes the listener, then stops the proxy in three bounded
// phases: a grace (DrainGrace, 2s by default) for in-flight connections to
// finish on their own; a force-close of whatever remains (logged) — closing
// the client legs, the relay's close plumbing tears each flow's other legs
// down; and a settle wait for the connection goroutines' cleanup to
// complete. Each wait is bounded by the caller's ctx; if the ctx ends first
// the error names the connections still in flight. A pre-cancelled ctx
// makes the drain return immediately — callers draining after a signal must
// pass a fresh ctx.
func (a *Prox) Shutdown(ctx context.Context) error {
	slog.Info("shutting down")
	if a.Ladder != nil {
		a.Ladder.Draining.Store(true)
	}
	a.closeListener()
	// Grace: short transactions finish naturally and are never torn
	// mid-flight.
	grace := a.DrainGrace
	if grace <= 0 {
		grace = drainGraceDefault
	}
	if !a.awaitIdle(ctx, grace) {
		if ctx.Err() != nil {
			return a.drainError(ctx)
		}
		// The grace expired with connections still running; the force
		// phase below takes over.
	}
	// Force: long-lived connections (tunnels) never finish on their own.
	if a.active.Load() > 0 {
		a.connsMu.Lock()
		snap := make([]net.Conn, 0, len(a.conns))
		for c := range a.conns {
			snap = append(snap, c)
		}
		a.connsMu.Unlock()
		for _, c := range snap {
			_ = c.Close()
		}
		// A conn can finish between the active check and the snapshot, so
		// skip the log rather than announce force-closing nothing.
		if len(snap) > 0 {
			slog.Info("drain: force-closed", "connections", len(snap))
		}
	}
	// Settle: serveConn's defers (drain event, pipe close, capture finish,
	// sink writes) must run to completion before Shutdown returns.
	if !a.awaitIdle(ctx, 0) {
		return a.drainError(ctx)
	}
	var errs []error
	if a.Store != nil {
		errs = append(errs, a.Store.Close())
	}
	return errors.Join(errs...)
}

// awaitIdle reports whether the in-flight set empties before ctx ends or
// timeout elapses, whichever is sooner; a zero timeout makes it a pure
// ctx-bounded wait. The 10ms poll keeps the wait responsive to the last
// connection's exit without busy-spinning.
func (a *Prox) awaitIdle(ctx context.Context, timeout time.Duration) bool {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	for a.active.Load() > 0 {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(10 * time.Millisecond):
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return a.active.Load() == 0
		}
	}
	return true
}

func (a *Prox) drainError(ctx context.Context) error {
	return fmt.Errorf("prox: drain: %d connection(s) still in flight: %w", a.active.Load(), ctx.Err())
}

// closeListener closes the listener exactly once: the ctx-cancel watcher,
// Run's deferred cleanup, and Shutdown may each call it, and a second Close
// on a TCP listener errors (exit-code 1 on an otherwise clean stop).
func (a *Prox) closeListener() {
	a.lnOnce.Do(func() {
		if a.ln != nil {
			a.ln.Close()
		}
	})
}

func (a *Prox) ruleParams() (rules.Params, error) {
	onPort := 0
	if addr, err := net.ResolveTCPAddr("tcp", a.cfg.Listen); err == nil {
		onPort = addr.Port
	}
	for _, name := range a.cfg.Rules.Ifaces {
		// A rule for a missing interface installs fine but never matches;
		// fail fast instead of silently capturing nothing.
		if _, err := net.InterfaceByName(name); err != nil {
			return rules.Params{}, fmt.Errorf("prox: rules.ifaces: %w", err)
		}
	}
	return rules.Params{
		OnPort:       onPort,
		Ports:        a.cfg.Ports,
		FWMark:       a.cfg.Rules.FWMark,
		RoutingTable: a.cfg.Rules.RoutingTable,
		Ifaces:       a.cfg.Rules.Ifaces,
	}, nil
}

// ruleLifecycle wires the tproxy rules for this run and returns the
// cleanup (removal) function. Consumer mode: the operator — or the
// embedding host — owns the diversion; no runner calls at all, and the
// exit path removes nothing.
func (a *Prox) ruleLifecycle(params rules.Params, runner rules.Runner) (func(), error) {
	if a.cfg.Rules.Mode == "consumer" {
		slog.Info("tproxy rules: consumer-owned — install and removal skipped")
		return func() {}, nil
	}
	if err := rules.Remove(runner, params); err != nil {
		slog.Debug("clear stale tproxy rules", "err", err)
	}
	if err := rules.Apply(runner, params); err != nil {
		slog.Error("install tproxy rules", "err", err)
		return nil, fmt.Errorf("prox: install rules: %w", err)
	}
	slog.Info("tproxy rules installed", "ports", a.cfg.Ports, "on_port", params.OnPort, "fwmark", params.FWMark, "routing_table", params.RoutingTable)
	return func() {
		if err := rules.Remove(runner, params); err != nil {
			slog.Error("remove tproxy rules", "err", err)
		}
	}, nil
}

// ensureDataDoc installs the data model guide at <dataroot>/AGENTS.md so
// agents pointed at the capture directory can read its shape. Convergent:
// the file is rewritten only when its content differs.
func ensureDataDoc(dataRoot string, dirMode fs.FileMode) {
	target := filepath.Join(dataRoot, "AGENTS.md")
	if cur, err := os.ReadFile(target); err == nil && bytes.Equal(cur, dataModelDoc) {
		return
	}
	if err := os.MkdirAll(dataRoot, dirMode); err != nil {
		slog.Warn("datadir docs", "err", err)
		return
	}
	// Deliberately world-readable: the guide is for operators and agents,
	// not capture data, so file_mode does not apply to it.
	if err := os.WriteFile(target, dataModelDoc, 0o644); err != nil {
		slog.Warn("datadir docs", "err", err)
	}
}

// recheckLoop unmarks patched pairs whose recheck interval has elapsed so
// their next connection gets a fresh MITM attempt.
func (a *Prox) recheckLoop(ctx context.Context) {
	t := time.NewTicker(recheckTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pairs, err := a.Store.Recheck(time.Now(), a.cfg.MITM.PatchedRecheck)
			if err != nil {
				slog.Warn("patch recheck", "err", err)
				continue
			}
			for _, p := range pairs {
				if err := a.Store.Unmark(p.IP, p.Host); err != nil {
					slog.Warn("patch recheck unmark", "ip", p.IP, "host", p.Host, "err", err)
					continue
				}
			}
			if len(pairs) > 0 {
				slog.Info("patch recheck", "unmarked", len(pairs))
			}
		}
	}
}

// retentionLoop prunes the sink by age and size and evicts finished capture
// records.
func (a *Prox) retentionLoop(ctx context.Context) {
	t := time.NewTicker(retentionTick)
	defer t.Stop()
	evict := time.NewTicker(captureEvictTick)
	defer evict.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := sink.Compact(a.cfg.DataRoot, a.cfg.Log.RetentionMaxAge, a.cfg.Log.RetentionMaxSize, 0); err != nil {
				slog.Warn("retention compact", "err", err)
			} else {
				slog.Info("retention compacted")
			}
		case <-evict.C:
			a.Capture.Evict(time.Now(), captureEvictAge)
		}
	}
}

// transparentListen creates the TCP listener the TPROXY target delivers
// to. The kernel's TPROXY listener lookup only sees sockets bound with
// IP_TRANSPARENT; a plain net.Listen is invisible to it, so every captured
// packet is dropped inside the target — the rule counter grows while the
// proxy sees nothing.
//
// SO_MARK must NOT be set on this socket: a listener's mark is inherited by
// every SYN-ACK it triggers (tcp_conn_request derives ireq->ir_mark from
// sk->sk_mark) and by every accepted child. Together with the "ip rule
// fwmark N lookup T" + "local 0.0.0.0/0 dev lo table T" pair that tproxy
// delivery needs, any mark matching the rule routes the SYN-ACK — and every
// later reply — to loopback instead of out on the wire: the client sees
// nothing and the handshake never completes. The rule's --tproxy-mark marks
// the skb, not the socket. Requires CAP_NET_ADMIN (the service runs as root).
func transparentListen(addr string) (net.Listener, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("listen addr %q: bad port", addr)
	}
	ip4 := net.ParseIP(host).To4()
	if ip4 == nil {
		return nil, fmt.Errorf("listen addr %q: TPROXY capture is IPv4", addr)
	}
	raw, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	closeRaw := func() { _ = syscall.Close(raw) }
	if err := syscall.SetsockoptInt(raw, syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		closeRaw()
		return nil, fmt.Errorf("IP_TRANSPARENT: %w", err)
	}
	sa := &syscall.SockaddrInet4{Port: port, Addr: [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}}
	if err := syscall.Bind(raw, sa); err != nil {
		closeRaw()
		return nil, fmt.Errorf("bind: %w", err)
	}
	if err := syscall.Listen(raw, 4096); err != nil {
		closeRaw()
		return nil, fmt.Errorf("listen: %w", err)
	}
	f := os.NewFile(uintptr(raw), "tproxy-listener")
	ln, err := net.FileListener(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return ln, nil
}

// originalDst returns the packet's original destination. TPROXY preserves
// the original tuple on the accepted socket: LocalAddr (getsockname) is the
// original destination, RemoteAddr (getpeername) is the client,
// verified on a live deployment (LocalAddr=198.51.100.72:14431, RemoteAddr=client,
// IP_TRANSPARENT=1 on the accepted child). This mirrors HAProxy's
// sock_inet_get_dst (src/sock_inet.c): for a transparent socket, getsockname
// is the answer; SO_ORIGINAL_DST is a conntrack-dependent NAT/REDIRECT
// mechanism and is not used (the design is TPROXY-only). Non-TPROXY
// connections (unit tests) fall back to RemoteAddr.
func originalDst(conn net.Conn) net.Addr {
	if isTransparent(conn) {
		return conn.LocalAddr()
	}
	return conn.RemoteAddr()
}

// isTransparent reports whether conn's socket has IP_TRANSPARENT set, i.e.
// it was created by TPROXY delivery. The accepted child inherits the option
// from the transparent listener.
func isTransparent(conn net.Conn) bool {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return false
	}
	sc, err := tc.SyscallConn()
	if err != nil {
		return false
	}
	var val int32
	var n int32 = 4
	var serr syscall.Errno
	cerr := sc.Control(func(fd uintptr) {
		_, _, serr = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, uintptr(unsafe.Pointer(&val)), uintptr(unsafe.Pointer(&n)), 0)
	})
	return cerr == nil && serr == 0 && val != 0
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}
