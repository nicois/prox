package prox

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/nicois/prox/pkg/config"
	"github.com/nicois/prox/pkg/hooks"
	"github.com/nicois/prox/pkg/proxy"
	"github.com/nicois/prox/pkg/rules"
	"github.com/nicois/prox/pkg/sink"
)

// TestAcceptLoopUnblocksOnCancel: cancelling ctx (SIGTERM) must unblock the
// accept loop promptly — Run previously blocked on Accept until systemd's
// SIGKILL, skipping the deferred TPROXY rule removal.
func TestAcceptLoopUnblocksOnCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := &Prox{ln: ln}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.acceptLoop(ctx) }()
	time.Sleep(50 * time.Millisecond) // let it park in Accept
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("acceptLoop after cancel: %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acceptLoop did not unblock after ctx cancel")
	}
	// Shutdown must not report the listener close (already done by the
	// watcher) — otherwise main exits 1 on an otherwise clean stop.
	if err := a.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown after clean cancel: %v, want nil", err)
	}
}

func TestNewWiresComponents(t *testing.T) {
	cfg := config.Default()
	cfg.DataRoot = t.TempDir()
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.Ladder == nil || a.Store == nil || a.Leaves == nil {
		t.Fatal("New did not wire all components")
	}
	if a.Ladder.UpstreamRoots != nil {
		t.Fatal("UpstreamRoots must be nil (system roots) without upstream_cas")
	}
	a.Shutdown(context.Background())
}

// testVendorCertPEM is a throwaway self-signed cert; only its parsability
// matters for the upstream_cas wiring.
const testVendorCertPEM = `-----BEGIN CERTIFICATE-----
MIIBrjCCAVWgAwIBAgIUNZK7Ms2CueRVxDUU53D5yv+2qn0wCgYIKoZIzj0EAwIw
LTERMA8GA1UECgwIVm94IFRlc3QxGDAWBgNVBAMMD3ZveC10ZXN0LXZlbmRvcjAe
Fw0yNjExMDMyMzQ5MjhaFw0zNjEwMzEyMzQ5MjhaMC0xETAPBgNVBAoMCFZveCBU
ZXN0MRgwFgYDVQQDDA92b3gtdGVzdC12ZW5kb3IwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQcEZ97WuC4ZHm529u+Ev32MJ9lI3FAorc7YqXWA6ON5G+NdDb4HaVr
Je7+PQy4tNdEV73C6AYtFWyCxpXz9Fhuo1MwUTAdBgNVHQ4EFgQU7BpIwgq/ONw8
eGfQjVBnnO8inWcwHwYDVR0jBBgwFoAU7BpIwgq/ONw8eGfQjVBnnO8inWcwDwYD
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBW+fEps7aJb1fptak6Ys5z
FoCGdUDnvgL1PwqI6zLRlAIgMHTiWt8+3x7q3QkD02wpu2vFRrxUw+KtnL/ME272
Awk=
-----END CERTIFICATE-----`

// TestNewUpstreamRoots verifies mitm.upstream_cas files become the
// ladder's extra upstream trust anchors, and a missing file fails startup.
func TestNewUpstreamRoots(t *testing.T) {
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "vendor.pem")
	if err := os.WriteFile(pemPath, []byte(testVendorCertPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DataRoot = t.TempDir()
	cfg.MITM.UpstreamCAs = []string{pemPath}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.Ladder.UpstreamRoots == nil {
		t.Fatal("UpstreamRoots must be populated from upstream_cas")
	}
	a.Shutdown(context.Background())

	cfg2 := config.Default()
	cfg2.DataRoot = t.TempDir()
	cfg2.MITM.UpstreamCAs = []string{filepath.Join(dir, "missing.pem")}
	if _, err := New(cfg2); err == nil {
		t.Fatal("New with missing upstream_cas file: want error")
	}
}

// TestTransparentListenOptions: the TPROXY target only delivers to sockets
// bound with IP_TRANSPARENT (a plain net.Listen is invisible to the lookup,
// so captured packets are dropped inside the target). The mark must stay 0:
// a marked listener routes its own SYN-ACKs to the "local ... dev lo" tproxy
// table instead of out on the wire. Setting IP_TRANSPARENT needs
// CAP_NET_RAW/CAP_NET_ADMIN; skip when unprivileged.
func TestTransparentListenOptions(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("setting IP_TRANSPARENT requires CAP_NET_RAW/CAP_NET_ADMIN")
	}
	ln, err := transparentListen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("transparentListen: %v", err)
	}
	defer ln.Close()
	tl, ok := ln.(*net.TCPListener)
	if !ok {
		t.Fatalf("listener type %T, want *net.TCPListener", ln)
	}
	sc, err := tl.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var mark, tr int
	if cerr := sc.Control(func(fd uintptr) {
		mark, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
		tr, _ = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TRANSPARENT)
	}); cerr != nil {
		t.Fatal(cerr)
	}
	if mark != 0 {
		t.Fatalf("SO_MARK = %d, want 0 (a marked listener misroutes its own SYN-ACKs to the tproxy local table)", mark)
	}
	if tr != 1 {
		t.Fatalf("IP_TRANSPARENT = %d, want 1", tr)
	}
}

// TestNewEmbeddedNoDataRoot: cfg.DataRoot "" runs with zero filesystem
// side effects — no dir created, no store, noop sink, capture registry live.
func TestNewEmbeddedNoDataRoot(t *testing.T) {
	cfg := config.Default()
	cfg.DataRoot = ""
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.Store != nil {
		t.Error("Store must be nil without a dataroot")
	}
	if a.Capture == nil {
		t.Error("Capture registry must be wired")
	}
	sc, err := a.Ladder.Sink("", "test-id", 0)
	if err != nil {
		t.Fatalf("embedded sink factory: %v", err)
	}
	if _, _, err := sc.WriteC2S([]byte("x")); err != nil {
		t.Errorf("embedded sink must discard: %v", err)
	}
	a.Shutdown(context.Background())
}

// TestNewIsolationWiring: cfg.Isolation selects the client–upstream isolation
// in the built ladder. full serves a flow locally (no dial, nothing sent back);
// readonly sets Ladder.IsolationReadOnly; off leaves both unset and mirrors
// through the dialer as before.
func TestNewIsolationWiring(t *testing.T) {
	dst := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80}

	t.Run("full", func(t *testing.T) {
		cfg := config.Default()
		cfg.DataRoot, cfg.Isolation = "", "full"
		a, err := New(cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if a.Ladder.IsolationReadOnly {
			t.Error("IsolationReadOnly must be false under full")
		}
		release, dialed := make(chan struct{}), make(chan struct{})
		a.Ladder.Dial = newDialer(release, dialed)
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		go func() {
			defer client.Close()
			_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
			_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			buf := make([]byte, 1)
			_, _ = client.Read(buf) // must receive nothing
		}()
		if err := a.Ladder.Serve(server, dst); err != nil {
			t.Fatalf("Serve: %v", err)
		}
		select {
		case <-dialed:
			t.Fatal("Dial called under full isolation")
		default:
		}
		a.Shutdown(context.Background())
	})

	t.Run("readonly", func(t *testing.T) {
		cfg := config.Default()
		cfg.DataRoot, cfg.Isolation = "", "readonly"
		a, err := New(cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if !a.Ladder.IsolationReadOnly {
			t.Error("IsolationReadOnly must be true under readonly")
		}
		a.Shutdown(context.Background())
	})

	t.Run("off", func(t *testing.T) {
		cfg := config.Default()
		cfg.DataRoot, cfg.Isolation = "", "off"
		a, err := New(cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if a.Ladder.IsolationReadOnly {
			t.Error("IsolationReadOnly must be false under off")
		}
		release, dialed := make(chan struct{}), make(chan struct{})
		a.Ladder.Dial = newDialer(release, dialed)
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		go func() {
			_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		}()
		serveErr := make(chan error, 1)
		go func() {
			serveErr <- a.Ladder.Serve(server, dst)
		}()
		select {
		case <-dialed:
		case <-time.After(2 * time.Second):
			t.Fatal("Dial not called: off must mirror, not serve locally")
		}
		close(release) // let the dial fail so Serve can return
		if err := <-serveErr; err == nil {
			t.Error("Serve: expected the hermetic dial to fail, got nil")
		}
		a.Shutdown(context.Background())
	})
}

// TestNewS2cMaxPacketWiring: cfg.S2cMaxPacket reaches the built ladder only
// for isolation "off" — the cap is inapplicable under readonly (no s2c is
// delivered) and full (no relay at all), so those modes drop it.
func TestNewS2cMaxPacketWiring(t *testing.T) {
	for _, tc := range []struct {
		isolation string
		want      int
	}{
		{"off", 2048},
		{"readonly", 0},
		{"full", 0},
	} {
		t.Run(tc.isolation, func(t *testing.T) {
			cfg := config.Default()
			cfg.DataRoot, cfg.Isolation, cfg.S2cMaxPacket = "", tc.isolation, 2048
			a, err := New(cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if a.Ladder.S2cMaxPacket != tc.want {
				t.Errorf("Ladder.S2cMaxPacket = %d under isolation %q, want %d", a.Ladder.S2cMaxPacket, tc.isolation, tc.want)
			}
			a.Shutdown(context.Background())
		})
	}
}

// TestShutdownDrainsInFlight: Shutdown waits for in-flight connections and
// reports the remainder when ctx ends first. Hermetic: the upstream dial is
// faked through Ladder.Dial and blocked on a release channel, so nothing
// touches DNS or the network.
func TestShutdownDrainsInFlight(t *testing.T) {
	waitFor := func(a *Prox, want int64) {
		deadline := time.Now().Add(2 * time.Second)
		for a.active.Load() != want {
			if time.Now().After(deadline) {
				t.Fatalf("active = %d, want %d", a.active.Load(), want)
			}
			time.Sleep(time.Millisecond)
		}
	}
	// Park a conn in the fake dial: serveConn parks in the first Read,
	// the junk byte classifies it raw-TCP, and the dial blocks on release.
	blockConn := func(a *Prox, client, server net.Conn, release, dialed chan struct{}) {
		a.Ladder.Dial = newDialer(release, dialed)
		a.trackConn(server) // acceptLoop does this before spawning serveConn
		go a.serveConn(server)
		waitFor(a, 1)
		if _, err := client.Write([]byte{0x01}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-dialed:
		case <-time.After(2 * time.Second):
			t.Fatal("fake dialer was not reached")
		}
	}

	// A conn in flight (dial blocked) makes the short-ctx Shutdown return
	// the drain error; after release the counter reaches 0 and Shutdown
	// returns nil.
	release, dialed := make(chan struct{}), make(chan struct{})
	a := &Prox{Ladder: &proxy.Ladder{
		Sink: func(string, string, int64) (*sink.Conn, error) { return sink.Noop(), nil },
	}}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	blockConn(a, clientConn, serverConn, release, dialed)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := a.Shutdown(ctx); err == nil {
		t.Fatal("Shutdown with an in-flight connection and an expired ctx: want error")
	}
	close(release)
	waitFor(a, 0)
	if err := a.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown after drain: %v, want nil", err)
	}

	// Shutdown itself must block until the in-flight conn ends: with the
	// dial still blocked, Shutdown must still be running 100 ms in; only
	// after release does it return.
	release2, dialed2 := make(chan struct{}), make(chan struct{})
	b := &Prox{Ladder: &proxy.Ladder{
		Sink: func(string, string, int64) (*sink.Conn, error) { return sink.Noop(), nil },
	}}
	client2, server2 := net.Pipe()
	defer client2.Close()
	defer server2.Close()
	blockConn(b, client2, server2, release2, dialed2)
	longCtx, lcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer lcancel()
	ended := make(chan struct{})
	go func() {
		b.Shutdown(longCtx)
		close(ended)
	}()
	select {
	case <-ended:
		t.Fatal("Shutdown returned before the in-flight connection ended")
	case <-time.After(100 * time.Millisecond):
	}
	close(release2)
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return after the connection ended")
	}
}

// newDialer returns a Ladder.Dial that signals dialed on its first call,
// then blocks until release is closed, and returns a fixed error. Hermetic
// stand-in for the upstream dial (TestShutdownDrainsInFlight,
// TestShutdownDrainEvent).
func newDialer(release, dialed chan struct{}) func(net.Addr) (net.Conn, error) {
	return func(net.Addr) (net.Conn, error) {
		close(dialed)
		<-release
		return nil, errors.New("upstream down")
	}
}

// drainHook records the events fired for the TestShutdownDrainEvent flow.
type drainHook struct{ evs chan hooks.Event }

func (h drainHook) Filter() hooks.Match                                   { return hooks.Match{} }
func (h drainHook) OnOpen(c *hooks.Conn, hc *hooks.HookConn) hooks.Result { return hooks.Result{} }
func (h drainHook) OnData(c *hooks.Conn, dir hooks.Dir, data []byte) hooks.Result {
	return hooks.Result{}
}
func (h drainHook) OnClose(c *hooks.Conn, reason string) {}
func (h drainHook) OnEvent(c *hooks.Conn, e hooks.Event) { h.evs <- e }

// TestShutdownDrainEvent: a connection that ends while Prox.Shutdown is
// running must fire the drain event.
func TestShutdownDrainEvent(t *testing.T) {
	waitFor := func(a *Prox, want int64) {
		deadline := time.Now().Add(2 * time.Second)
		for a.active.Load() != want {
			if time.Now().After(deadline) {
				t.Fatalf("active = %d, want %d", a.active.Load(), want)
			}
			time.Sleep(time.Millisecond)
		}
	}
	evs := make(chan hooks.Event, 4)

	release := make(chan struct{})
	dialed := make(chan struct{})
	a := &Prox{Ladder: &proxy.Ladder{
		Sink:  func(string, string, int64) (*sink.Conn, error) { return sink.Noop(), nil },
		Hooks: func() *hooks.Pipeline { p := hooks.NewPipeline(); p.Register(drainHook{evs: evs}); return p }(),
		Dial:  newDialer(release, dialed),
	}}
	client, server := net.Pipe()
	defer server.Close()
	a.trackConn(server)
	go a.serveConn(server)
	waitFor(a, 1)
	if _, err := client.Write([]byte{0x01}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- a.Shutdown(context.Background()) }()
	// Wait until Shutdown has marked the ladder draining (the drain event
	// requires it), then end the in-flight connection.
	deadline := time.Now().Add(2 * time.Second)
	for !a.Ladder.Draining.Load() {
		if time.Now().After(deadline) {
			t.Fatal("Shutdown did not mark the ladder draining")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	client.Close()
	if err := <-done; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	sawDrain := false
	// evs is never closed: drain the buffer with non-blocking selects.
drain:
	for {
		select {
		case ev := <-evs:
			if ev.Kind == hooks.Drain {
				sawDrain = true
				break drain
			}
		default:
			break drain
		}
	}
	if !sawDrain {
		t.Error("no drain event for the conn that ended during Shutdown")
	}
}

// TestShutdownForceClosesInFlight: a connection that does not finish on its
// own (a long-lived tunnel) must not hold the stop path open. Shutdown must
// force-close it after the drain grace and settle well under the caller's
// deadline — blocking until the deadline is exactly the behavior that let
// systemd's stop timeout SIGABRT the live process mid-drain.
func TestShutdownForceClosesInFlight(t *testing.T) {
	waitFor := func(a *Prox, want int64) {
		deadline := time.Now().Add(2 * time.Second)
		for a.active.Load() != want {
			if time.Now().After(deadline) {
				t.Fatalf("active = %d, want %d", a.active.Load(), want)
			}
			time.Sleep(time.Millisecond)
		}
	}
	evs := make(chan hooks.Event, 4)
	dialed := make(chan struct{})
	// The dial seam returns a held upstream leg (net.Pipe, never read and
	// never closed by the relay): the flow parks in the relay copies,
	// exactly like a live tunnel.
	upClient, upServer := net.Pipe()
	a := &Prox{Ladder: &proxy.Ladder{
		Sink:  func(string, string, int64) (*sink.Conn, error) { return sink.Noop(), nil },
		Hooks: func() *hooks.Pipeline { p := hooks.NewPipeline(); p.Register(drainHook{evs: evs}); return p }(),
		Dial: func(net.Addr) (net.Conn, error) {
			close(dialed)
			return upClient, nil
		},
	}}
	client, server := net.Pipe()
	defer client.Close()
	defer upServer.Close()
	a.trackConn(server) // acceptLoop does this before spawning serveConn
	go a.serveConn(server)
	waitFor(a, 1)
	if _, err := client.Write([]byte{0x01}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dialed:
	case <-time.After(2 * time.Second):
		t.Fatal("fake dialer was not reached")
	}
	// Consume the prefix byte the c2s copy pushes to the upstream leg so
	// the flow parks in the relay copies, both legs blocked on reads.
	if _, err := upServer.Read(make([]byte, 1)); err != nil {
		t.Fatalf("read the prefix off the upstream leg: %v", err)
	}
	// A real peer tears down its leg once the client leg goes away: watch
	// the client leg and close the upstream leg when it does.
	go func() {
		buf := make([]byte, 1)
		for {
			if _, err := client.Read(buf); err != nil {
				upServer.Close()
				return
			}
		}
	}()

	// Bounded stop: grace + force-close + settle must finish well under
	// the 5s deadline, with the held conn force-closed and nothing left
	// in flight.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- a.Shutdown(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown with a held in-flight connection: %v, want nil (bounded by grace + force-close + settle)", err)
		}
		if d := time.Since(start); d > 4*time.Second {
			t.Fatalf("Shutdown took %v, want well under the 5s deadline", d)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("Shutdown did not return within grace + settle, want well under the 5s deadline (it must force-close, not wait for the conn)")
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("client leg still open after the force-close")
	}
	if n := a.active.Load(); n != 0 {
		t.Errorf("active = %d after Shutdown, want 0", n)
	}
	sawDrain := false
	// evs is never closed: drain the buffer with non-blocking selects.
drain:
	for {
		select {
		case ev := <-evs:
			if ev.Kind == hooks.Drain {
				sawDrain = true
				break drain
			}
		default:
			break drain
		}
	}
	if !sawDrain {
		t.Error("no drain event for the force-closed connection")
	}
}

// TestShutdownForceClosesSilentUpstream: an upstream that goes silent
// (never writes, never closes) must not hold the stop path open. The
// force-close tears the client leg and the c2s copy fails, but the s2c
// copy is parked in the upstream read — only an explicit upstream close
// unblocks it, so without that the conn outlives the settle budget and
// the stop ends in a drain error (exit 1).
func TestShutdownForceClosesSilentUpstream(t *testing.T) {
	waitFor := func(a *Prox, want int64) {
		deadline := time.Now().Add(2 * time.Second)
		for a.active.Load() != want {
			if time.Now().After(deadline) {
				t.Fatalf("active = %d, want %d", a.active.Load(), want)
			}
			time.Sleep(time.Millisecond)
		}
	}
	dialed := make(chan struct{})
	// The SILENT upstream: the leg is held open, never read again,
	// never written, never closed by anyone on the upstream side.
	upClient, upServer := net.Pipe()
	a := &Prox{Ladder: &proxy.Ladder{
		Sink: func(string, string, int64) (*sink.Conn, error) { return sink.Noop(), nil },
		Dial: func(net.Addr) (net.Conn, error) {
			close(dialed)
			return upClient, nil
		},
	}}
	client, server := net.Pipe()
	defer client.Close()
	defer upServer.Close()
	a.trackConn(server) // acceptLoop does this before spawning serveConn
	go a.serveConn(server)
	waitFor(a, 1)
	if _, err := client.Write([]byte{0x01}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dialed:
	case <-time.After(2 * time.Second):
		t.Fatal("fake dialer was not reached")
	}
	// Consume the prefix byte the c2s copy pushes to the upstream leg so
	// the flow parks in the relay copies: c2s on the client read, s2c on
	// the silent upstream read.
	if _, err := upServer.Read(make([]byte, 1)); err != nil {
		t.Fatalf("read the prefix off the upstream leg: %v", err)
	}

	// Bounded stop: grace + force-close + settle must finish well under
	// the 5s deadline even though nothing on the upstream side ever
	// reacts to the client leg going away.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- a.Shutdown(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown with a silent upstream: %v, want nil (the force-close must unblock the parked s2c copy)", err)
		}
		if d := time.Since(start); d > 4*time.Second {
			t.Fatalf("Shutdown took %v, want well under the 5s deadline", d)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("Shutdown did not return within grace + settle, want well under the 5s deadline (the silent upstream outlived the force-close)")
	}
	if n := a.active.Load(); n != 0 {
		t.Errorf("active = %d after Shutdown, want 0", n)
	}
}

// recRunner is a rules.Runner that records every command it is asked to
// execute and never execs — these tests stay hermetic (no iptables, no
// root).
type recRunner struct{ calls [][]string }

func (r *recRunner) Run(name string, args ...string) error {
	r.calls = append(r.calls, append([]string{name}, args...))
	return nil
}

// argvs renders a rules.Cmd set the way recRunner records it (Bin + Args
// per command).
func argvs(cmds []rules.Cmd) [][]string {
	out := make([][]string, len(cmds))
	for i, c := range cmds {
		out[i] = append([]string{c.Bin}, c.Args...)
	}
	return out
}

// argvsEqual reports whether two recorded command sets are identical
// (same commands, same order) — [][]string is not comparable, so compare
// element-wise.
func argvsEqual(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !slices.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// TestRulesModeConsumerRemovesNothing: consumer mode — the operator or
// the embedding host owns the diversion. Zero runner calls at install and
// on cleanup: no stale removal, no apply, no teardown.
func TestRulesModeConsumerRemovesNothing(t *testing.T) {
	cfg := config.Default()
	cfg.DataRoot = ""
	cfg.Rules.Mode = "consumer"
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rr := &recRunner{}
	a.SetRulesRunner(rr)
	params, err := a.ruleParams()
	if err != nil {
		t.Fatalf("ruleParams: %v", err)
	}
	cleanup, err := a.ruleLifecycle(params, rr)
	if err != nil {
		t.Fatalf("ruleLifecycle: %v", err)
	}
	cleanup()
	if len(rr.calls) != 0 {
		t.Fatalf("consumer mode made %d runner calls, want 0: %v", len(rr.calls), rr.calls)
	}
}

// TestRulesModeManagedApplies: managed mode (the default) converges at
// install — Remove(stale) then Apply — and removes at cleanup, all through
// the injected runner, with command sets exactly matching
// rules.BuildRemove / rules.BuildRules.
func TestRulesModeManagedApplies(t *testing.T) {
	cfg := config.Default()
	cfg.DataRoot = ""
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rr := &recRunner{}
	a.SetRulesRunner(rr)
	params, err := a.ruleParams()
	if err != nil {
		t.Fatalf("ruleParams: %v", err)
	}
	removeSet := argvs(rules.BuildRemove(params))
	applySet := argvs(rules.BuildRules(params))
	cleanup, err := a.ruleLifecycle(params, rr)
	if err != nil {
		t.Fatalf("ruleLifecycle: %v", err)
	}
	want := append(append([][]string{}, removeSet...), applySet...)
	if !argvsEqual(rr.calls, want) {
		t.Fatalf("install = %v, want the Remove set followed by the Apply set:\nremove: %v\napply:  %v", rr.calls, removeSet, applySet)
	}
	installed := len(rr.calls)
	cleanup()
	if !argvsEqual(rr.calls[installed:], removeSet) {
		t.Fatalf("cleanup = %v, want the Remove set: %v", rr.calls[installed:], removeSet)
	}
}
