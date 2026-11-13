// Package isolation is prox's built-in client–upstream isolation hook. It
// serves every flow with a local blackhole leg: c2s is accepted and captured
// exactly as on a mirrored flow (including the client-leg MITM handshake on
// TLS flows), no upstream is ever dialed, and the client receives nothing.
package isolation

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/nicois/prox/pkg/hooks"
)

// blackhole is an io.ReadWriteCloser that accepts and discards every write;
// Read blocks until Close, then returns io.EOF; Close is idempotent. One is
// created per flow, so there is no shared state between flows.
type blackhole struct {
	once   sync.Once
	done   chan struct{}
	closed atomic.Bool
}

var errClosedLeg = errors.New("isolation: leg closed")

func newBlackhole() *blackhole { return &blackhole{done: make(chan struct{})} }

func (b *blackhole) Write(p []byte) (int, error) {
	if b.closed.Load() {
		return 0, errClosedLeg
	}
	return len(p), nil
}

func (b *blackhole) Read(p []byte) (int, error) {
	<-b.done
	return 0, io.EOF
}

func (b *blackhole) Close() error {
	b.closed.Store(true)
	b.once.Do(func() { close(b.done) })
	return nil
}

// fullHook is the built-in full-isolation hook: a hooks.Hook implementing
// hooks.Serving. It is stateless — one instance serves all flows, with a
// fresh blackhole per flow.
type fullHook struct{}

// Full returns the built-in full-isolation hook: every flow is served with a
// local blackhole leg — c2s is accepted and captured exactly as on a
// mirrored flow (including the client-leg MITM handshake on TLS flows), no
// upstream is ever dialed, and the client receives nothing. Register it
// before any consumer hooks so the operator's isolation config wins the
// serve decision.
func Full() hooks.Hook { return fullHook{} }

func (fullHook) Filter() hooks.Match { return hooks.Match{} }
func (fullHook) OnOpen(c *hooks.Conn, hc *hooks.HookConn) hooks.Result {
	c.SetLabel("isolation", "full")
	return hooks.Result{}
}
func (fullHook) OnData(c *hooks.Conn, dir hooks.Dir, data []byte) hooks.Result { return hooks.Result{} }
func (fullHook) OnClose(c *hooks.Conn, reason string)                          {}
func (fullHook) Name() string                                                  { return "isolation" }
func (fullHook) Serve(c *hooks.Conn) (hooks.ServeDecision, error) {
	return hooks.ServeDecision{Mode: hooks.ServeLocal, Local: newBlackhole()}, nil
}
