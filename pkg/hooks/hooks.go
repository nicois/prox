// Package hooks gives a host Go application per-connection decision points
// into prox's relay: passively observe the byte streams, modify them, or
// block a connection or individual chunks, in either direction.
//
// A hook is registered on a hooks.Pipeline, which the prox facade hands to
// the relay ladder. For each proxied connection the ladder resolves the
// matching hooks into a per-connection Pipe and routes every chunk through
// it before forwarding. A connection with no matching hooks incurs no hook
// overhead (the pipe is nil and the relay uses plain io.Copy writers).
//
// Hooks can also write: OnOpen receives a per-connection HookConn through
// which the hook injects bytes on its own initiative — for example,
// manufacturing server messages while the real upstream's messages are
// blocked in OnData. Injected bytes are captured like relayed bytes and are
// not reprocessed through the hook chain.
//
// When the relay wires a capture stream into the pipe (pkg/capture), every
// chunk decision is recorded on it: forwarded chunks, dropped chunks with
// the hook's reason, and HookConn writes as injected with the owning
// hook's origin. A drop terminates the chain for that chunk — later hooks
// never see it.
//
// Phase 2 adds three optional surfaces (the Hook interface is unchanged):
// Serving decides per flow at establishment how it is served (mirror /
// tunnel / local — no upstream, consumer leg — / reject); Result.Hold
// buffers a chunk in a bounded per-direction buffer released via
// HookConn.ReleaseC2S/ReleaseS2C (a full buffer backpressures the holding
// direction only, and close resolves unreleased bytes as Dropped records);
// EventObserver receives typed lifecycle and pressure events in-band.
package hooks

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nicois/prox/pkg/capture"
)

// ErrClosed is returned by a hooked writer once the connection has ended,
// to stop that direction's copy loop and any hook writer.
var ErrClosed = errors.New("hooks: connection closed")

// ErrNotReady is returned by HookConn writes made before the relay's legs
// are established (see HookConn.Ready).
var ErrNotReady = errors.New("hooks: connection not established")

// Dir is one direction of a proxied connection's byte stream. It aliases
// capture.Dir so the hook surface and the record stream share one type.
type Dir = capture.Dir

const (
	// DirC2S is bytes flowing client -> upstream.
	DirC2S = capture.DirC2S
	// DirS2C is bytes flowing upstream -> client.
	DirS2C = capture.DirS2C
)

// Conn describes a proxied connection as seen by hooks. Fields are set
// once at connection open and are stable for the connection's lifetime.
type Conn struct {
	ID      string // the connection's sink event id
	Kind    string // sniffed kind: "plain_http", "tls", or "raw_tcp"
	Src     string // client IP address
	SrcPort int
	Dst     string // original destination IP address
	DPort   int
	SNI     string // TLS server name, "" when absent
	// Labels is the flow's typed labels, set by hooks during OnOpen via
	// SetLabel, and by the relay after the chain for built-in isolation
	// modes. Every subsequent hook call on this connection inherits them,
	// and the capture record's CloseInfo inherits them.
	Labels map[string]string
}

// SetLabel attaches a label to the flow. Set it during OnOpen. The capture
// record shares the map by reference (attached once, after the OnOpen
// chain); the OnOpen chain runs sequentially before any chunk flows, so no
// synchronization is needed.
func (c *Conn) SetLabel(key, value string) {
	if c == nil {
		return
	}
	if c.Labels == nil {
		c.Labels = make(map[string]string)
	}
	c.Labels[key] = value
}

// Match selects the connections a hook applies to. Zero fields match all
// connections.
type Match struct {
	Src   string // "" = any client
	Dst   string // "" = any destination
	DPort int    // 0 = any destination port
}

func (m Match) matches(c *Conn) bool {
	if m.Src != "" && m.Src != c.Src {
		return false
	}
	if m.Dst != "" && m.Dst != c.Dst {
		return false
	}
	if m.DPort != 0 && m.DPort != c.DPort {
		return false
	}
	return true
}

// Result is a hook's verdict on a chunk (OnData) or on the connection at
// open (OnOpen). The zero value forwards the chunk unchanged / allows the
// connection.
type Result struct {
	// Data, if non-nil, replaces the chunk. An empty slice drops the chunk:
	// it is neither forwarded nor captured.
	Data []byte
	// Close terminates the connection after this verdict; the chunk is
	// dropped.
	Close bool
	// Reason is recorded in the sink and operator logs when Close is set.
	Reason string
	// Hold buffers the chunk instead of forwarding or dropping it: it is
	// released later by HookConn.ReleaseC2S/ReleaseS2C (forwarded then) or
	// resolved as Dropped with the close reason when the connection ends.
	// Mutually exclusive with Data; with Close, Close wins. Reason is
	// recorded with the Held capture record.
	Hold bool
}

// Hook observes and controls proxied connections. All methods are required;
// a hook that only observes returns Result{} from OnOpen and OnData and
// ignores OnClose.
type Hook interface {
	// Filter selects the connections this hook applies to.
	Filter() Match
	// OnOpen is called when a matching connection opens, before the
	// upstream is dialed. A Close verdict refuses the connection. hc lets
	// the hook write into the relay on its own initiative: the typical
	// pattern is to start a goroutine here that manufactures bytes once
	// hc.Ready() closes and exits when hc.Done() closes.
	OnOpen(c *Conn, hc *HookConn) Result
	// OnData is called for each chunk in the given direction, in
	// registration order, before it is forwarded. Each hook receives the
	// previous hook's output, so an earlier hook's modification is visible
	// to later hooks. Chunks are arbitrary TCP boundaries, not messages.
	// The two directions run concurrently, so a hook must synchronize its
	// own state; it must not retain data beyond the call.
	OnData(c *Conn, dir Dir, data []byte) Result
	// OnClose is called once when a connection ends. reason is "" for a
	// clean end or the closing hook's reason.
	OnClose(c *Conn, reason string)
}

// TLSResult is the client-leg TLS outcome for a flow classified TLS.
// Result vocabulary: "success" | "client_rejected" | "mint_failed".
type TLSResult = capture.TLSInfo

// TLSObserver is implemented by a hook that wants the TLS handshake
// outcome. It is called once, as soon as the client-leg result is known —
// before the upstream leg is dialed on success.
// OnTLSResult is synchronous; a hook that blocks in it delays the flow,
// including the upstream dial (same contract as OnOpen/OnData).
type TLSObserver interface {
	OnTLSResult(c *Conn, r TLSResult)
}

// NotifyTLS delivers the client-leg TLS outcome to hooks that implement
// TLSObserver and attaches it to the capture record.
func (p *Pipe) NotifyTLS(r TLSResult) {
	if p == nil {
		return
	}
	if p.stream != nil {
		rp := r
		p.stream.SetTLS(&rp)
	}
	for _, h := range p.hooks {
		if o, ok := h.(TLSObserver); ok {
			o.OnTLSResult(p.conn, r)
		}
	}
}

// Pipeline is the ordered registry of hooks, shared across all connections.
type Pipeline struct {
	mu    sync.RWMutex
	hooks []Hook
}

// NewPipeline returns an empty pipeline.
func NewPipeline() *Pipeline { return &Pipeline{} }

// Register appends h. Safe to call before or while the proxy is running;
// the connection currently being served picks the hooks up on its next
// chunk.
func (p *Pipeline) Register(h Hook) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hooks = append(p.hooks, h)
}

// Unregister removes h. Safe to call before or while the proxy is running.
func (p *Pipeline) Unregister(h Hook) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, k := range p.hooks {
		if k == h {
			p.hooks = append(p.hooks[:i], p.hooks[i+1:]...)
			return
		}
	}
}

// Pipe builds the per-connection filter for c, or nil when no registered
// hook matches c. A nil Pipeline returns nil.
func (p *Pipeline) Pipe(c *Conn) *Pipe {
	if p == nil || c == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	matched := make([]Hook, 0, len(p.hooks))
	for _, h := range p.hooks {
		if h.Filter().matches(c) {
			matched = append(matched, h)
		}
	}
	if len(matched) == 0 {
		return nil
	}
	return &Pipe{conn: c, hooks: matched, ready: make(chan struct{}), done: make(chan struct{}),
		hold: [2]*holdBuf{newHoldBuf(), newHoldBuf()}}
}

// Pipe runs the matching hooks for one connection. Build one with
// Pipeline.Pipe; a nil Pipe is a no-op in every method, so callers may use
// it without a nil check.
type Pipe struct {
	conn     *Conn
	hooks    []Hook
	mu       sync.Mutex // guards reason, notified, onClose
	reason   string
	notified bool
	onClose  func()
	closed   atomic.Bool
	// wmu serializes writes per direction: the relay's own copy goroutine
	// and hook-initiated HookConn writes share each direction's writer.
	wmu          [2]sync.Mutex
	inner        [2]io.Writer
	readyOnce    sync.Once
	ready        chan struct{} // closed once both directions are bound
	doneOnce     sync.Once
	done         chan struct{}   // closed when the connection ends
	inflight     atomic.Int64    // hook writes in flight (for Seal)
	stream       *capture.Stream // capture record, wired by the relay; nil = no recording
	bytesEnabled bool            // payload capture on, snapshotted from the stream in SetStream
	hold         [2]*holdBuf     // per-direction hold buffers (byte growth is lazy)
	dropGen      [2]uint64       // per-direction policy-drop marks (see MarkDrop)
}

// SetCloseFn wires the leg-teardown callback invoked exactly once when a
// hook closes the connection. The proxy sets it before any bytes flow.
func (p *Pipe) SetCloseFn(fn func()) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.onClose = fn
	p.mu.Unlock()
}

// SetStream wires the capture record for this connection. The relay calls
// it before Open; a nil stream disables recording.
func (p *Pipe) SetStream(s *capture.Stream) {
	if p == nil {
		return
	}
	p.stream = s
	// Snapshot the stream's payload-capture flag here, where the stream
	// is set: it is stable for the stream's lifetime, and every record
	// path (relay or direct) runs after this.
	p.bytesEnabled = s != nil && s.BytesEnabled()
}

// record appends c to the wired capture stream. When payload capture is
// enabled on the stream (Registry.EnableBytes) and payload is non-nil, c
// carries a copy of the chunk bytes — the bytes in scope at the record
// site — safe to retain.
func (p *Pipe) record(c capture.Chunk, payload []byte) {
	if p == nil || p.stream == nil {
		return
	}
	if p.bytesEnabled && payload != nil {
		c.Payload = append([]byte(nil), payload...)
	}
	p.stream.Record(c)
}

// originOf names a hook for injected-chunk records: its Name() when it
// has one, otherwise its type.
func originOf(h Hook) string {
	if n, ok := h.(interface{ Name() string }); ok {
		return n.Name()
	}
	return fmt.Sprintf("%T", h)
}

// Open runs the OnOpen chain and returns the first Close verdict, if any.
// A nil Pipe allows the connection.
func (p *Pipe) Open() Result {
	if p == nil {
		return Result{}
	}
	for _, h := range p.hooks {
		hc := &HookConn{pipe: p, origin: originOf(h)}
		if r := h.OnOpen(p.conn, hc); r.Close {
			p.fireClose(r.Reason)
			return r
		}
	}
	return Result{}
}

// Data runs chunk b in direction dir through the hook chain. It returns the
// bytes to forward (nil = the chunk is dropped) and whether a hook has
// closed the connection. A nil Pipe forwards b unchanged. Every chunk
// decision is recorded on the wired capture stream (pkg/capture); a drop
// terminates the chain for that chunk, so later hooks never see it.
func (p *Pipe) Data(dir Dir, b []byte) ([]byte, bool) {
	if p == nil {
		return b, false
	}
	if p.closed.Load() {
		return nil, true
	}
	cur := b
	for _, h := range p.hooks {
		r := h.OnData(p.conn, dir, cur)
		if r.Close {
			p.record(capture.Chunk{Dir: dir, TS: time.Now(), Len: len(cur), Decision: capture.Dropped, Reason: r.Reason}, cur)
			p.fireClose(r.Reason)
			return nil, true
		}
		if r.Hold {
			// Hold: buffered behind the gate — not forwarded, not dropped.
			// The relay's writer sees nil and consumes the chunk; release
			// or close resolves its fate. The bytes held are cur, i.e. the
			// chunk as transformed by earlier hooks.
			if wm := p.hold[dir].append(cur); wm {
				depth, limit := p.hold[dir].depth()
				p.Emit(Event{Kind: HoldWatermark, Dir: dir,
					Detail: fmt.Sprintf("%d/%d", depth, limit)})
			}
			p.record(capture.Chunk{Dir: dir, TS: time.Now(), Len: len(cur), Decision: capture.Held, Reason: r.Reason}, cur)
			return nil, false
		}
		if r.Data != nil {
			if len(r.Data) == 0 {
				// A hook dropped the chunk: record it with the hook's
				// reason and terminate the chain for this chunk — later
				// hooks must not see it. Len is the chunk as this hook
				// received it (earlier-hook-transformed), consistent
				// with every other record path.
				p.record(capture.Chunk{Dir: dir, TS: time.Now(), Len: len(cur),
					Decision: capture.Dropped, Reason: r.Reason}, cur)
				return nil, false
			}
			cur = r.Data
		}
	}
	if len(cur) == 0 {
		return nil, false
	}
	p.record(capture.Chunk{Dir: dir, TS: time.Now(), Len: len(cur), Decision: capture.Forwarded}, cur)
	return cur, false
}

// Close notifies the hooks that the connection ended with reason. An
// earlier Close verdict's reason takes precedence over the passed one. A
// nil Pipe is a no-op.
func (p *Pipe) Close(reason string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.notified {
		p.mu.Unlock()
		return
	}
	p.notified = true
	r := p.reason
	if r == "" {
		r = reason
	}
	p.mu.Unlock()
	// Resolve held bytes at close: a chunk that was held but never released
	// was lost with the connection — record it as Dropped so the
	// post-decision view stays provable (its Held record shows the hold,
	// this record shows the loss). Must run before stream.Finish, which
	// makes later records no-ops.
	for _, dir := range []Dir{DirC2S, DirS2C} {
		if b := p.hold[dir].drain(); len(b) > 0 {
			res := r
			if res == "" {
				res = "close"
			}
			p.record(capture.Chunk{Dir: dir, TS: time.Now(), Len: len(b), Decision: capture.Dropped, Reason: res}, b)
		}
	}
	p.closed.Store(true)
	p.doneOnce.Do(func() { close(p.done) })
	if p.stream != nil {
		p.stream.Finish(r)
	}
	for _, h := range p.hooks {
		h.OnClose(p.conn, r)
	}
}

// Seal stops hook writes and waits for in-flight ones to finish. The relay
// calls it when its copy loops have ended and before it reads the capture
// ranges or closes the sink, so hook-manufactured bytes cannot still be
// landing in the same writers. A nil Pipe is a no-op.
func (p *Pipe) Seal() {
	if p == nil {
		return
	}
	p.closed.Store(true)
	// Reserve a slot so no write can slip past the closed check after we
	// start counting; wait until only our reservation remains.
	p.inflight.Add(1)
	for p.inflight.Load() > 1 {
		runtime.Gosched()
	}
	p.inflight.Add(-1)
	p.doneOnce.Do(func() { close(p.done) })
}

// MarkDrop flags that the direction's inner writer consumed bytes by
// policy (a size cap — not a transport failure) and recorded each loss on
// the capture stream itself. The relay calls it from inside that writer's
// Write: every write of the direction's inner writer (the relay's own,
// hook-initiated, Release) holds the direction lock, so the mark is
// consistent with Release's before/after comparison. A Release whose write
// moved the mark records no Forwarded resolution of its own — the writer's
// Dropped record is the chunk's fate; recording Forwarded would claim bytes
// that never left. Nil-safe: a nil Pipe marks nothing.
func (p *Pipe) MarkDrop(dir Dir) {
	if p == nil {
		return
	}
	p.dropGen[dir]++
}

// Release flushes direction dir's hold buffer: the buffered bytes are
// written to the direction's inner writer (serialized with the relay's own
// writes and hook writes via the direction lock), recorded as one Forwarded
// chunk — unless the inner writer consumed them by policy (MarkDrop moved
// during the write), in which case the writer's own Dropped record is the
// chunk's resolution — and the watermark re-arms. Nil-safe: a nil Pipe
// releases nothing. After close it fails with the close error; a write that
// fails records the buffered bytes as Dropped so the loss is never silent.
func (p *Pipe) Release(dir Dir) (int, error) {
	if p == nil {
		return 0, nil
	}
	if p.closed.Load() {
		return 0, p.closeErr()
	}
	// Reserve the slot before stealing bytes: Seal counts slots, so a
	// Release that drains must be counted before Close/Finish can run, or
	// its terminal record would hit a finished stream (a silent record
	// loss).
	p.inflight.Add(1)
	b := p.hold[dir].drain()
	if len(b) == 0 {
		p.inflight.Add(-1)
		return 0, nil
	}
	defer p.inflight.Add(-1)
	total := len(b)
	p.wmu[dir].Lock()
	defer p.wmu[dir].Unlock()
	if p.closed.Load() {
		p.record(capture.Chunk{Dir: dir, TS: time.Now(), Len: total, Decision: capture.Dropped, Reason: "release_closed"}, b)
		return 0, p.closeErr()
	}
	inner := p.inner[dir]
	if inner == nil {
		// M-1: check inner before any loss is possible — but the bytes
		// are already drained, so record them as dropped (this branch is
		// unreachable in the documented relay flow: inner binds before
		// any chunk can be held).
		p.record(capture.Chunk{Dir: dir, TS: time.Now(), Len: total, Decision: capture.Dropped, Reason: "release_not_ready"}, b)
		return 0, ErrNotReady
	}
	marked := p.dropGen[dir]
	full := b // the chunk, before the write loop re-bases b
	for len(b) > 0 {
		n, err := inner.Write(b)
		b = b[n:]
		if err != nil {
			p.record(capture.Chunk{Dir: dir, TS: time.Now(), Len: total, Decision: capture.Dropped, Reason: "release_failed"}, full)
			return 0, err
		}
	}
	if p.dropGen[dir] != marked {
		// The inner writer consumed the release by policy (e.g. the s2c
		// cap) and already recorded each loss; its Dropped record is the
		// chunk's resolution.
		return total, nil
	}
	p.record(capture.Chunk{Dir: dir, TS: time.Now(), Len: total, Decision: capture.Forwarded}, full)
	return total, nil
}

// fireClose records reason and calls the leg-teardown callback exactly once.
func (p *Pipe) fireClose(reason string) {
	p.mu.Lock()
	if p.closed.Load() {
		p.mu.Unlock()
		return
	}
	if reason != "" {
		p.reason = reason
	}
	fn := p.onClose
	p.closed.Store(true)
	p.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// Reason returns the close reason set by a hook verdict, or "" when no
// hook has closed the connection.
func (p *Pipe) Reason() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reason
}

// closeErr is the error a hooked writer returns once the connection is
// closed: it carries the hook's reason so operator logs and sink events
// name the cause.
func (p *Pipe) closeErr() error {
	if r := p.Reason(); r != "" {
		return fmt.Errorf("prox: hook close: %s", r)
	}
	return ErrClosed
}

// bind makes direction dir's inner writer available to hook writes and,
// once both directions are bound, closes the ready channel. The relay calls
// it via Writer when it wires up its per-direction writers.
func (p *Pipe) bind(dir Dir, inner io.Writer) {
	if p == nil || inner == nil {
		return
	}
	p.wmu[0].Lock()
	p.wmu[1].Lock()
	p.inner[dir] = inner
	both := p.inner[0] != nil && p.inner[1] != nil
	p.wmu[1].Unlock()
	p.wmu[0].Unlock()
	if both {
		p.readyOnce.Do(func() { close(p.ready) })
	}
}

// Writer returns an io.Writer that runs each chunk through the hook chain
// for direction dir and forwards the surviving bytes to inner. Dropped
// chunks are consumed without forwarding (so the sink does not capture
// them). Once the connection has ended, further writes fail with a close
// error to stop the copy. inner is also bound for HookConn writes, which
// share it. A nil Pipe returns inner unchanged.
func (p *Pipe) Writer(dir Dir, inner io.Writer) io.Writer {
	if p == nil {
		return inner
	}
	p.bind(dir, inner)
	return &pipeWriter{pipe: p, dir: dir}
}

type pipeWriter struct {
	pipe *Pipe
	dir  Dir
}

func (w *pipeWriter) Write(b []byte) (int, error) {
	out, closeConn := w.pipe.Data(w.dir, b)
	if closeConn {
		return 0, w.pipe.closeErr()
	}
	if out == nil {
		return len(b), nil
	}
	// A hook may resize the chunk, so the forwarded bytes are not b
	// itself; loop partial writes and report bytes consumed from b, as
	// the io.Writer contract requires. The direction lock serializes this
	// with hook-initiated writes to the same direction.
	w.pipe.wmu[w.dir].Lock()
	defer w.pipe.wmu[w.dir].Unlock()
	for len(out) > 0 {
		n, err := w.pipe.inner[w.dir].Write(out)
		out = out[n:]
		if err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// HookConn is the per-connection handle passed to OnOpen. It lets a hook
// write bytes into the relay on its own initiative — for example,
// manufacturing server messages while the real upstream's messages are
// blocked in OnData.
//
// HookConn writes share the relay's per-direction writer: they are captured
// in the sink exactly like relayed bytes, serialized with the relay's own
// writes to the same direction, and never reprocessed through the hook
// chain (a hook's own output is not its input). They fail with ErrNotReady
// before Ready closes and with a close error once the connection ends.
type HookConn struct {
	pipe   *Pipe
	origin string // which hook owns this handle, for injected-chunk records
}

// WriteC2S writes b to the upstream leg (the client -> upstream
// direction).
func (h *HookConn) WriteC2S(b []byte) (int, error) {
	return h.pipe.writeBypass(DirC2S, b, h.origin)
}

// WriteS2C writes b to the client leg (the upstream -> client direction).
func (h *HookConn) WriteS2C(b []byte) (int, error) {
	return h.pipe.writeBypass(DirS2C, b, h.origin)
}

// Ready returns a channel closed once the relay's legs are established;
// WriteC2S and WriteS2C fail with ErrNotReady until it closes.
func (h *HookConn) Ready() <-chan struct{} { return h.pipe.ready }

// Done returns a channel closed when the connection ends. Hook goroutines
// should select on it so they cannot outlive the stream or write into a
// closed pipe.
func (h *HookConn) Done() <-chan struct{} { return h.pipe.done }

// ReleaseC2S flushes the c2s direction's hold buffer (see Pipe.Release).
func (h *HookConn) ReleaseC2S() (int, error) { return h.pipe.Release(DirC2S) }

// ReleaseS2C flushes the s2c direction's hold buffer.
func (h *HookConn) ReleaseS2C() (int, error) { return h.pipe.Release(DirS2C) }

// HoldDepth reports direction dir's hold buffer: current depth and limit,
// in bytes.
func (h *HookConn) HoldDepth(dir Dir) (depth, limit int64) {
	if h == nil || h.pipe == nil || h.pipe.hold[dir] == nil {
		return 0, 0
	}
	return h.pipe.hold[dir].depth()
}

// SetHoldLimits overrides this connection's hold buffer bound (limit) and
// high-water mark (high; 0 keeps the current value). Call from OnOpen,
// before bytes flow. The relay uses the package defaults unless an embedded
// host or test tightens them.
func (h *HookConn) SetHoldLimits(limit, high int64) {
	if h == nil || h.pipe == nil {
		return
	}
	h.pipe.hold[DirC2S].setLimits(limit, high)
	h.pipe.hold[DirS2C].setLimits(limit, high)
}

// writeBypass writes hook-manufactured bytes directly into the relay for
// direction dir, bypassing the hook chain (a hook's own output must not be
// reprocessed). It is serialized with the relay's own writes to the same
// direction.
func (p *Pipe) writeBypass(dir Dir, b []byte, origin string) (int, error) {
	if p == nil {
		return 0, ErrNotReady
	}
	if p.closed.Load() {
		return 0, p.closeErr()
	}
	p.inflight.Add(1)
	if p.closed.Load() {
		p.inflight.Add(-1)
		return 0, p.closeErr()
	}
	defer p.inflight.Add(-1)
	n := len(b)
	full := b // the bytes actually written, before the loop re-bases b
	p.wmu[dir].Lock()
	defer p.wmu[dir].Unlock()
	inner := p.inner[dir]
	if inner == nil {
		return 0, ErrNotReady
	}
	for len(b) > 0 {
		m, err := inner.Write(b)
		b = b[m:]
		if err != nil {
			return 0, err
		}
	}
	p.record(capture.Chunk{Dir: dir, TS: time.Now(), Len: n, Decision: capture.Injected, Origin: origin}, full)
	return n, nil
}
