package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nicois/prox/pkg/capture"
	"github.com/nicois/prox/pkg/hooks"
	"github.com/nicois/prox/pkg/sink"
	"github.com/nicois/prox/pkg/sniff"
	"github.com/nicois/prox/pkg/store"
)

// LeafMinter mints the forged leaf for a (host, dst) pair.
type LeafMinter interface {
	Leaf(host, dst string, now time.Time) (*tls.Certificate, error)
}

type Ladder struct {
	Sink   func(dataRoot, id string, maxBytes int64) (*sink.Conn, error)
	Store  *store.Store
	Leaves LeafMinter
	// LeafSelector, when non-nil, is consulted before the leaf minter for
	// each TLS flow: it may supply the leaf to present, given the
	// client's offer (host = SNI or the destination IP). (cert, nil)
	// serves cert; (nil, nil) falls through to the minter; (nil, err)
	// fails the flow as mint_failed — the selector is authoritative when
	// it speaks. The minter stays the default; the consumer's CA and leaf
	// stores stay the consumer's.
	LeafSelector     func(host, dst string) (*tls.Certificate, error)
	DataRoot         string
	MaxPeek          int
	MaxBytes         int64
	HandshakeTimeout time.Duration
	// UpstreamRoots verifies the upstream server cert; nil = system roots.
	UpstreamRoots *x509.CertPool
	// Hooks, when non-nil, routes matched connections' byte streams
	// through the registered hooks before forwarding (pkg/hooks).
	Hooks *hooks.Pipeline
	// Capture, when non-nil, records every chunk decision of every flow
	// into a per-connection capture.Stream (pkg/capture).
	Capture *capture.Registry
	// IsolationReadOnly is read-only isolation: c2s passes through to the
	// real upstream exactly as on a mirrored flow, but s2c bytes are
	// captured and never written to the client. Prox sets it from
	// cfg.Isolation.
	IsolationReadOnly bool
	// S2cMaxPacket, when > 0, drops s2c chunks larger than it instead of
	// forwarding them to the client (they are still captured; each drop
	// logs an s2c_drop journal line and meta.jsonl event). The chunk unit
	// is one upstream read delivery (one TLS record on a MITM leg). Zero
	// disables. Prox sets it only for isolation "off".
	S2cMaxPacket int
	// Dial, when non-nil, dials the upstream instead of the default TCP
	// dial. It exists for tests and scripted harnesses: returning an
	// in-memory conn (e.g. a net.Pipe end driven by a test goroutine)
	// gives byte-exact control of upstream transmissions and keeps the
	// whole relay inside a testing/synctest group, where timers and
	// context deadlines advance on a simulated clock at zero wall-clock
	// cost.
	Dial func(addr net.Addr) (net.Conn, error)
	// Draining is set by Prox.Shutdown while the drain runs; connections
	// that end while it is set fire the drain event.
	Draining atomic.Bool
	// TunnelFallback, when true, serves patched (ip, host) pairs with the
	// legacy pass-through tunnel (both TLS legs relayed verbatim). When
	// false (the default), a patched pair's connection is dropped and the
	// stored rejection reason is logged (design §5.2). Prox sets it from
	// cfg.MITM.TunnelFallback.
	TunnelFallback bool
}

var connSeq atomic.Uint64

// Serve peeks the first bytes of conn, classifies them, and dispatches to
// the plain, TLS (MITM or pass-through) or raw path. It always writes a
// conn_open and a conn_close event to the sink.
func (l *Ladder) Serve(conn net.Conn, origDst net.Addr) error {
	if l.Sink == nil {
		return errors.New("proxy: Sink not configured")
	}
	defer conn.Close()
	// id = <unix-ms>-<seq>: unique across restarts (the per-process counter
	// alone would collide when the proxy is restarted within the same
	// millisecond window) and sortable by start time.
	id := fmt.Sprintf("%d-%d", time.Now().UnixMilli(), connSeq.Add(1))
	maxPeek := l.MaxPeek
	if maxPeek <= 0 {
		maxPeek = sniff.MaxPeek
	}
	buf := make([]byte, maxPeek)
	// One read: "peek up to MaxPeek". A full ReadFull would hang on any
	// client that sends less and then waits for the response.
	n, err := conn.Read(buf)
	if err != nil {
		slog.Debug("conn_drop", "client", conn.RemoteAddr().String(), "dst", origDst.String(), "err", err)
		return err
	}
	buf = buf[:n]
	s, err := sniff.Sniff(buf)
	if err != nil {
		slog.Debug("conn_drop", "client", conn.RemoteAddr().String(), "dst", origDst.String(), "err", err)
		return err
	}
	scn, err := l.Sink(l.DataRoot, id, l.MaxBytes)
	if err != nil {
		return err
	}
	defer scn.Close()
	if err := scn.WriteJSON(evt("conn_open", "id", id, "kind", s.Kind.String(), "client", conn.RemoteAddr().String(), "dst", origDst.String(), "sni", s.SNI)); err != nil {
		return err
	}
	slog.Debug("conn_open", "id", id, "kind", s.Kind.String(), "client", conn.RemoteAddr().String(), "dst", origDst.String(), "sni", s.SNI)
	var serveErr error
	switch s.Kind {
	case sniff.KindPlainHTTP:
		serveErr = l.servePlain(conn, buf, scn, origDst, id)
	case sniff.KindTLS:
		serveErr = l.serveTLS(conn, buf, scn, s, origDst, id)
	default:
		serveErr = l.serveRaw(conn, buf, scn, origDst, id, s.Kind.String(), s.SNI)
	}
	slog.Debug("conn_close", "id", id, "err", errString(serveErr))
	scn.WriteJSON(evt("conn_close", "id", id, "err", errString(serveErr)))
	return serveErr
}

// serveRaw tunnels the bytes verbatim to origDst, prefix included.
func (l *Ladder) serveRaw(conn net.Conn, prefix []byte, scn *sink.Conn, origDst net.Addr, id, kind, sni string) error {
	info := connInfo(id, kind, sni, conn.RemoteAddr(), origDst)
	pipe, cs, dec, err := l.hookGate(info, scn, id)
	if err != nil {
		return err
	}
	return l.serveRawGated(conn, prefix, scn, origDst, id, kind, sni, pipe, cs, dec)
}

// serveRawGated is the raw relay body with the hook gate already applied
// (pipe/cs/dec from a prior hookGate). The serveTLS tunnel path enters here
// without re-running the gate: a flow's hooks must observe it exactly once.
// ServeLocal serves with no upstream: the consumer's leg is adapted to the
// relay's conn plumbing.
func (l *Ladder) serveRawGated(conn net.Conn, prefix []byte, scn *sink.Conn, origDst net.Addr, id, kind, sni string,
	pipe *hooks.Pipe, cs *capture.Stream, dec hooks.ServeDecision) error {
	reason := ""
	defer func() {
		if l.Draining.Load() {
			pipe.Emit(hooks.Event{Kind: hooks.Drain})
		}
		if pipe != nil {
			pipe.Close(reason)
		} else if cs != nil {
			cs.Finish(reason)
		}
	}()
	var up net.Conn
	if dec.Mode == hooks.ServeLocal {
		up = localConn{dec.Local}
		slog.Debug("relay", "id", id, "client", conn.RemoteAddr().String(), "kind", "local", "dst", origDst.String())
	} else {
		var err error
		up, err = l.dialUpstream(origDst)
		if err != nil {
			slog.Warn("relay", "id", id, "client", conn.RemoteAddr().String(), "kind", kind, "dst", origDst.String(), "err", err)
			pipe.Emit(hooks.Event{Kind: hooks.UpstreamConnectFailed, Detail: errString(err)})
			reason = errString(err)
			return err
		}
		slog.Debug("relay", "id", id, "client", conn.RemoteAddr().String(), "kind", kind, "dst", origDst.String())
	}
	defer up.Close()
	pipe.SetCloseFn(func() { up.Close(); conn.Close() })
	c2s := &rangeTee{fn: scn.WriteC2S}
	s2c := newS2cTee(scn, nil)
	ea, eb := l.copyTee(io.MultiReader(bytes.NewReader(prefix), conn), conn, up,
		pipe.Writer(hooks.DirC2S, io.MultiWriter(up, c2s)),
		l.s2cWriter(pipe, conn, s2c, scn, cs, id))
	serveErr := ea
	fireRelayEndEvents(pipe, ea, eb)
	pipe.Seal()
	scn.WriteJSON(bytesRange("bytes_c2s", c2s))
	scn.WriteJSON(bytesRange("bytes_s2c", s2c))
	reason = errString(serveErr)
	return serveErr
}

// s2cLimit, when max > 0, drops s2c chunks larger than it instead of
// forwarding them: a chunk with len > max is dropped whole (never partial),
// a chunk within the limit passes byte-exact. Dropped chunks reach onDrop
// (the caller has already teed them into the capture) and are reported as
// written, so the copy loop never sees an error for them. Zero max
// forwards everything. pos tracks the bytes observed so far in this
// direction; the cap and the capture tee sit inside the same MultiWriter
// and hook drops skip both, so pos is identical to the tee's recorded
// offsets and each onDrop range is exact within s2c.bin. A failed forward
// write (the client gone) advances pos but ends the flow, so no later drop
// event can carry a stale range.
type s2cLimit struct {
	inner  io.Writer
	max    int
	pos    int64
	onDrop func(start, end int64, b []byte)
}

func (w *s2cLimit) Write(b []byte) (int, error) {
	start := w.pos
	w.pos += int64(len(b))
	if len(b) > w.max {
		w.onDrop(start, start+int64(len(b)), b)
		return len(b), nil
	}
	return w.inner.Write(b)
}

// s2cWriter builds the hooked s2c writer. In read-only isolation the
// capture tee is the only sink for s2c bytes — the client is never
// written — so the relay keeps reading (and capturing) the upstream while
// the client stays silent. Otherwise the client leg and the capture tee
// are the sinks; when S2cMaxPacket is set the client leg passes the
// s2cLimit cap first: chunks larger than it are dropped (each drop logs an
// s2c_drop journal line and meta.jsonl event, records a Dropped chunk with
// reason s2c_max_packet on the flow's capture stream when one is wired,
// and marks the pipe so a Release of held bytes into this writer records
// no Forwarded for bytes the cap consumed) while the capture still gets
// every byte. The cap sits after the hook chain (hooks see all s2c) and
// after the capture tee; a hook that drops a chunk takes precedence and
// the cap is never consulted for it.
func (l *Ladder) s2cWriter(pipe *hooks.Pipe, toClient io.Writer, s2c *rangeTee, scn *sink.Conn, cs *capture.Stream, id string) io.Writer {
	if l.IsolationReadOnly {
		return pipe.Writer(hooks.DirS2C, s2c)
	}
	if l.S2cMaxPacket > 0 {
		toClient = &s2cLimit{inner: toClient, max: l.S2cMaxPacket, onDrop: func(start, end int64, b []byte) {
			size := len(b)
			slog.Info("s2c_drop", "id", id, "size", size, "limit", l.S2cMaxPacket, "start", start, "end", end)
			scn.WriteJSON(evt("s2c_drop", "id", id, "size", size, "limit", l.S2cMaxPacket, "start", start, "end", end))
			if cs != nil {
				c := capture.Chunk{Dir: hooks.DirS2C, TS: time.Now(),
					Len: size, Decision: capture.Dropped, Reason: "s2c_max_packet"}
				if cs.BytesEnabled() {
					c.Payload = append([]byte(nil), b...)
				}
				cs.Record(c)
			}
			pipe.MarkDrop(hooks.DirS2C)
		}}
	}
	return pipe.Writer(hooks.DirS2C, io.MultiWriter(toClient, s2c))
}

// copyTee shuttles client<->up through the given per-direction writers and
// returns the c2s and s2c leg end errors (nil = that leg ended cleanly on
// the peer's EOF). While draining, a c2s end that errored (the client leg
// was force-closed) also fully closes the upstream: the c2s half-close
// alone cannot unblock a silent upstream parked in the s2c read, and the
// conn must settle within the Shutdown budget.
func (l *Ladder) copyTee(client io.Reader, conn net.Conn, up net.Conn, c2sW, s2cW io.Writer) (error, error) {
	errC2S := make(chan error, 1)
	errS2C := make(chan error, 1)
	go func() {
		_, err := io.Copy(c2sW, client)
		if hc, ok := up.(interface{ CloseWrite() error }); ok {
			hc.CloseWrite()
		}
		errC2S <- err
	}()
	go func() {
		_, err := io.Copy(s2cW, up)
		// The upstream stopped sending: half-close toward the client so
		// the c2s copy terminates once the client is done.
		if hc, ok := conn.(interface{ CloseWrite() error }); ok {
			hc.CloseWrite()
		}
		errS2C <- err
	}()
	ea := <-errC2S
	if ea != nil && l.Draining.Load() {
		// A drain force-closed the client leg; close the upstream in full
		// so a silent upstream parked in the s2c read unblocks and the
		// flow settles within the Shutdown budget.
		_ = up.Close()
	}
	eb := <-errS2C
	// A client read that ends with EOF means the client went away; any
	// s2c write error at that point is a consequence of it (broken pipe,
	// reset) rather than a failure of the connection itself — the call
	// sites keep that "ea wins" policy for the serve error.
	return ea, eb
}

// fireRelayEndEvents delivers the per-leg end events: each leg that ended
// fires its event (both legs end, both fire); a leg whose end error is a
// TLS alert fires tls_alert for that leg instead.
func fireRelayEndEvents(pipe *hooks.Pipe, ea, eb error) {
	if pipe == nil {
		return
	}
	if isTLSErr(ea) {
		pipe.Emit(hooks.Event{Kind: hooks.TLSAlert, Dir: hooks.DirC2S, Detail: errString(ea)})
	} else {
		pipe.Emit(hooks.Event{Kind: hooks.ClientClose, Dir: hooks.DirC2S, Detail: errString(ea)})
	}
	if isTLSErr(eb) {
		pipe.Emit(hooks.Event{Kind: hooks.TLSAlert, Dir: hooks.DirS2C, Detail: errString(eb)})
	} else {
		pipe.Emit(hooks.Event{Kind: hooks.UpstreamClose, Dir: hooks.DirS2C, Detail: errString(eb)})
	}
}

// isTLSErr reports whether err is a TLS alert or handshake failure (as
// opposed to a transport end).
func isTLSErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "certificate required") ||
		strings.Contains(s, "client didn't provide a certificate") ||
		strings.HasPrefix(s, "tls: ")
}

// rangeTee accumulates the [start,end) byte range of what it tees into the
// sink and may capture the first line for http_* events. Writes may come
// from the relay's copy goroutine and from hook-manufactured bytes in the
// same direction, so state updates are locked; Range is read after the
// pipe is sealed. onRange, when set, is called once per successful write
// with that write's [start,end) range (from fn), after the lock is
// released — never with the lock held.
type rangeTee struct {
	mu      sync.Mutex // guards start, end, have, line state
	fn      func([]byte) (int64, int64, error)
	onRange func(st, en int64)
	start   int64
	end     int64
	have    bool
	line    *string
	lineBuf []byte
	lineHit bool
}

func (r *rangeTee) Write(b []byte) (int, error) {
	st, en, err := r.fn(b)
	if err != nil {
		return 0, err
	}
	r.mu.Lock()
	if !r.have {
		r.start = st
		r.have = true
	}
	r.end = en
	if r.line != nil && !r.lineHit {
		if len(r.lineBuf) < 8192 {
			r.lineBuf = append(r.lineBuf, b...)
			if i := bytes.IndexByte(r.lineBuf, '\n'); i >= 0 {
				*r.line = strings.TrimRight(string(r.lineBuf[:i]), "\r")
				r.lineHit = true
				r.lineBuf = nil
			}
		} else {
			// Line longer than 8 KiB: stop capturing it.
			r.lineHit = true
			r.lineBuf = nil
		}
	}
	r.mu.Unlock()
	if r.onRange != nil && en > st {
		r.onRange(st, en)
	}
	return len(b), nil
}

// newS2cTee builds the s2c rangeTee with per-write emission: every write
// to s2c.bin journals a bytes_s2c event for that write's [start,end)
// range (cumulative, in write order); the per-flow close summary remains
// the final bytes_s2c event.
func newS2cTee(scn *sink.Conn, line *string) *rangeTee {
	return &rangeTee{
		fn:   scn.WriteS2C,
		line: line,
		onRange: func(st, en int64) {
			scn.WriteJSON(evt("bytes_s2c", "start", st, "end", en))
		},
	}
}

// Range returns the [start,end) byte range captured so far. Safe to call
// once the pipe is sealed (no further writers).
func (r *rangeTee) Range() (int64, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.start, r.end
}

// connInfo describes a connection to hooks: client address, original
// destination, and the sniffed kind and SNI.
func connInfo(id, kind, sni string, client, dst net.Addr) *hooks.Conn {
	c := &hooks.Conn{ID: id, Kind: kind, SNI: sni}
	if ta, ok := client.(*net.TCPAddr); ok {
		c.Src, c.SrcPort = ta.IP.String(), ta.Port
	} else {
		c.Src = client.String()
	}
	if ta, ok := dst.(*net.TCPAddr); ok {
		c.Dst, c.DPort = ta.IP.String(), ta.Port
	} else {
		c.Dst = dst.String()
	}
	return c
}

// attachIsolationLabel marks a read-only-isolation flow in its capture
// record (without this, its record is byte-indistinguishable from a
// mirrored one).
func (l *Ladder) attachIsolationLabel(cs *capture.Stream, info *hooks.Conn) {
	if !l.IsolationReadOnly || cs == nil {
		return
	}
	info.SetLabel("isolation", "readonly")
	cs.SetLabels(info.Labels)
}

// hookGate resolves the per-connection hook pipe and capture stream, runs
// the OnOpen and serve-decision passes, and applies the first refusal: a
// hook Close verdict or a ServeReject decision closes the flow and is
// returned as an error before any upstream work. The pipe is nil when no
// hook matches (its methods are nil-safe); the stream is nil when no
// capture registry is configured.
func (l *Ladder) hookGate(info *hooks.Conn, scn *sink.Conn, id string) (*hooks.Pipe, *capture.Stream, hooks.ServeDecision, error) {
	cs := l.captureStream(info)
	pipe := l.Hooks.Pipe(info)
	if pipe != nil {
		pipe.SetStream(cs)
	}
	dec := hooks.ServeDecision{Mode: hooks.ServeMirror}
	if pipe == nil {
		l.attachIsolationLabel(cs, info)
		// A standalone read-only flow has no serving hook, so its serve
		// mode is not recorded elsewhere; record it as mirror (what it is)
		// so the record carries a mode, not just the label.
		if l.IsolationReadOnly && cs != nil {
			cs.SetServeMode(dec.Mode.String())
		}
		return nil, cs, dec, nil
	}
	if r := pipe.Open(); r.Close {
		pipe.Close(r.Reason)
		slog.Warn("hook", "id", id, "result", "blocked", "reason", r.Reason)
		scn.WriteJSON(evt("record_summary", "dst", info.Dst, "reason", "hook", "detail", r.Reason))
		return nil, nil, dec, fmt.Errorf("prox: hook close: %s", r.Reason)
	}
	dec = pipe.Serve()
	if cs != nil {
		cs.SetServeMode(dec.Mode.String())
		if info.Labels != nil {
			cs.SetLabels(info.Labels)
		}
		l.attachIsolationLabel(cs, info)
	}
	if dec.Mode == hooks.ServeReject {
		pipe.Close(dec.Reason)
		slog.Warn("hook", "id", id, "result", "rejected", "reason", dec.Reason)
		scn.WriteJSON(evt("record_summary", "dst", info.Dst, "reason", "rejected", "detail", dec.Reason))
		return nil, nil, dec, fmt.Errorf("prox: rejected: %s", dec.Reason)
	}
	return pipe, cs, dec, nil
}

// captureStream opens the per-connection capture record, or nil when no
// capture registry is configured.
func (l *Ladder) captureStream(info *hooks.Conn) *capture.Stream {
	if l.Capture == nil {
		return nil
	}
	return l.Capture.Open(capture.CloseInfo{
		ID:     info.ID,
		Kind:   info.Kind,
		SNI:    info.SNI,
		Client: net.JoinHostPort(info.Src, strconv.Itoa(info.SrcPort)),
		Dst:    net.JoinHostPort(info.Dst, strconv.Itoa(info.DPort)),
	})
}

func (l *Ladder) dialUpstream(addr net.Addr) (net.Conn, error) {
	if l.Dial != nil {
		return l.Dial(addr)
	}
	target := addr.String()
	if ta, ok := addr.(*net.TCPAddr); ok {
		target = net.JoinHostPort(ta.IP.String(), strconv.Itoa(ta.Port))
	}
	return net.DialTimeout("tcp", target, l.handshakeTimeout())
}

func (l *Ladder) handshakeTimeout() time.Duration {
	if l.HandshakeTimeout > 0 {
		return l.HandshakeTimeout
	}
	return 60 * time.Second
}

func evt(typ string, kv ...any) map[string]any {
	m := map[string]any{"type": typ, "ts": time.Now().UnixMilli()}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}

func bytesRange(typ string, r *rangeTee) map[string]any {
	st, en := r.Range()
	return evt(typ, "start", st, "end", en)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
