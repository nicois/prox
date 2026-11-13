package hooks

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nicois/prox/pkg/capture"
)

// testHook is a scriptable hook: each method records calls and returns the
// configured verdict.
type testHook struct {
	name   string
	filter Match
	onOpen Result
	onData func(dir Dir, data []byte) Result
	calls  []string
	closes []string
}

func (h *testHook) Filter() Match { return h.filter }

func (h *testHook) OnOpen(c *Conn, hc *HookConn) Result {
	h.calls = append(h.calls, "open")
	return h.onOpen
}

func (h *testHook) OnData(c *Conn, dir Dir, data []byte) Result {
	h.calls = append(h.calls, "data")
	if h.onData != nil {
		return h.onData(dir, data)
	}
	return Result{}
}

func (h *testHook) OnClose(c *Conn, reason string) {
	h.closes = append(h.closes, reason)
}

func testConn() *Conn {
	return &Conn{ID: "1-1", Kind: "plain_http", Src: "192.0.2.177", SrcPort: 55152, Dst: "198.51.100.72", DPort: 443}
}

func TestPipelineMatchSelection(t *testing.T) {
	p := NewPipeline()
	any := &testHook{name: "any"}
	bySrc := &testHook{name: "src", filter: Match{Src: "192.0.2.177"}}
	byDst := &testHook{name: "dst", filter: Match{Dst: "198.51.100.72"}}
	other := &testHook{name: "other", filter: Match{Src: "192.0.2.1"}}
	byPort := &testHook{name: "port", filter: Match{DPort: 443}}
	for _, h := range []*testHook{any, bySrc, byDst, other, byPort} {
		p.Register(h)
	}

	c := testConn()
	if got := p.Pipe(c); got == nil {
		t.Fatal("Pipe nil for matching connection")
	}
	// Registration order must be preserved.
	want := []string{"any", "src", "dst", "port"}
	hs := p.Pipe(c).hooks
	if len(hs) != 4 {
		t.Fatalf("matched %d hooks, want 4 (the Src-filtered 'other' must not match)", len(hs))
	}
	for i, h := range hs {
		if h.(*testHook).name != want[i] {
			t.Errorf("hook %d = %v, want %s", i, h, want[i])
		}
	}

	// No match -> nil pipe (zero overhead path). A zero Match matches
	// everything, so use a pipeline whose hooks do not select the
	// connection.
	none := NewPipeline()
	none.Register(&testHook{name: "narrow", filter: Match{Src: "192.0.2.1"}})
	if none.Pipe(&Conn{Src: "203.0.113.9", Dst: "1.1.1.1"}) != nil {
		t.Error("Pipe non-nil for a fully unmatched connection")
	}
	if (*Pipeline)(nil).Pipe(c) != nil {
		t.Error("nil Pipeline must return a nil Pipe")
	}
}

func TestDataChainSeesPreviousOutput(t *testing.T) {
	p := NewPipeline()
	h1 := &testHook{name: "h1"}
	h2 := &testHook{name: "h2"}
	p.Register(h1)
	p.Register(h2)

	h1.onData = func(dir Dir, data []byte) Result {
		return Result{Data: append([]byte(nil), data...)}
	}
	seen := []string{}
	h2.onData = func(dir Dir, data []byte) Result {
		seen = append(seen, string(data))
		return Result{Data: []byte("final")}
	}

	pipe := p.Pipe(testConn())
	out, closed := pipe.Data(DirC2S, []byte("hello"))
	if closed {
		t.Fatal("chain closed, want forward")
	}
	if string(out) != "final" {
		t.Errorf("out = %q, want \"final\"", out)
	}
	if len(seen) != 1 || seen[0] != "hello" {
		t.Errorf("h2 saw %v, want [hello] (h1 copied bytes through unchanged)", seen)
	}
}

func TestDataDropAndAllow(t *testing.T) {
	p := NewPipeline()
	dropper := &testHook{name: "drop"}
	dropper.onData = func(dir Dir, data []byte) Result { return Result{Data: []byte{}} }
	p.Register(dropper)
	pipe := p.Pipe(testConn())
	if out, closed := pipe.Data(DirS2C, []byte("secret")); closed || out != nil {
		t.Errorf("dropped chunk: got (out=%v, closed=%v), want (nil, false)", out, closed)
	}

	p2 := NewPipeline()
	p2.Register(&testHook{name: "allow"})
	pipe2 := p2.Pipe(testConn())
	out, closed := pipe2.Data(DirC2S, []byte("plain"))
	if closed || !bytes.Equal(out, []byte("plain")) {
		t.Errorf("allowing chain altered the chunk: (out=%q, closed=%v)", out, closed)
	}
}

func TestCloseVerdictStopsChainAndIsSticky(t *testing.T) {
	p := NewPipeline()
	blocker := &testHook{name: "block", onOpen: Result{Close: true, Reason: "policy"}}
	after := &testHook{name: "after"}
	p.Register(blocker)
	p.Register(after)
	pipe := p.Pipe(testConn())

	if r := pipe.Open(); !r.Close || r.Reason != "policy" {
		t.Fatalf("Open = %+v, want Close with reason policy", r)
	}
	// After a close verdict, Data must stop without consulting hooks.
	if out, closed := pipe.Data(DirC2S, []byte("x")); !closed || out != nil {
		t.Errorf("post-close Data = (out=%v, closed=%v), want (nil, true)", out, closed)
	}
	if len(after.calls) != 0 {
		t.Errorf("hook after the closer was still consulted: %v", after.calls)
	}

	// The close reason is recorded for OnClose and wins over a later reason.
	pipe.Close("client went away")
	if len(blocker.closes) != 1 || blocker.closes[0] != "policy" {
		t.Errorf("OnClose reason = %v, want [policy]", blocker.closes)
	}
	// OnClose is notified exactly once.
	pipe.Close("again")
	if len(blocker.closes) != 1 {
		t.Errorf("OnClose notified %d times, want 1", len(blocker.closes))
	}
}

func TestCloseFnCalledOnce(t *testing.T) {
	p := NewPipeline()
	calls := 0
	h := &testHook{name: "block"}
	h.onData = func(dir Dir, data []byte) Result { return Result{Close: true, Reason: "cut"} }
	p.Register(h)
	pipe := p.Pipe(testConn())
	pipe.SetCloseFn(func() { calls++ })

	out, closed := pipe.Data(DirC2S, []byte("bad"))
	if !closed || out != nil {
		t.Fatalf("Data = (out=%v, closed=%v), want close", out, closed)
	}
	if _, closed := pipe.Data(DirS2C, []byte("more")); !closed {
		t.Error("second direction not reported closed")
	}
	if calls != 1 {
		t.Errorf("close fn called %d times, want 1", calls)
	}
}

func TestWriterForwardsModifiesDropsAndCloses(t *testing.T) {
	p := NewPipeline()
	var mode int
	h := &testHook{name: "mode"}
	h.onData = func(dir Dir, data []byte) Result {
		switch mode {
		case 1:
			return Result{Data: []byte("changed")}
		case 2:
			return Result{Data: []byte{}}
		case 3:
			return Result{Close: true, Reason: "stop"}
		}
		return Result{}
	}
	p.Register(h)
	pipe := p.Pipe(testConn())

	var buf bytes.Buffer
	w := pipe.Writer(DirC2S, &buf)

	mode = 0
	if _, err := w.Write([]byte("abc")); err != nil || buf.String() != "abc" {
		t.Errorf("pass-through write: buf=%q err=%v", buf.String(), err)
	}
	buf.Reset()
	mode = 1
	if _, err := w.Write([]byte("abc")); err != nil || buf.String() != "changed" {
		t.Errorf("modify write: buf=%q err=%v", buf.String(), err)
	}
	buf.Reset()
	mode = 2
	if n, err := w.Write([]byte("secret")); err != nil || n != len("secret") || buf.Len() != 0 {
		t.Errorf("drop write: n=%d buf=%q err=%v, want consumed and empty", n, buf.String(), err)
	}
	// A nil pipe must return the inner writer unchanged.
	var buf2 bytes.Buffer
	if w := (*Pipe)(nil).Writer(DirS2C, &buf2); w != io.Writer(&buf2) {
		t.Error("nil Pipe Writer did not return inner")
	}
}

// shortWriter writes at most `short` bytes on its first call, then all.
type shortWriter struct {
	buf   bytes.Buffer
	short int
}

func (s *shortWriter) Write(p []byte) (int, error) {
	if s.short > 0 && len(p) > s.short {
		p = p[:s.short]
		s.short = 0
	}
	return s.buf.Write(p)
}

func TestWriterSurvivesShortWriteWithResizedChunk(t *testing.T) {
	p := NewPipeline()
	h := &testHook{name: "grow"}
	h.onData = func(dir Dir, data []byte) Result {
		return Result{Data: append(append([]byte(nil), data...), []byte("-extra")...)}
	}
	p.Register(h)
	inner := &shortWriter{short: 4}
	w := p.Pipe(testConn()).Writer(DirC2S, inner)

	n, err := w.Write([]byte("ab"))
	if err != nil || n != 2 {
		t.Fatalf("Write = (%d, %v), want (2, nil): the count must reference p, not the grown chunk", n, err)
	}
	if got := inner.buf.String(); got != "ab-extra" {
		t.Errorf("inner got %q, want the full grown chunk despite the short first write", got)
	}
}

func TestUnregister(t *testing.T) {
	p := NewPipeline()
	h := &testHook{name: "gone", filter: Match{Src: "192.0.2.177"}}
	p.Register(h)
	if p.Pipe(testConn()) == nil {
		t.Fatal("pipe non-nil before unregister")
	}
	p.Unregister(h)
	if p.Pipe(testConn()) != nil {
		t.Error("pipe still non-nil after unregister")
	}
	p.Unregister(h) // unknown hook: no-op, no panic
}

func TestHookConnPushPath(t *testing.T) {
	p := NewPipeline()
	pusher := &testHook{name: "pusher"}
	passive := &testHook{name: "passive"}
	var s2cSeen []string
	passive.onData = func(dir Dir, data []byte) Result {
		if dir == DirS2C {
			s2cSeen = append(s2cSeen, string(data))
		}
		return Result{}
	}
	p.Register(pusher)
	p.Register(passive)

	pipe := p.Pipe(testConn())
	hc := &HookConn{pipe: pipe}
	var c2sBuf, s2cBuf bytes.Buffer
	// Bind c2s only: s2c writes must fail until both directions are bound,
	// which is when the relay's legs exist.
	pipe.Writer(DirC2S, &c2sBuf)
	if _, err := hc.WriteS2C([]byte("early")); !errors.Is(err, ErrNotReady) {
		t.Fatalf("s2c write before both directions bound: err = %v, want ErrNotReady", err)
	}
	s2cW := pipe.Writer(DirS2C, &s2cBuf)
	select {
	case <-hc.Ready():
	default:
		t.Fatal("Ready not closed after both directions were bound")
	}

	// A push made from inside OnData (re-entrancy) must succeed, must not
	// deadlock, and must not be reprocessed by the chain.
	var pushed bool
	pusher.onData = func(dir Dir, data []byte) Result {
		if dir == DirS2C && !pushed {
			pushed = true
			if _, err := hc.WriteS2C([]byte("PUSH")); err != nil {
				t.Errorf("push from OnData: %v", err)
			}
		}
		return Result{}
	}
	if _, err := s2cW.Write([]byte("RELAY")); err != nil {
		t.Fatalf("relay s2c write: %v", err)
	}
	if !pushed {
		t.Fatal("OnData never ran, so the push never happened")
	}
	// Injected and relayed bytes share the same per-direction writer, so
	// the sink sees both, in order.
	if got := s2cBuf.String(); got != "PUSHRELAY" {
		t.Errorf("s2c capture = %q, want PUSH then RELAY", got)
	}
	if len(s2cSeen) != 1 || s2cSeen[0] != "RELAY" {
		t.Errorf("later hook saw s2c = %v, want [RELAY]: injected bytes bypass the chain", s2cSeen)
	}

	// Once the connection ends, writes fail and Done is closed.
	pipe.Close("done")
	if _, err := hc.WriteS2C([]byte("late")); !errors.Is(err, ErrClosed) {
		t.Errorf("write after close: err = %v, want ErrClosed", err)
	}
	select {
	case <-hc.Done():
	default:
		t.Error("Done not closed after Close")
	}
}

func TestDataRecordsDecisions(t *testing.T) {
	p := NewPipeline()
	rec := &testHook{name: "rec"}
	rec.onData = func(dir Dir, data []byte) Result {
		if bytes.Contains(data, []byte("x")) {
			return Result{Data: []byte{}, Reason: "no"}
		}
		return Result{}
	}
	p.Register(rec)
	pipe := p.Pipe(testConn())
	st := capture.NewStream(capture.CloseInfo{ID: "1"}, 0)
	pipe.SetStream(st)

	pipe.Data(DirC2S, []byte("keep"))
	pipe.Data(DirS2C, []byte("x-drop"))
	st.Finish("")
	chunks := st.Chunks()
	if len(chunks) != 2 {
		t.Fatalf("chunks = %+v, want one forwarded and one dropped", chunks)
	}
	if chunks[0].Decision != capture.Forwarded || chunks[0].Len != 4 || chunks[0].Dir != DirC2S {
		t.Errorf("chunks[0] = %+v, want forwarded c2s len 4", chunks[0])
	}
	if chunks[1].Decision != capture.Dropped || chunks[1].Reason != "no" || chunks[1].Dir != DirS2C {
		t.Errorf("chunks[1] = %+v, want dropped s2c reason no", chunks[1])
	}
}

func TestDropShortCircuitsChain(t *testing.T) {
	p := NewPipeline()
	drop := &testHook{name: "drop"}
	drop.onData = func(dir Dir, data []byte) Result {
		return Result{Data: []byte{}, Reason: "gone"}
	}
	after := &testHook{name: "after"}
	p.Register(drop)
	p.Register(after)
	pipe := p.Pipe(testConn())
	if out, closed := pipe.Data(DirC2S, []byte("x")); closed || out != nil {
		t.Fatalf("Data = (out=%v, closed=%v), want dropped", out, closed)
	}
	for _, c := range after.calls {
		if c == "data" {
			t.Error("later hook was consulted after a drop; the chain must terminate for that chunk")
		}
	}
}

func TestHookConnRecordsInjected(t *testing.T) {
	p := NewPipeline()
	p.Register(&testHook{name: "h"})
	pipe := p.Pipe(testConn())
	st := capture.NewStream(capture.CloseInfo{ID: "1"}, 0)
	pipe.SetStream(st)
	// Both directions must be bound before HookConn writes are ready.
	var buf, buf2 bytes.Buffer
	pipe.Writer(DirC2S, &buf)
	pipe.Writer(DirS2C, &buf2)
	hc := &HookConn{pipe: pipe, origin: "pusher"}
	if _, err := hc.WriteC2S([]byte("ping")); err != nil {
		t.Fatalf("WriteC2S: %v", err)
	}
	st.Finish("")
	chunks := st.Chunks()
	if len(chunks) != 1 || chunks[0].Decision != capture.Injected ||
		chunks[0].Origin != "pusher" || chunks[0].Len != 4 || chunks[0].Dir != DirC2S {
		t.Fatalf("chunks = %+v, want one injected ping from pusher", chunks)
	}
}

func TestNotifyTLSReachesObserversOnly(t *testing.T) {
	p := NewPipeline()
	p.Register(&testHook{name: "plain"})
	obs := &tlsObsHook{}
	p.Register(obs)
	pipe := p.Pipe(testConn())
	st := capture.NewStream(capture.CloseInfo{ID: "1"}, 0)
	pipe.SetStream(st)

	pipe.NotifyTLS(TLSResult{Host: "1.2.3.4", Version: 0x0304, Result: "success"})
	if len(obs.got) != 1 || obs.got[0].Result != "success" || obs.got[0].Host != "1.2.3.4" {
		t.Fatalf("observer got %+v, want one success for 1.2.3.4", obs.got)
	}
	if st.Info().TLS == nil || st.Info().TLS.Result != "success" {
		t.Errorf("capture record TLS = %+v, want the outcome attached", st.Info().TLS)
	}
}

type tlsObsHook struct{ got []TLSResult }

func (h *tlsObsHook) Filter() Match                       { return Match{} }
func (h *tlsObsHook) OnOpen(c *Conn, hc *HookConn) Result { return Result{} }
func (h *tlsObsHook) OnData(c *Conn, dir Dir, data []byte) Result {
	return Result{}
}
func (h *tlsObsHook) OnClose(c *Conn, reason string)   {}
func (h *tlsObsHook) OnTLSResult(c *Conn, r TLSResult) { h.got = append(h.got, r) }

type plainStubHook struct{}

func (plainStubHook) Filter() Match                               { return Match{} }
func (plainStubHook) OnOpen(c *Conn, hc *HookConn) Result         { return Result{} }
func (plainStubHook) OnData(c *Conn, dir Dir, data []byte) Result { return Result{} }
func (plainStubHook) OnClose(c *Conn, reason string)              {}

type stubServing struct {
	dec   ServeDecision
	err   error
	calls int
}

func (s *stubServing) Filter() Match                               { return Match{} }
func (s *stubServing) OnOpen(c *Conn, hc *HookConn) Result         { return Result{} }
func (s *stubServing) OnData(c *Conn, dir Dir, data []byte) Result { return Result{} }
func (s *stubServing) OnClose(c *Conn, reason string)              {}
func (s *stubServing) Serve(c *Conn) (ServeDecision, error)        { s.calls++; return s.dec, s.err }

func TestPipeServeDefaultsMirror(t *testing.T) {
	pl := NewPipeline()
	pl.Register(plainStubHook{})
	p := pl.Pipe(&Conn{ID: "x"})
	if dec := p.Serve(); dec.Mode != ServeMirror {
		t.Errorf("Mode = %v, want mirror", dec.Mode)
	}
	if dec := (*Pipe)(nil).Serve(); dec.Mode != ServeMirror {
		t.Errorf("nil pipe Mode = %v, want mirror", dec.Mode)
	}
}

func TestPipeServeFirstServingWins(t *testing.T) {
	first := &stubServing{dec: ServeDecision{Mode: ServeTunnel}}
	second := &stubServing{dec: ServeDecision{Mode: ServeLocal}}
	pl := NewPipeline()
	pl.Register(first)
	pl.Register(second)
	p := pl.Pipe(&Conn{ID: "x"})
	if dec := p.Serve(); dec.Mode != ServeTunnel {
		t.Errorf("Mode = %v, want tunnel (first serving hook decides)", dec.Mode)
	}
	if second.calls != 0 {
		t.Errorf("second serving hook consulted: calls = %d, want 0", second.calls)
	}
}

func TestPipeServeErrorBecomesReject(t *testing.T) {
	pl := NewPipeline()
	pl.Register(&stubServing{err: errors.New("boom")})
	p := pl.Pipe(&Conn{ID: "x"})
	dec := p.Serve()
	if dec.Mode != ServeReject || dec.Reason != "boom" {
		t.Errorf("dec = %+v, want reject/boom", dec)
	}
}

func TestPipeServeLocalWithoutLegBecomesReject(t *testing.T) {
	pl := NewPipeline()
	pl.Register(&stubServing{dec: ServeDecision{Mode: ServeLocal}})
	p := pl.Pipe(&Conn{ID: "x"})
	dec := p.Serve()
	if dec.Mode != ServeReject || !strings.Contains(dec.Reason, "leg") {
		t.Errorf("dec = %+v, want reject naming the missing leg", dec)
	}
}

type holdStub struct {
	hc   *HookConn
	mode string // "hold-c2s", "hold-s2c", or "pass"
	evs  chan Event
}

func (h *holdStub) Filter() Match                       { return Match{} }
func (h *holdStub) OnOpen(c *Conn, hc *HookConn) Result { h.hc = hc; return Result{} }
func (h *holdStub) OnData(c *Conn, dir Dir, data []byte) Result {
	switch h.mode {
	case "hold-c2s":
		if dir == DirC2S {
			return Result{Hold: true, Reason: "wait"}
		}
	case "hold-s2c":
		if dir == DirS2C {
			return Result{Hold: true, Reason: "wait"}
		}
	}
	return Result{}
}
func (h *holdStub) OnClose(c *Conn, reason string) {}

// OnEvent is nil-channel-safe: tests that do not observe events leave evs
// nil, and a blocking send there would deadlock the watermark append.
func (h *holdStub) OnEvent(c *Conn, e Event) {
	if h.evs != nil {
		h.evs <- e
	}
}

func TestHoldReleaseRoundTrip(t *testing.T) {
	h := &holdStub{mode: "hold-c2s"}
	pl := NewPipeline()
	pl.Register(h)
	p := pl.Pipe(&Conn{ID: "x"})
	stream := capture.NewStream(capture.CloseInfo{ID: "x"}, 0)
	p.SetStream(stream)
	var buf bytes.Buffer
	w := p.Writer(DirC2S, &buf)
	p.Open()
	if n, err := w.Write([]byte("abc")); err != nil || n != 3 {
		t.Fatalf("Write = %d, %v; want 3, nil", n, err)
	}
	if buf.Len() != 0 {
		t.Fatalf("held bytes leaked to the writer: %q", buf.String())
	}
	if d, _ := h.hc.HoldDepth(DirC2S); d != 3 {
		t.Fatalf("HoldDepth = %d, want 3", d)
	}
	n, err := h.hc.ReleaseC2S()
	if err != nil || n != 3 {
		t.Fatalf("ReleaseC2S = %d, %v; want 3, nil", n, err)
	}
	if buf.String() != "abc" {
		t.Fatalf("after release buf = %q, want abc", buf.String())
	}
	recs := stream.Chunks()
	if len(recs) != 2 || recs[0].Decision != capture.Held || recs[0].Reason != "wait" ||
		recs[1].Decision != capture.Forwarded || recs[1].Len != 3 {
		t.Fatalf("records = %+v; want Held(wait) then Forwarded(3)", recs)
	}
}

func TestHoldS2CIndependentOfC2S(t *testing.T) {
	// Holding s2c must not stall c2s: the uplink-heavy shape (position R2).
	h := &holdStub{mode: "hold-s2c"}
	pl := NewPipeline()
	pl.Register(h)
	p := pl.Pipe(&Conn{ID: "x"})
	var c2sBuf, s2cBuf bytes.Buffer
	wc := p.Writer(DirC2S, &c2sBuf)
	ws := p.Writer(DirS2C, &s2cBuf)
	p.Open()
	// Hold the s2c buffer full-ish, then write c2s: it must pass.
	if _, err := ws.Write([]byte("hold-me")); err != nil {
		t.Fatalf("s2c Write: %v", err)
	}
	if s2cBuf.Len() != 0 {
		t.Fatalf("s2c bytes not held: %q", s2cBuf.String())
	}
	if n, err := wc.Write([]byte("telemetry")); err != nil || n != 9 {
		t.Fatalf("c2s Write = %d, %v; want 9, nil (c2s must not stall)", n, err)
	}
	if c2sBuf.String() != "telemetry" {
		t.Fatalf("c2s buf = %q, want telemetry", c2sBuf.String())
	}
}

func TestHoldWatermarkEvent(t *testing.T) {
	evs := make(chan Event, 4)
	h := &holdStub{mode: "hold-c2s", evs: evs}
	pl := NewPipeline()
	pl.Register(h)
	p := pl.Pipe(&Conn{ID: "x"})
	var buf bytes.Buffer
	w := p.Writer(DirC2S, &buf)
	p.Open()
	h.hc.SetHoldLimits(16, 8)
	if _, err := w.Write([]byte("1234")); err != nil { // depth 4 < 8
		t.Fatal(err)
	}
	select {
	case ev := <-evs:
		t.Fatalf("early watermark: %+v", ev)
	default:
	}
	if _, err := w.Write([]byte("5678")); err != nil { // depth 8 >= 8
		t.Fatal(err)
	}
	select {
	case ev := <-evs:
		if ev.Kind != HoldWatermark || ev.Dir != DirC2S {
			t.Fatalf("event = %+v; want HoldWatermark on c2s", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no HoldWatermark event at the high-water mark")
	}
}

func TestHoldFullBufferBackpressures(t *testing.T) {
	h := &holdStub{mode: "hold-c2s"}
	pl := NewPipeline()
	pl.Register(h)
	p := pl.Pipe(&Conn{ID: "x"})
	var buf bytes.Buffer
	w := p.Writer(DirC2S, &buf)
	p.Open()
	h.hc.SetHoldLimits(4, 4)
	if _, err := w.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_, _ = w.Write([]byte("x")) // must block: buffer at the limit
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("write completed against a full hold buffer")
	case <-time.After(50 * time.Millisecond):
	}
	if n, err := h.hc.ReleaseC2S(); err != nil || n != 4 {
		t.Fatalf("ReleaseC2S = %d, %v; want 4, nil", n, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("write not unblocked by release")
	}
}

func TestHoldCloseResolvesDropped(t *testing.T) {
	h := &holdStub{mode: "hold-c2s"}
	pl := NewPipeline()
	pl.Register(h)
	p := pl.Pipe(&Conn{ID: "x"})
	stream := capture.NewStream(capture.CloseInfo{ID: "x"}, 0)
	p.SetStream(stream)
	var buf bytes.Buffer
	w := p.Writer(DirC2S, &buf)
	p.Open()
	if _, err := w.Write([]byte("held")); err != nil {
		t.Fatal(err)
	}
	p.Close("")
	recs := stream.Chunks()
	if len(recs) != 2 || recs[0].Decision != capture.Held ||
		recs[1].Decision != capture.Dropped || recs[1].Reason != "close" {
		t.Fatalf("records = %+v; want Held then Dropped(close)", recs)
	}
}

func TestReleaseOnClosedPipeFails(t *testing.T) {
	h := &holdStub{mode: "hold-c2s"}
	pl := NewPipeline()
	pl.Register(h)
	p := pl.Pipe(&Conn{ID: "x"})
	var buf bytes.Buffer
	w := p.Writer(DirC2S, &buf)
	p.Open()
	if _, err := w.Write([]byte("held")); err != nil {
		t.Fatal(err)
	}
	p.Close("done")
	if n, err := h.hc.ReleaseC2S(); err == nil {
		t.Fatalf("ReleaseC2S after close = %d, nil; want close error", n)
	}
}

func TestDoubleReleaseReleasesNothing(t *testing.T) {
	h := &holdStub{mode: "hold-c2s"}
	pl := NewPipeline()
	pl.Register(h)
	p := pl.Pipe(&Conn{ID: "x"})
	var buf bytes.Buffer
	w := p.Writer(DirC2S, &buf)
	p.Open()
	if _, err := w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if n, err := h.hc.ReleaseC2S(); err != nil || n != 3 {
		t.Fatalf("first release = %d, %v; want 3, nil", n, err)
	}
	if n, err := h.hc.ReleaseC2S(); err != nil || n != 0 {
		t.Fatalf("second release = %d, %v; want 0, nil", n, err)
	}
	if buf.String() != "abc" {
		t.Fatalf("buf = %q, want abc", buf.String())
	}
}

// errWriter always fails: exercises Release's write-failure record path.
type errWriter struct{}

func (errWriter) Write(b []byte) (int, error) { return 0, errors.New("inner down") }

func TestReleaseFailingInnerRecordsDropped(t *testing.T) {
	h := &holdStub{mode: "hold-c2s"}
	pl := NewPipeline()
	pl.Register(h)
	p := pl.Pipe(&Conn{ID: "x"})
	stream := capture.NewStream(capture.CloseInfo{ID: "x"}, 0)
	p.SetStream(stream)
	w := p.Writer(DirC2S, errWriter{})
	p.Open()
	if _, err := w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if n, err := h.hc.ReleaseC2S(); err == nil || n != 0 {
		t.Fatalf("ReleaseC2S = %d, %v; want 0, error", n, err)
	}
	recs := stream.Chunks()
	if len(recs) != 2 || recs[0].Decision != capture.Held ||
		recs[1].Decision != capture.Dropped || recs[1].Reason != "release_failed" {
		t.Fatalf("records = %+v; want Held then Dropped(release_failed)", recs)
	}
}

func TestHoldDepthReportsLimit(t *testing.T) {
	h := &holdStub{mode: "pass"}
	pl := NewPipeline()
	pl.Register(h)
	p := pl.Pipe(&Conn{ID: "x"})
	p.Open()
	if _, err := h.hc.ReleaseC2S(); err != nil { // no bytes: (0, nil)
		t.Fatal(err)
	}
	if d, limit := h.hc.HoldDepth(DirC2S); d != 0 || limit != DefaultHoldLimit {
		t.Fatalf("HoldDepth = %d/%d; want 0/%d", d, limit, DefaultHoldLimit)
	}
}

type labelerHook struct{}

func (labelerHook) Filter() Match { return Match{} }
func (labelerHook) OnOpen(c *Conn, hc *HookConn) Result {
	c.SetLabel("class", "uplink-channel-a")
	return Result{}
}
func (labelerHook) OnData(c *Conn, dir Dir, data []byte) Result { return Result{} }
func (labelerHook) OnClose(c *Conn, reason string)              {}

type labelReaderHook struct{ seen map[string]string }

// Pointer receivers: the test registers &labelReaderHook{}, so value
// receivers would write state into the interface copy, not into rd.
func (h *labelReaderHook) Filter() Match                       { return Match{} }
func (h *labelReaderHook) OnOpen(c *Conn, hc *HookConn) Result { return Result{} }
func (h *labelReaderHook) OnData(c *Conn, dir Dir, data []byte) Result {
	h.seen = c.Labels
	return Result{}
}
func (h *labelReaderHook) OnClose(c *Conn, reason string) {}

func TestLabelsInheritedByLaterHooks(t *testing.T) {
	pl := NewPipeline()
	pl.Register(labelerHook{})
	rd := &labelReaderHook{}
	pl.Register(rd)
	p := pl.Pipe(&Conn{ID: "x"})
	p.Open()
	p.Data(DirC2S, []byte("z"))
	if rd.seen == nil || rd.seen["class"] != "uplink-channel-a" {
		t.Errorf("later hook saw labels = %v; want the labeler's label", rd.seen)
	}
}

func TestSetLabelNilConnSafe(t *testing.T) {
	var c *Conn
	c.SetLabel("a", "b") // must not panic
}

func TestHookDropRecordCarriesLength(t *testing.T) {
	// The dropping hook receives a 5-byte chunk (transformed by the
	// earlier hook); the record must carry 5 — not the original 10,
	// not 0.
	rewrite := &testHook{name: "rewrite"}
	rewrite.onData = func(dir Dir, data []byte) Result { return Result{Data: data[:5]} }
	drop := &testHook{name: "drop"}
	drop.onData = func(dir Dir, data []byte) Result { return Result{Data: []byte{}, Reason: "gone"} }
	p := NewPipeline()
	p.Register(rewrite)
	p.Register(drop)
	pipe := p.Pipe(testConn())
	st := capture.NewStream(capture.CloseInfo{ID: "t1"}, 0)
	pipe.SetStream(st)

	if out, closed := pipe.Data(DirC2S, []byte("0123456789")); closed || out != nil {
		t.Fatalf("dropped chunk: (out=%v, closed=%v), want (nil, false)", out, closed)
	}
	cs := st.Chunks()
	if len(cs) != 1 {
		t.Fatalf("want 1 record, got %d: %+v", len(cs), cs)
	}
	if cs[0].Decision != capture.Dropped || cs[0].Reason != "gone" {
		t.Fatalf("record = %+v, want Dropped/gone", cs[0])
	}
	if cs[0].Len != 5 {
		t.Fatalf("Len = %d, want 5 (chunk as received by the dropping hook)", cs[0].Len)
	}
}

// G2: with byte capture enabled (Registry.EnableBytes), a record's
// Payload is a copy of the chunk's bytes at the record site — the
// forwarded (final) bytes on Forward, the chunk as the dropping hook
// received it on drop — and mutating the input slice after the call
// does not change the recorded payload. Without EnableBytes, every
// record's Payload is nil.
func TestRecordPayloadCopied(t *testing.T) {
	r := capture.NewRegistry()
	r.EnableBytes()

	// Forward: payload = the forwarded (final) bytes.
	p := NewPipeline()
	h := &testHook{name: "h"}
	// Return a sub-slice of the input so an aliasing record (no copy)
	// would be exposed by the post-Data mutation of in below.
	h.onData = func(dir Dir, data []byte) Result { return Result{Data: data[:2]} }
	p.Register(h)
	pipe := p.Pipe(testConn())
	st := r.Open(capture.CloseInfo{ID: "b4"})
	pipe.SetStream(st)
	in := []byte("original")
	pipe.Data(DirC2S, in)
	for i := range in {
		in[i] = 'X'
	}
	cs := st.Chunks()
	if len(cs) != 1 || cs[0].Decision != capture.Forwarded {
		t.Fatalf("records: %+v", cs)
	}
	if !bytes.Equal(cs[0].Payload, []byte("or")) {
		t.Fatalf("Payload = %q, want %q (2-byte sub-slice of the input)", cs[0].Payload, "or")
	}

	// Hook drop: payload = the chunk as the dropping hook received it
	// (post earlier-hook transform) — same bytes as the Len=5 case.
	p2 := NewPipeline()
	rewrite := &testHook{name: "rewrite"}
	rewrite.onData = func(dir Dir, data []byte) Result { return Result{Data: data[:5]} }
	drop := &testHook{name: "drop"}
	drop.onData = func(dir Dir, data []byte) Result { return Result{Data: []byte{}, Reason: "gone"} }
	p2.Register(rewrite)
	p2.Register(drop)
	pipe2 := p2.Pipe(testConn())
	st2 := r.Open(capture.CloseInfo{ID: "b5"})
	pipe2.SetStream(st2)
	if out, closed := pipe2.Data(DirC2S, []byte("0123456789")); closed || out != nil {
		t.Fatalf("dropped chunk: (out=%v, closed=%v), want (nil, false)", out, closed)
	}
	cs2 := st2.Chunks()
	if len(cs2) != 1 || cs2[0].Decision != capture.Dropped {
		t.Fatalf("records: %+v", cs2)
	}
	if !bytes.Equal(cs2[0].Payload, []byte("01234")) {
		t.Fatalf("Payload = %q, want %q", cs2[0].Payload, "01234")
	}

	// Default off: without EnableBytes, every record's Payload is nil.
	st3 := capture.NewStream(capture.CloseInfo{ID: "b6"}, 0)
	pipe.SetStream(st3)
	pipe.Data(DirC2S, []byte("original"))
	cs3 := st3.Chunks()
	if len(cs3) != 1 || cs3[0].Payload != nil {
		t.Fatalf("default-off records: %+v", cs3)
	}
}
