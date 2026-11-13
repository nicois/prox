package proxy

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nicois/prox/pkg/capture"
	"github.com/nicois/prox/pkg/chanpipe"
	"github.com/nicois/prox/pkg/hooks"
)

// hooky is a scriptable hooks.Hook for end-to-end ladder tests.
type hooky struct {
	filter hooks.Match
	mut    func(dir hooks.Dir, b []byte) hooks.Result
	openR  hooks.Result
	// push, if non-nil, is written to the client leg once the relay is
	// ready (exercises the HookConn push path).
	push []byte
	// hc is the HookConn this hook received in OnOpen (lets a scriptable
	// OnData release held bytes).
	hc *hooks.HookConn

	mu       sync.Mutex
	opened   int
	closed   []string
	dataSeen map[hooks.Dir]int
}

func (h *hooky) Filter() hooks.Match { return h.filter }

func (h *hooky) OnOpen(c *hooks.Conn, hc *hooks.HookConn) hooks.Result {
	h.mu.Lock()
	h.opened++
	h.mu.Unlock()
	h.hc = hc
	if h.push != nil {
		msg := h.push
		go func() {
			<-hc.Ready()
			hc.WriteS2C(msg)
			<-hc.Done()
		}()
	}
	return h.openR
}

func (h *hooky) OnData(c *hooks.Conn, dir hooks.Dir, data []byte) hooks.Result {
	h.mu.Lock()
	h.dataSeen[dir] += len(data)
	h.mu.Unlock()
	if h.mut != nil {
		return h.mut(dir, data)
	}
	return hooks.Result{}
}

func (h *hooky) OnClose(c *hooks.Conn, reason string) {
	h.mu.Lock()
	h.closed = append(h.closed, reason)
	h.mu.Unlock()
}

func (h *hooky) opens() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.opened
}

func (h *hooky) closes() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.closed...)
}

func (h *hooky) seen(d hooks.Dir) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.dataSeen[d]
}

// newEchoUpstream starts a loopback echo server; it returns the listener
// and a counter of accepted connections.
func newEchoUpstream(t *testing.T) (net.Listener, *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&conns, 1)
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln, &conns
}

// readCapture returns the first capture file named file (c2s.bin / s2c.bin)
// under the day dir.
func readCapture(t *testing.T, dataRoot, file string) string {
	t.Helper()
	// Walk all day dirs: under synctest the stream's day stamp is the
	// simulated date, not today.
	days, err := os.ReadDir(filepath.Join(dataRoot, "conns"))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range days {
		if !d.IsDir() {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(dataRoot, "conns", d.Name()))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if data, err := os.ReadFile(filepath.Join(dataRoot, "conns", d.Name(), e.Name(), file)); err == nil {
				return string(data)
			}
		}
	}
	t.Fatalf("no %s capture under %s", file, dataRoot)
	return ""
}

func TestLadderHookAltersBytes(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	up, _ := newEchoUpstream(t)

	h := &hooky{dataSeen: map[hooks.Dir]int{}}
	h.mut = func(d hooks.Dir, b []byte) hooks.Result {
		if d != hooks.DirC2S {
			return hooks.Result{}
		}
		return hooks.Result{Data: bytes.ReplaceAll(b, []byte("Host: x"), []byte("Host: changed"))}
	}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(h)

	const req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	const want = "GET / HTTP/1.1\r\nHost: changed\r\n\r\n"
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer clientConn.Close()
		if _, err := clientConn.Write([]byte(req)); err != nil {
			return
		}
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(clientConn, buf); err != nil {
			return
		}
		if string(buf) != want {
			t.Errorf("client received %q, want the hook-modified request %q", buf, want)
		}
	}()
	if err := l.Serve(serverConn, up.Addr()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	<-done
	// The capture records what went on the wire: the modified bytes.
	if got := readCapture(t, dir, "c2s.bin"); !strings.Contains(got, "Host: changed") {
		t.Errorf("c2s capture = %q, want the modified bytes", got)
	}
	if got := h.closes(); len(got) != 1 {
		t.Errorf("OnClose notifications = %v, want exactly one", got)
	}
}

func TestLadderHookBlocksAtOpen(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	up, conns := newEchoUpstream(t)

	h := &hooky{openR: hooks.Result{Close: true, Reason: "policy"}, dataSeen: map[hooks.Dir]int{}}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(h)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	go func() {
		clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	}()
	err := l.Serve(serverConn, up.Addr())
	if err == nil || !strings.Contains(err.Error(), "hook close: policy") {
		t.Fatalf("Serve err = %v, want hook close: policy", err)
	}
	if n := atomic.LoadInt32(conns); n != 0 {
		t.Errorf("upstream dialed %d times, want 0 (a block must happen before the dial)", n)
	}
	if got := h.closes(); len(got) != 1 || got[0] != "policy" {
		t.Errorf("OnClose = %v, want [policy]", got)
	}
	meta, _ := readAllMeta(t, dir)
	if !strings.Contains(meta, `"reason":"hook"`) || !strings.Contains(meta, `"detail":"policy"`) {
		t.Errorf("meta missing the hook record_summary: %s", meta)
	}
	if !strings.Contains(meta, "hook close: policy") {
		t.Errorf("meta conn_close missing the hook error: %s", meta)
	}
}

func TestLadderHookClosesMidStream(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)

	// Recording upstream: capture everything it receives.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var got []byte
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				b, _ := io.ReadAll(c)
				c.Close()
				mu.Lock()
				got = append(got, b...)
				mu.Unlock()
			}(c)
		}
	}()

	h := &hooky{dataSeen: map[hooks.Dir]int{}}
	h.mut = func(d hooks.Dir, b []byte) hooks.Result {
		if bytes.Contains(b, []byte("EVIL")) {
			return hooks.Result{Close: true, Reason: "cut"}
		}
		return hooks.Result{}
	}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(h)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	go func() {
		clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: EVIL\r\n\r\n"))
	}()
	err = l.Serve(serverConn, ln.Addr())
	if err == nil || !strings.Contains(err.Error(), "hook close: cut") {
		t.Fatalf("Serve err = %v, want hook close: cut", err)
	}
	mu.Lock()
	upstreamGot := string(got)
	mu.Unlock()
	if upstreamGot != "" {
		t.Errorf("upstream received %q, want nothing (the bad chunk must be dropped)", upstreamGot)
	}
	if readCapture(t, dir, "c2s.bin") != "" {
		t.Error("c2s capture must be empty: no bytes were forwarded")
	}
	if closes := h.closes(); len(closes) != 1 || closes[0] != "cut" {
		t.Errorf("OnClose = %v, want [cut]", closes)
	}
}

func TestLadderHookFilterMismatch(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	up, _ := newEchoUpstream(t)

	h := &hooky{filter: hooks.Match{Src: "203.0.113.9"}, dataSeen: map[hooks.Dir]int{}}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(h)

	const req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer clientConn.Close()
		if _, err := clientConn.Write([]byte(req)); err != nil {
			return
		}
		buf := make([]byte, len(req))
		if _, err := io.ReadFull(clientConn, buf); err != nil {
			return
		}
		if string(buf) != req {
			t.Errorf("client received %q, want the request verbatim", buf)
		}
	}()
	if err := l.Serve(serverConn, up.Addr()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	<-done
	if n := h.opens(); n != 0 {
		t.Errorf("hook consulted %d times, want 0 (filter does not match)", n)
	}
}

func TestLadderHookManufacturesServerMessages(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)

	// A silent upstream: it records what it receives but sends nothing,
	// so anything the client reads must have been manufactured.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var got []byte
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				b, _ := io.ReadAll(c)
				c.Close()
				mu.Lock()
				got = append(got, b...)
				mu.Unlock()
			}(c)
		}
	}()

	const fakeMsg = "FAKE-MSG-1"
	hook := &hooky{dataSeen: map[hooks.Dir]int{}, push: []byte(fakeMsg)}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(hook)

	const req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer clientConn.Close()
		if _, err := clientConn.Write([]byte(req)); err != nil {
			return
		}
		buf := make([]byte, len(fakeMsg))
		if _, err := io.ReadFull(clientConn, buf); err != nil {
			return
		}
		if string(buf) != fakeMsg {
			t.Errorf("client received %q, want the manufactured %q (the real upstream sent nothing)", buf, fakeMsg)
		}
	}()
	if err := l.Serve(serverConn, ln.Addr()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	<-done
	mu.Lock()
	upstreamGot := string(got)
	mu.Unlock()
	if !strings.Contains(upstreamGot, req) {
		t.Errorf("upstream received %q, want the client request (c2s relay must be untouched)", upstreamGot)
	}
	if n := hook.seen(hooks.DirS2C); n != 0 {
		t.Errorf("hook chain saw %d s2c bytes, want 0: manufactured bytes bypass the chain and the upstream sent none", n)
	}
	if cap := readCapture(t, dir, "s2c.bin"); !strings.Contains(cap, fakeMsg) {
		t.Errorf("s2c capture = %q, want the manufactured message (injected bytes are captured like relayed bytes)", cap)
	}
	if closes := hook.closes(); len(closes) != 1 {
		t.Errorf("OnClose notifications = %v, want exactly one", closes)
	}
}

// chunkRec records the exact chunks OnData receives, per direction.
type chunkRec struct {
	mu     sync.Mutex
	chunks map[hooks.Dir][][]byte
}

func (c *chunkRec) Filter() hooks.Match { return hooks.Match{} }
func (c *chunkRec) OnOpen(cc *hooks.Conn, hc *hooks.HookConn) hooks.Result {
	return hooks.Result{}
}
func (c *chunkRec) OnData(cc *hooks.Conn, dir hooks.Dir, data []byte) hooks.Result {
	c.mu.Lock()
	c.chunks[dir] = append(c.chunks[dir], append([]byte(nil), data...))
	c.mu.Unlock()
	return hooks.Result{}
}
func (c *chunkRec) OnClose(cc *hooks.Conn, reason string) {}

func (c *chunkRec) got(dir hooks.Dir) [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.chunks[dir]...)
}

// readRequest reads from up until the request terminator has arrived.
func readRequest(up net.Conn) []byte {
	var req []byte
	rb := make([]byte, 256)
	for !bytes.Contains(req, []byte("\r\n\r\n")) {
		n, err := up.Read(rb)
		req = append(req, rb[:n]...)
		if err != nil {
			return req
		}
	}
	return req
}

func TestLadderScriptedUpstreamChunkSplit(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)

	// A scripted upstream: one end of an in-memory pipe, driven by a test
	// goroutine, dialed through l.Dial instead of TCP. The ladder sees a
	// plain net.Conn and nothing else changes.
	upServer, upClient := net.Pipe()
	l.Dial = func(net.Addr) (net.Conn, error) { return upClient, nil }

	rec := &chunkRec{chunks: map[hooks.Dir][][]byte{}}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(rec)

	// The upstream splits one response across two writes; the hook must
	// see exactly that split. An echo upstream cannot script this.
	const respA = "HTTP/1.1 200 OK\r\n"
	const respB = "Content-Length: 0\r\n\r\n"

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer clientConn.Close()
		clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		buf := make([]byte, len(respA)+len(respB))
		if _, err := io.ReadFull(clientConn, buf); err != nil {
			return
		}
		if string(buf) != respA+respB {
			t.Errorf("client received %q, want the two scripted writes in order", buf)
		}
	}()
	go func() {
		defer upServer.Close()
		if req := readRequest(upServer); !bytes.Contains(req, []byte("Host: x")) {
			t.Errorf("upstream request = %q, want the client request", req)
		}
		upServer.Write([]byte(respA))
		upServer.Write([]byte(respB))
	}()
	if err := l.Serve(serverConn, &net.TCPAddr{}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	<-done
	s2c := rec.got(hooks.DirS2C)
	if len(s2c) != 2 || string(s2c[0]) != respA || string(s2c[1]) != respB {
		t.Errorf("hook saw s2c chunks %q, want the scripted split [%q %q] verbatim", s2c, respA, respB)
	}
	if cap := readCapture(t, dir, "s2c.bin"); cap != respA+respB {
		t.Errorf("s2c capture = %q, want both scripted writes concatenated", cap)
	}
}

// timedPusher is a push hook: its goroutine pushes a message every `every`
// (a real timer; inside a synctest bubble it runs on the simulated clock).
type timedPusher struct {
	msg   string
	every time.Duration
}

func (p *timedPusher) Filter() hooks.Match { return hooks.Match{} }
func (p *timedPusher) OnOpen(c *hooks.Conn, hc *hooks.HookConn) hooks.Result {
	go func() {
		<-hc.Ready()
		for {
			select {
			case <-hc.Done():
				return
			case <-time.After(p.every):
				if _, err := hc.WriteS2C([]byte(p.msg)); err != nil {
					return
				}
			}
		}
	}()
	return hooks.Result{}
}
func (p *timedPusher) OnData(c *hooks.Conn, dir hooks.Dir, data []byte) hooks.Result {
	return hooks.Result{}
}
func (p *timedPusher) OnClose(c *hooks.Conn, reason string) {}

func TestLadderHookPushUnderSynctest(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)

	synctest.Test(t, func(t *testing.T) {
		// Both legs are chanpipe (pkg/chanpipe) pipes created inside the
		// bubble: only channels created within the bubble are "durably
		// blocking" for synctest, and only then does the simulated clock
		// advance. net.Pipe would not work here at all: its kernel pipe
		// is a non-durable blocking wait. ~250 ms of simulated time
		// elapses at zero wall-clock cost.
		upServer, upClient := chanpipe.New()
		l.Dial = func(net.Addr) (net.Conn, error) { return upClient, nil }
		clientConn, serverConn := chanpipe.New()

		l.Hooks = hooks.NewPipeline()
		l.Hooks.Register(&timedPusher{msg: "PING", every: 50 * time.Millisecond})

		go func() {
			// Client: send a request, collect three pings, hang up.
			clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
			buf := make([]byte, 3*len("PING"))
			io.ReadFull(clientConn, buf)
			clientConn.Close()
		}()
		go func() {
			// Upstream: swallow the request, hold the connection for 200 ms
			// of simulated time, then close so the relay's s2c copy ends.
			readRequest(upServer)
			time.Sleep(200 * time.Millisecond)
			upServer.Close()
		}()
		if err := l.Serve(serverConn, &net.TCPAddr{}); err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	if cap := readCapture(t, dir, "s2c.bin"); strings.Count(cap, "PING") != 3 {
		t.Errorf("s2c capture = %q, want exactly three simulated-time pings", cap)
	}
}

func TestLadderHookPassiveSeesBothDirections(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	up, _ := newEchoUpstream(t)

	h := &hooky{dataSeen: map[hooks.Dir]int{}}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(h)

	const req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer clientConn.Close()
		if _, err := clientConn.Write([]byte(req)); err != nil {
			return
		}
		buf := make([]byte, len(req))
		if _, err := io.ReadFull(clientConn, buf); err != nil {
			return
		}
		if string(buf) != req {
			t.Errorf("client received %q, want the request verbatim", buf)
		}
	}()
	if err := l.Serve(serverConn, up.Addr()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	<-done
	if n := h.seen(hooks.DirC2S); n == 0 {
		t.Error("passive hook saw no c2s bytes")
	}
	if n := h.seen(hooks.DirS2C); n == 0 {
		t.Error("passive hook saw no s2c bytes")
	}
	if got := h.closes(); len(got) != 1 {
		t.Errorf("OnClose notifications = %v, want exactly one", got)
	}
}

// TestLadderCaptureStreamRecordsDecisions: the per-connection record shows
// the post-decision view — the request forwarded, the policy-dropped
// response chunk dropped with its reason, and the close metadata.
func TestLadderCaptureStreamRecordsDecisions(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	reg := capture.NewRegistry()
	l.Capture = reg
	var stream *capture.Stream
	reg.OnConnection(func(s *capture.Stream) { stream = s })

	dropPolicy := &policyDrop{}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(dropPolicy)

	upServer, upClient := net.Pipe()
	l.Dial = func(net.Addr) (net.Conn, error) { return upClient, nil }
	clientConn, serverConn := net.Pipe()
	go func() {
		defer clientConn.Close()
		clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		buf := make([]byte, 256)
		// The policy drops the whole response, so nothing reaches the
		// client and net.Pipe offers no half-close to end this Read;
		// bound the wait so the client closes and the relay's c2s copy
		// sees its EOF.
		clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		clientConn.Read(buf)
	}()
	go func() {
		defer upServer.Close()
		readRequest(upServer)
		upServer.Write([]byte("HTTP/1.1 200 OK\r\n\r\nblocked here\r\n"))
		time.Sleep(10 * time.Millisecond)
	}()
	if err := l.Serve(serverConn, &net.TCPAddr{}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	<-stream.Wait()

	info := stream.Info()
	if info.Kind != "plain_http" || info.Cause != "" || info.ID == "" {
		t.Errorf("CloseInfo = %+v, want a clean plain_http record", info)
	}
	if info.Client == "" || info.Dst == "" {
		t.Errorf("CloseInfo tuple empty: %+v", info)
	}
	chunks := stream.Chunks()
	if len(chunks) != 2 {
		t.Fatalf("chunks = %+v, want one forwarded and one dropped", chunks)
	}
	if chunks[0].Dir != hooks.DirC2S || chunks[0].Decision != capture.Forwarded || chunks[0].Len != len("GET / HTTP/1.1\r\nHost: x\r\n\r\n") {
		t.Errorf("chunks[0] = %+v, want the forwarded request", chunks[0])
	}
	if chunks[1].Dir != hooks.DirS2C || chunks[1].Decision != capture.Dropped || chunks[1].Reason != "policy" {
		t.Errorf("chunks[1] = %+v, want the dropped response with reason policy", chunks[1])
	}
}

// policyDrop drops s2c chunks containing the marker, recording a reason.
type policyDrop struct{}

func (p *policyDrop) Filter() hooks.Match { return hooks.Match{} }
func (p *policyDrop) OnOpen(c *hooks.Conn, hc *hooks.HookConn) hooks.Result {
	return hooks.Result{}
}
func (p *policyDrop) OnData(c *hooks.Conn, dir hooks.Dir, data []byte) hooks.Result {
	if dir == hooks.DirS2C && bytes.Contains(data, []byte("blocked")) {
		return hooks.Result{Data: []byte{}, Reason: "policy"}
	}
	return hooks.Result{}
}
func (p *policyDrop) OnClose(c *hooks.Conn, reason string) {}
