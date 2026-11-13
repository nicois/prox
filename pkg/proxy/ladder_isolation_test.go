package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nicois/prox/pkg/capture"
	"github.com/nicois/prox/pkg/hooks"
	"github.com/nicois/prox/pkg/isolation"
)

// countDir sums the forwarded capture bytes in one direction.
func countDir(t *testing.T, stream *capture.Stream, dir hooks.Dir) int {
	t.Helper()
	var n int
	for _, r := range stream.Chunks() {
		if r.Dir == dir && r.Decision == capture.Forwarded {
			n += r.Len
		}
	}
	return n
}

// readSinkBins reads the single connection's c2s.bin and s2c.bin from the
// file sink under dataRoot. A standalone flow (no hooks) records no capture
// chunks, so the sink is where its captured bytes are observable.
func readSinkBins(t *testing.T, dataRoot string) (c2s, s2c []byte) {
	t.Helper()
	err := filepath.WalkDir(dataRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		switch d.Name() {
		case "c2s.bin":
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Fatal(rerr)
			}
			c2s = b
		case "s2c.bin":
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Fatal(rerr)
			}
			s2c = b
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return c2s, s2c
}

// TestLadderIsolationFullPlain: a plain flow under full isolation is served
// locally — the request is accepted and captured, nothing is dialed, nothing
// is written to the client, and the flow stays open while the client is.
func TestLadderIsolationFullPlain(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.Capture = capture.NewRegistry()
	streamCh := make(chan *capture.Stream, 1)
	l.Capture.OnConnection(func(s *capture.Stream) { streamCh <- s })
	dialed := make(chan struct{}, 1)
	l.Dial = func(net.Addr) (net.Conn, error) {
		dialed <- struct{}{}
		t.Error("Dial must not be called under full isolation")
		return nil, errors.New("no dial under full isolation")
	}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(isolation.Full())

	client, server := net.Pipe()
	defer server.Close()

	const req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	go func() {
		defer client.Close()
		// Send the request in two chunks, then stay silent.
		half := len(req) / 2
		_, _ = client.Write([]byte(req[:half]))
		_, _ = client.Write([]byte(req[half:]))
		// The client must receive nothing: a short deadline, not data.
		_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 1)
		if n, err := client.Read(buf); err == nil && n != 0 {
			t.Errorf("client read %d bytes, want none", n)
		}
	}()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- l.Serve(server, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80})
	}()

	// Receive the stream (the channel handoff synchronizes the pointer). The
	// client is still open in its silent window, so the isolation flow must
	// still be open: the capture stream is not yet finished.
	var stream *capture.Stream
	select {
	case stream = <-streamCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no capture stream")
	}
	if !stream.Info().Closed.IsZero() {
		t.Fatal("stream was finished while the client was still open")
	}

	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after the client closed")
	}

	select {
	case <-dialed:
		t.Fatal("Dial called under full isolation")
	default:
	}
	info := stream.Info()
	if info.ServeMode != "local" {
		t.Errorf("ServeMode = %q, want local", info.ServeMode)
	}
	if info.Labels["isolation"] != "full" {
		t.Errorf("Labels[isolation] = %q, want full (labels %v)", info.Labels["isolation"], info.Labels)
	}
	if got := countDir(t, stream, hooks.DirC2S); got < len(req) {
		t.Errorf("c2s = %d, want to cover the full request (%d)", got, len(req))
	}
	if got := countDir(t, stream, hooks.DirS2C); got != 0 {
		t.Errorf("s2c = %d, want 0", got)
	}
}

// TestLadderIsolationFullTLS: a TLS flow under full isolation completes the
// client-leg MITM handshake against the forged leaf, captures the decrypted
// request, never dials, and sends the client nothing.
func TestLadderIsolationFullTLS(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.Capture = capture.NewRegistry()
	var stream *capture.Stream
	l.Capture.OnConnection(func(s *capture.Stream) { stream = s })
	dialed := make(chan struct{}, 1)
	l.Dial = func(net.Addr) (net.Conn, error) {
		dialed <- struct{}{}
		t.Error("Dial must not be called under full isolation")
		return nil, errors.New("no dial under full isolation")
	}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(isolation.Full())

	ca, caKey := buildCert(t, "iso-ca", nil, nil, true, nil, nil)
	l.Leaves = fakeLeafProvider{cert: leafFor(t, ca, caKey, "example.com")}
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	client, server := net.Pipe()
	defer server.Close()

	hsDone := make(chan error, 1)
	appSent := make(chan error, 1)
	go func() {
		defer client.Close()
		tlsC := tls.Client(client, &tls.Config{ServerName: "example.com", RootCAs: pool})
		if err := tlsC.Handshake(); err != nil {
			hsDone <- err
			return
		}
		hsDone <- nil
		if _, err := tlsC.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
			appSent <- err
			return
		}
		appSent <- nil
		// The client receives no app bytes: a short deadline, not data.
		_ = tlsC.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 1)
		if n, err := tlsC.Read(buf); err == nil && n != 0 {
			t.Errorf("client read %d app bytes, want none", n)
		}
	}()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- l.Serve(server, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443})
	}()

	select {
	case err := <-hsDone:
		if err != nil {
			t.Fatalf("client handshake: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client handshake did not complete")
	}
	select {
	case err := <-appSent:
		if err != nil {
			t.Fatalf("client app write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client app write did not complete")
	}
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after the client closed")
	}

	select {
	case <-dialed:
		t.Fatal("Dial called under full isolation")
	default:
	}
	if stream == nil {
		t.Fatal("no capture stream recorded")
	}
	info := stream.Info()
	if info.ServeMode != "local" {
		t.Errorf("ServeMode = %q, want local", info.ServeMode)
	}
	if info.Labels["isolation"] != "full" {
		t.Errorf("Labels[isolation] = %q, want full (labels %v)", info.Labels["isolation"], info.Labels)
	}
	if got := countDir(t, stream, hooks.DirC2S); got == 0 {
		t.Error("decrypted c2s not captured (c2s=0)")
	}
	if got := countDir(t, stream, hooks.DirS2C); got != 0 {
		t.Errorf("s2c = %d, want 0", got)
	}
}

// TestLadderIsolationReadOnlyPlain: a plain flow under read-only isolation
// mirrors c2s to the real upstream but captures s2c without delivering it to
// the client; the record is labeled isolation=readonly and served as mirror.
func TestLadderIsolationReadOnlyPlain(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.Capture = capture.NewRegistry()
	var stream *capture.Stream
	l.Capture.OnConnection(func(s *capture.Stream) { stream = s })
	l.IsolationReadOnly = true // no hooks: the standalone case
	l.Hooks = hooks.NewPipeline()

	const req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	const reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	upl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upl.Close()
	gotReq := make(chan string, 1)
	go func() {
		c, err := upl.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Read the full request, then reply and close.
		var got []byte
		buf := make([]byte, 4096)
		for len(got) < len(req) {
			n, rerr := c.Read(buf)
			got = append(got, buf[:n]...)
			if rerr != nil {
				break
			}
		}
		gotReq <- string(got)
		_, _ = c.Write([]byte(reply))
	}()

	client, server := net.Pipe()
	defer server.Close()
	clientGot := make(chan int, 1)
	go func() {
		defer client.Close()
		_, _ = client.Write([]byte(req))
		// The client receives nothing under readonly; over a real socket the
		// relay half-closes toward it once the upstream finishes, so it
		// closes. Here net.Pipe has no half-close, so a read deadline stands
		// in for that and closes the client to end the flow.
		_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, len(reply))
		n, _ := client.Read(buf) // must receive nothing
		clientGot <- n
	}()

	if err := l.Serve(server, upl.Addr()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if got := <-gotReq; got != req {
		t.Errorf("upstream got %q, want the full request %q", got, req)
	}
	if n := <-clientGot; n != 0 {
		t.Errorf("client received %d bytes, want 0", n)
	}
	if stream == nil {
		t.Fatal("no capture stream recorded")
	}
	info := stream.Info()
	if info.Labels["isolation"] != "readonly" {
		t.Errorf("Labels[isolation] = %q, want readonly (labels %v)", info.Labels["isolation"], info.Labels)
	}
	if info.ServeMode != "mirror" {
		t.Errorf("ServeMode = %q, want mirror", info.ServeMode)
	}
	c2sBin, s2cBin := readSinkBins(t, dir)
	if string(s2cBin) != reply {
		t.Errorf("s2c capture = %q, want the full reply %q", s2cBin, reply)
	}
	if len(c2sBin) < len(req) {
		t.Errorf("c2s capture = %d bytes, want to cover the request (%d)", len(c2sBin), len(req))
	}
}

// TestLadderIsolationReadOnlyTLS: a TLS flow under read-only isolation
// completes the client-leg MITM and mirrors to the real upstream, but s2c is
// captured without being delivered to the client; the record is labeled
// isolation=readonly.
func TestLadderIsolationReadOnlyTLS(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.Capture = capture.NewRegistry()
	var stream *capture.Stream
	l.Capture.OnConnection(func(s *capture.Stream) { stream = s })
	l.IsolationReadOnly = true // no hooks: the standalone case
	l.Hooks = hooks.NewPipeline()

	ca, caKey := buildCert(t, "iso-ca", nil, nil, true, nil, nil)
	l.Leaves = fakeLeafProvider{cert: leafFor(t, ca, caKey, "example.com")}
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	const req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	const reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	upCert, upKey := buildCert(t, "upstream", []string{"example.com"}, []net.IP{net.ParseIP("127.0.0.1")}, true, nil, nil)
	upl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upl.Close()
	upRoots := x509.NewCertPool()
	upRoots.AddCert(upCert)
	l.UpstreamRoots = upRoots
	upReq := make(chan int, 1)
	go func() {
		for {
			c, err := upl.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsS := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{
					{Certificate: [][]byte{upCert.Raw}, PrivateKey: upKey},
				}})
				if err := tlsS.Handshake(); err != nil {
					return
				}
				buf := make([]byte, 4096)
				n, _ := tlsS.Read(buf)
				upReq <- n
				_, _ = tlsS.Write([]byte(reply))
			}(c)
		}
	}()

	client, server := net.Pipe()
	defer server.Close()
	clientGot := make(chan int, 1)
	go func() {
		defer client.Close()
		tlsC := tls.Client(client, &tls.Config{ServerName: "example.com", RootCAs: pool})
		if err := tlsC.Handshake(); err != nil {
			clientGot <- -1
			return
		}
		if _, err := tlsC.Write([]byte(req)); err != nil {
			clientGot <- -1
			return
		}
		_ = tlsC.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, len(reply))
		n, _ := tlsC.Read(buf) // must receive nothing
		clientGot <- n
	}()

	if err := l.Serve(server, upl.Addr()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if n := <-clientGot; n != 0 {
		t.Errorf("client received %d app bytes, want 0", n)
	}
	if n := <-upReq; n <= 0 {
		t.Errorf("upstream read %d bytes of the request, want > 0", n)
	}
	if stream == nil {
		t.Fatal("no capture stream recorded")
	}
	info := stream.Info()
	if info.Labels["isolation"] != "readonly" {
		t.Errorf("Labels[isolation] = %q, want readonly (labels %v)", info.Labels["isolation"], info.Labels)
	}
	if info.ServeMode != "mirror" {
		t.Errorf("ServeMode = %q, want mirror", info.ServeMode)
	}
	c2sBin, s2cBin := readSinkBins(t, dir)
	if string(s2cBin) != reply {
		t.Errorf("s2c capture = %q, want the full decrypted reply %q", s2cBin, reply)
	}
	if len(c2sBin) < len(req) {
		t.Errorf("c2s capture = %d bytes, want to cover the request (%d)", len(c2sBin), len(req))
	}
}

// labelMirrorHook is a consumer hook that labels the flow in OnOpen and
// decides mirror: it pins that the relay's readonly label lands in the same
// capture record as the hook's own label.
type labelMirrorHook struct{}

func (labelMirrorHook) Filter() hooks.Match { return hooks.Match{} }
func (labelMirrorHook) OnOpen(c *hooks.Conn, hc *hooks.HookConn) hooks.Result {
	c.SetLabel("who", "consumer")
	return hooks.Result{}
}
func (labelMirrorHook) OnData(c *hooks.Conn, dir hooks.Dir, data []byte) hooks.Result {
	return hooks.Result{}
}
func (labelMirrorHook) OnClose(c *hooks.Conn, reason string) {}
func (labelMirrorHook) Serve(c *hooks.Conn) (hooks.ServeDecision, error) {
	return hooks.ServeDecision{Mode: hooks.ServeMirror}, nil
}

// TestLadderIsolationReadOnlyWithHook: a hooked readonly flow merges the
// consumer hook's own OnOpen label with the relay's isolation=readonly
// label in one capture record; the record's serve mode is the hook's
// decision (mirror) and the client still receives no s2c bytes.
func TestLadderIsolationReadOnlyWithHook(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.Capture = capture.NewRegistry()
	var stream *capture.Stream
	l.Capture.OnConnection(func(s *capture.Stream) { stream = s })
	l.IsolationReadOnly = true
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(labelMirrorHook{})

	const req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	const reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	upl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upl.Close()
	gotReq := make(chan string, 1)
	go func() {
		c, err := upl.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Read the full request, then reply and close.
		var got []byte
		buf := make([]byte, 4096)
		for len(got) < len(req) {
			n, rerr := c.Read(buf)
			got = append(got, buf[:n]...)
			if rerr != nil {
				break
			}
		}
		gotReq <- string(got)
		_, _ = c.Write([]byte(reply))
	}()

	client, server := net.Pipe()
	defer server.Close()
	clientGot := make(chan int, 1)
	go func() {
		defer client.Close()
		_, _ = client.Write([]byte(req))
		// The client receives nothing under readonly; over a real socket the
		// relay half-closes toward it once the upstream finishes, so it
		// closes. Here net.Pipe has no half-close, so a read deadline stands
		// in for that and closes the client to end the flow.
		_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, len(reply))
		n, _ := client.Read(buf) // must receive nothing
		clientGot <- n
	}()

	if err := l.Serve(server, upl.Addr()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if got := <-gotReq; got != req {
		t.Errorf("upstream got %q, want the full request %q", got, req)
	}
	if n := <-clientGot; n != 0 {
		t.Errorf("client received %d bytes, want 0", n)
	}
	if stream == nil {
		t.Fatal("no capture stream recorded")
	}
	info := stream.Info()
	if info.Labels["isolation"] != "readonly" {
		t.Errorf("Labels[isolation] = %q, want readonly (labels %v)", info.Labels["isolation"], info.Labels)
	}
	if info.Labels["who"] != "consumer" {
		t.Errorf("Labels[who] = %q, want consumer (labels %v)", info.Labels["who"], info.Labels)
	}
	if info.ServeMode != "mirror" {
		t.Errorf("ServeMode = %q, want mirror (the hook's decision)", info.ServeMode)
	}
	if got := countDir(t, stream, hooks.DirS2C); got < len(reply) {
		t.Errorf("s2c = %d, want the captured reply (%d)", got, len(reply))
	}
}
