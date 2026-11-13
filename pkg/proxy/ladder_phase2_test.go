package proxy

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nicois/prox/pkg/capture"
	"github.com/nicois/prox/pkg/hooks"
	"github.com/nicois/prox/pkg/store"
	"github.com/nicois/prox/pkg/tlsutil"
)

// newTestStore opens the ladder's patch store in dir and closes it when the
// test ends.
func newTestStore(t *testing.T, dir string) (*store.Store, error) {
	t.Helper()
	st, err := store.Open(filepath.Join(dir, "index.db"))
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { st.Close() })
	return st, nil
}

// pipeLeg is one side of a ServeLocal leg: an io.Pipe pair wrapped in the
// io.ReadWriteCloser a ServeDecision carries. For the leg side, Write is
// c2s (relay -> consumer) and Read is s2c (consumer -> relay); other is the
// mirror the test drives.
type pipeLeg struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p *pipeLeg) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeLeg) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeLeg) Close() error {
	_ = p.r.Close()
	_ = p.w.Close()
	return nil
}

func newPipeLeg() (leg, other *pipeLeg) {
	pr1, pw1 := io.Pipe() // c2s: relay writes, test reads
	pr2, pw2 := io.Pipe() // s2c: test writes, relay reads
	return &pipeLeg{r: pr2, w: pw1}, &pipeLeg{r: pr1, w: pw2}
}

// counter counts hook observations of one flow (package scope: methods
// cannot be declared inside a test function).
type counter struct {
	opens, closes *int32
}

func (h counter) Filter() hooks.Match { return hooks.Match{} }
func (h counter) OnOpen(cc *hooks.Conn, hc *hooks.HookConn) hooks.Result {
	atomic.AddInt32(h.opens, 1)
	return hooks.Result{}
}
func (h counter) OnData(cc *hooks.Conn, dir hooks.Dir, data []byte) hooks.Result {
	return hooks.Result{}
}
func (h counter) OnClose(cc *hooks.Conn, reason string) { atomic.AddInt32(h.closes, 1) }

type servingStub struct {
	dec hooks.ServeDecision
	err error
}

func (s servingStub) Filter() hooks.Match                                   { return hooks.Match{} }
func (s servingStub) OnOpen(c *hooks.Conn, hc *hooks.HookConn) hooks.Result { return hooks.Result{} }
func (s servingStub) OnData(c *hooks.Conn, dir hooks.Dir, data []byte) hooks.Result {
	return hooks.Result{}
}
func (s servingStub) OnClose(c *hooks.Conn, reason string)             {}
func (s servingStub) Serve(c *hooks.Conn) (hooks.ServeDecision, error) { return s.dec, s.err }

func TestLadderPlainLocal(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.Capture = capture.NewRegistry()
	var stream *capture.Stream
	l.Capture.OnConnection(func(s *capture.Stream) { stream = s })
	l.Dial = func(net.Addr) (net.Conn, error) {
		t.Error("Dial must not be called in local mode")
		return nil, errors.New("no dial in local mode")
	}
	leg, other := newPipeLeg()
	defer leg.Close()
	defer other.Close()
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(servingStub{dec: hooks.ServeDecision{Mode: hooks.ServeLocal, Local: leg}})

	got := make(chan string, 1)
	go func() {
		// Consumer side of the leg: read the client's bytes, answer.
		buf := make([]byte, 5)
		if _, err := io.ReadFull(other, buf); err != nil {
			got <- "read:" + err.Error()
			return
		}
		if _, err := other.Write([]byte("PONG\n")); err != nil {
			got <- "write:" + err.Error()
			return
		}
		other.Close()
		got <- string(buf)
	}()

	client, server := net.Pipe()
	defer server.Close()
	go func() {
		defer client.Close()
		if _, err := client.Write([]byte("PING\n")); err != nil {
			return
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(client, buf); err != nil {
			return
		}
		if string(buf) != "PONG\n" {
			t.Errorf("client got %q, want PONG\\n", buf)
		}
	}()

	if err := l.Serve(server, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if s := <-got; s != "PING\n" {
		t.Fatalf("consumer leg got %q, want PING\\n", s)
	}
	if stream == nil {
		t.Fatal("no capture stream recorded")
	}
	recs := stream.Chunks()
	var c2s, s2c int
	for _, r := range recs {
		switch {
		case r.Dir == hooks.DirC2S && r.Decision == capture.Forwarded:
			c2s += r.Len
		case r.Dir == hooks.DirS2C && r.Decision == capture.Forwarded:
			s2c += r.Len
		}
	}
	if c2s != 5 || s2c != 5 {
		t.Errorf("forwarded bytes c2s=%d s2c=%d; want 5/5 (recs %+v)", c2s, s2c, recs)
	}
	if info := stream.Info(); info.ServeMode != "local" {
		t.Errorf("ServeMode = %q, want local", info.ServeMode)
	}
}

func TestLadderServeReject(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.Capture = capture.NewRegistry()
	var stream *capture.Stream
	l.Capture.OnConnection(func(s *capture.Stream) { stream = s })
	dialed := make(chan struct{}, 1)
	l.Dial = func(net.Addr) (net.Conn, error) {
		dialed <- struct{}{}
		return nil, errors.New("no dial")
	}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(servingStub{dec: hooks.ServeDecision{Mode: hooks.ServeReject, Reason: "not here"}})

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	}()
	err := l.Serve(server, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("not here")) {
		t.Fatalf("Serve err = %v; want the reject reason", err)
	}
	select {
	case <-dialed:
		t.Fatal("Dial called for a rejected flow")
	default:
	}
	if stream == nil {
		t.Fatal("no capture stream for the rejected flow")
	}
	info := stream.Info()
	if info.ServeMode != "reject" || info.Cause != "not here" {
		t.Errorf("info = %+v; want ServeMode reject, Cause not here", info)
	}
	meta, err := readAllMeta(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(meta), []byte(`"rejected"`)) {
		t.Errorf("meta missing record_summary rejected: %s", meta)
	}
}

func TestLadderPatchedGateOnce(t *testing.T) {
	// A patched TLS flow with the TunnelFallback opt-in tunnels via the
	// raw path; its hooks must observe the flow exactly once (one OnOpen,
	// one OnClose) — the tunnel path must not re-run the gate.
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.TunnelFallback = true
	st, err := newTestStore(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	l.Store = st
	if err := st.MarkPatch("192.0.2.1", "example.com", "mtls", time.Now()); err != nil {
		t.Fatal(err)
	}
	var opens, closes int32
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(counter{opens: &opens, closes: &closes})

	up, upEnd := net.Pipe()
	go io.Copy(io.Discard, up) // drain the relayed ClientHello
	l.Dial = func(net.Addr) (net.Conn, error) { return up, nil }

	client, server := net.Pipe()
	defer server.Close()
	go func() {
		tlsC := tls.Client(client, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
		go func() { _ = tlsC.Handshake() }()
		time.Sleep(200 * time.Millisecond)
		client.Close()
	}()
	go func() {
		time.Sleep(200 * time.Millisecond)
		upEnd.Close() // end the relay so Serve returns
	}()

	dst := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
	if err := l.Serve(server, dst); err != nil && !isCloseErr(err) {
		t.Fatalf("Serve: %v", err)
	}
	if atomic.LoadInt32(&opens) != 1 {
		t.Errorf("OnOpen = %d, want 1 (gate must run exactly once)", atomic.LoadInt32(&opens))
	}
	if atomic.LoadInt32(&closes) != 1 {
		t.Errorf("OnClose = %d, want 1", atomic.LoadInt32(&closes))
	}
}

// poisonMinter fails if consulted — a selector test that mints would break
// the client handshake against the selector CA.
type poisonMinter struct{}

func (poisonMinter) Leaf(host, dst string, now time.Time) (*tls.Certificate, error) {
	return nil, errors.New("minter must not be consulted")
}

// leafFor mints a leaf for host under the given CA — the same construction
// TestLadderTLSMitm uses for its fake leaf (tlsutil.MintLeaf + a fresh
// ECDSA P-256 key + x509.CreateCertificate).
func leafFor(t *testing.T, ca *x509.Certificate, caKey crypto.Signer, host string) *tls.Certificate {
	t.Helper()
	now := time.Now()
	leafTmpl, _, err := tlsutil.MintLeaf(ca, caKey, host, "192.0.2.1", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, leafPriv.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{leafDER, ca.Raw}, PrivateKey: leafPriv}
}

// tlsClientFlow runs one TLS client handshake over a net.Pipe pair through
// l, with the client trusting roots. The upstream is a scripted loopback
// TLS echo (self-signed; the ladder trusts it via UpstreamRoots) so the
// mirror path's dial never touches a real network. It reports the client's
// handshake error.
func tlsClientFlow(t *testing.T, l *Ladder, roots *x509.CertPool, sni string) error {
	t.Helper()
	upCert, upKey := buildCert(t, "upstream", []string{sni}, []net.IP{net.ParseIP("127.0.0.1")}, true, nil, nil)
	upl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upl.Close()
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
				go func() {
					_ = tlsS.Handshake()
					_, _ = io.Copy(tlsS, tlsS)
				}()
			}(c)
		}
	}()
	pool := x509.NewCertPool()
	pool.AddCert(upCert)
	l.UpstreamRoots = pool

	client, server := net.Pipe()
	defer server.Close()
	errCh := make(chan error, 1)
	go func() {
		defer client.Close()
		tlsC := tls.Client(client, &tls.Config{ServerName: sni, RootCAs: roots})
		if err := tlsC.Handshake(); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	_ = l.Serve(server, upl.Addr())
	select {
	case err := <-errCh:
		return err
	case <-time.After(2 * time.Second):
		return errors.New("client handshake did not complete")
	}
}

func TestLadderTLSSelectorSuppliesLeaf(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	selCA, selKey := buildCert(t, "selector-ca", nil, nil, true, nil, nil)
	selLeaf := leafFor(t, selCA, selKey, "example.com")
	l.Leaves = poisonMinter{}
	l.LeafSelector = func(host, dst string) (*tls.Certificate, error) {
		if host != "example.com" {
			t.Errorf("selector host = %q, want example.com", host)
		}
		return selLeaf, nil
	}
	pool := x509.NewCertPool()
	pool.AddCert(selCA)
	if err := tlsClientFlow(t, l, pool, "example.com"); err != nil {
		t.Fatalf("client handshake = %v; want success against the selector CA", err)
	}
}

func TestLadderTLSSelectorFallsThrough(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	mintCA, mintKey := buildCert(t, "minter-ca", nil, nil, true, nil, nil)
	mintLeaf := leafFor(t, mintCA, mintKey, "example.com")
	l.Leaves = fakeLeafProvider{cert: mintLeaf}
	l.LeafSelector = func(host, dst string) (*tls.Certificate, error) { return nil, nil }
	pool := x509.NewCertPool()
	pool.AddCert(mintCA)
	if err := tlsClientFlow(t, l, pool, "example.com"); err != nil {
		t.Fatalf("client handshake = %v; want the minter's leaf when the selector passes", err)
	}
}

func TestLadderTLSSelectorErrorFailsMint(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.Leaves = fakeLeafProvider{cert: nil}
	l.Capture = capture.NewRegistry()
	var stream *capture.Stream
	l.Capture.OnConnection(func(s *capture.Stream) { stream = s })
	l.LeafSelector = func(host, dst string) (*tls.Certificate, error) {
		return nil, errors.New("no cert for host")
	}
	// The client must be rejected (the server leg ends without a cert).
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		defer client.Close()
		tlsC := tls.Client(client, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
		_ = tlsC.Handshake()
		time.Sleep(100 * time.Millisecond)
	}()
	dst := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
	_ = l.Serve(server, dst)
	if stream == nil {
		t.Fatal("no capture stream")
	}
	info := stream.Info()
	if info.TLS == nil || info.TLS.Result != "mint_failed" {
		t.Errorf("TLS outcome = %+v; want mint_failed", info.TLS)
	}
	if info.Cause != "mint_failed" {
		t.Errorf("Cause = %q, want mint_failed", info.Cause)
	}
	meta, err := readAllMeta(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(meta, `"result":"mint_failed"`) {
		t.Errorf("meta missing mint_failed: %s", meta)
	}
}

type eventSink struct {
	mu  sync.Mutex
	evs []hooks.Event
}

func (e *eventSink) add(ev hooks.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.evs = append(e.evs, ev)
}

func (e *eventSink) has(kind hooks.EventKind) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.evs {
		if ev.Kind == kind {
			return true
		}
	}
	return false
}

func (e *eventSink) hasKD(kind hooks.EventKind, dir hooks.Dir) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.evs {
		if ev.Kind == kind && ev.Dir == dir {
			return true
		}
	}
	return false
}

type eventHook struct{ sink *eventSink }

func (h eventHook) Filter() hooks.Match                                   { return hooks.Match{} }
func (h eventHook) OnOpen(c *hooks.Conn, hc *hooks.HookConn) hooks.Result { return hooks.Result{} }
func (h eventHook) OnData(c *hooks.Conn, dir hooks.Dir, data []byte) hooks.Result {
	return hooks.Result{}
}
func (h eventHook) OnClose(c *hooks.Conn, reason string) {}
func (h eventHook) OnEvent(c *hooks.Conn, e hooks.Event) { h.sink.add(e) }

func TestLadderEventUpstreamConnectFailed(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	sinkEv := &eventSink{}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(eventHook{sink: sinkEv})
	l.Dial = func(net.Addr) (net.Conn, error) { return nil, errors.New("dial refused") }
	client, server := net.Pipe()
	defer client.Close()
	go func() { _, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")) }()
	_ = l.Serve(server, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80})
	if !sinkEv.has(hooks.UpstreamConnectFailed) {
		t.Errorf("events = %+v; want upstream_connect_failed", sinkEv.evs)
	}
}

func TestLadderEventLegsEnd(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	sinkEv := &eventSink{}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(eventHook{sink: sinkEv})
	// Scripted in-memory upstream: echoes one line, then stays open until
	// the test closes it. The relay dials one end of the pipe; the script
	// must drive the peer end (reading the request, writing the response).
	// The read size must match the request below byte-for-byte: net.Pipe
	// writes block until fully consumed, so a short read deadlocks the
	// relay's single 27-byte write.
	upRelay, upScript := net.Pipe()
	go func() {
		defer upScript.Close()
		buf := make([]byte, 27)
		if _, err := io.ReadFull(upScript, buf); err != nil {
			return
		}
		_, _ = upScript.Write([]byte("HTTP/1.1 200 OK\r\n\r\nbye"))
		// stay open until the test ends the flow
		time.Sleep(300 * time.Millisecond)
	}()
	l.Dial = func(net.Addr) (net.Conn, error) { return upRelay, nil }

	client, server := net.Pipe()
	defer server.Close()
	go func() {
		defer client.Close()
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		buf := make([]byte, 3)
		if _, err := io.ReadFull(client, buf); err != nil {
			return
		}
		// client closes its side: ClientClose must fire
		client.Close()
	}()
	_ = l.Serve(server, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80})
	if !sinkEv.hasKD(hooks.ClientClose, hooks.DirC2S) {
		t.Errorf("events = %+v; want client_close on DirC2S", sinkEv.evs)
	}
	if !sinkEv.hasKD(hooks.UpstreamClose, hooks.DirS2C) {
		t.Errorf("events = %+v; want upstream_close on DirS2C", sinkEv.evs)
	}
}

func TestLadderEventTLSAlert(t *testing.T) {
	// An mTLS upstream rejects the no-cert upstream leg; the copy error is
	// a TLS alert and must surface as the tls_alert kind. Same flow as
	// TestLadderUpstreamMTLS, with an eventHook registered on the ladder.
	dir := t.TempDir()
	l := newLadder(t, dir)
	sinkEv := &eventSink{}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(eventHook{sink: sinkEv})

	caCert, caKey := buildCert(t, "prox-test-ca", nil, nil, true, nil, nil)
	interCert, interKey := buildCert(t, "prox-test-inter", nil, nil, true, caCert, caKey)
	now := time.Now()
	leafTmpl, _, err := tlsutil.MintLeaf(interCert, interKey, "example.com", "127.0.0.1", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, interCert, leafPriv.Public(), interKey)
	if err != nil {
		t.Fatal(err)
	}
	l.Leaves = fakeLeafProvider{cert: &tls.Certificate{
		Certificate: [][]byte{leafDER, interCert.Raw},
		PrivateKey:  leafPriv,
	}}

	// Upstream that REQUIRES a client certificate.
	upCert, upKey := buildCert(t, "upstream-mtls", []string{"example.com"}, []net.IP{net.ParseIP("127.0.0.1")}, true, nil, nil)
	upPool := x509.NewCertPool()
	upPool.AddCert(upCert)
	l.UpstreamRoots = upPool

	upl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upl.Close()
	go func() {
		for {
			c, err := upl.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsC := tls.Server(c, &tls.Config{
					Certificates: []tls.Certificate{{Certificate: [][]byte{upCert.Raw}, PrivateKey: upKey}},
					ClientCAs:    upPool,
					ClientAuth:   tls.RequireAnyClientCert,
				})
				tlsC.Handshake()
			}(c)
		}
	}()

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		defer clientConn.Close()
		tc := tls.Client(clientConn, &tls.Config{RootCAs: caPool, ServerName: "example.com"})
		if err := tc.Handshake(); err != nil {
			t.Errorf("client handshake: %v", err)
			return
		}
		tc.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	}()

	if err := l.Serve(serverConn, upl.Addr()); err == nil {
		t.Fatal("Serve: expected the upstream mTLS rejection to surface")
	}
	if !sinkEv.has(hooks.TLSAlert) {
		t.Errorf("events = %+v; want tls_alert", sinkEv.evs)
	}
}

// labelServing sets a flow label on open (package scope: methods cannot be
// declared inside a test function).
type labelServing struct{}

func (labelServing) Filter() hooks.Match { return hooks.Match{} }
func (labelServing) OnOpen(c *hooks.Conn, hc *hooks.HookConn) hooks.Result {
	c.SetLabel("class", "uplink-channel-a")
	return hooks.Result{}
}
func (labelServing) OnData(c *hooks.Conn, dir hooks.Dir, data []byte) hooks.Result {
	return hooks.Result{}
}
func (labelServing) OnClose(c *hooks.Conn, reason string) {}

func TestLabelsInCaptureRecord(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.Capture = capture.NewRegistry()
	var stream *capture.Stream
	l.Capture.OnConnection(func(s *capture.Stream) { stream = s })
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(labelServing{})
	up, upEnd := net.Pipe()
	go io.Copy(io.Discard, up)
	l.Dial = func(net.Addr) (net.Conn, error) { return up, nil }
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		defer client.Close()
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		time.Sleep(100 * time.Millisecond)
	}()
	go func() {
		time.Sleep(100 * time.Millisecond)
		upEnd.Close()
	}()
	_ = l.Serve(server, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80})
	if stream == nil {
		t.Fatal("no capture stream")
	}
	info := stream.Info()
	if info.Labels == nil || info.Labels["class"] != "uplink-channel-a" {
		t.Errorf("record labels = %v; want the hook's label", info.Labels)
	}
}

func TestUnlabeledFlowHasNilRecordLabels(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.Capture = capture.NewRegistry()
	var stream *capture.Stream
	l.Capture.OnConnection(func(s *capture.Stream) { stream = s })
	l.Hooks = hooks.NewPipeline() // no hooks at all
	up, upEnd := net.Pipe()
	go io.Copy(io.Discard, up)
	l.Dial = func(net.Addr) (net.Conn, error) { return up, nil }
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		defer client.Close()
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		time.Sleep(100 * time.Millisecond)
	}()
	go func() {
		time.Sleep(100 * time.Millisecond)
		upEnd.Close()
	}()
	_ = l.Serve(server, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80})
	if stream == nil {
		t.Fatal("no capture stream")
	}
	if info := stream.Info(); info.Labels != nil {
		t.Errorf("labels = %v; want nil for an unlabeled flow", info.Labels)
	}
}
