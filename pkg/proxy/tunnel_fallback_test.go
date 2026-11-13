package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestLadderPatchedDropDefault pins the default patched-pair behavior
// (tunnel_fallback disabled): the connection is dropped — no upstream
// dial, no bytes propagated to the upstream — and the capture meta
// carries the drop record with the stored rejection reason.
func TestLadderPatchedDropDefault(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	st, err := newTestStore(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	l.Store = st
	if err := st.MarkPatch("127.0.0.1", "example.com", "cert_rejected", time.Now()); err != nil {
		t.Fatal(err)
	}

	// Recording upstream: counts connections and bytes received; the
	// drop path must never reach it.
	var ups, upBytes int32
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
			atomic.AddInt32(&ups, 1)
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, rerr := c.Read(buf)
					if n > 0 {
						atomic.AddInt32(&upBytes, int32(n))
					}
					if rerr != nil {
						return
					}
				}
			}(c)
		}
	}()

	// Dial seam: any dial is a test failure (the drop path must not
	// touch the upstream).
	var dials int32
	l.Dial = func(net.Addr) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		return nil, errors.New("upstream must not be dialed for a dropped patched pair")
	}

	client, server := net.Pipe()
	defer server.Close()
	clientErr := make(chan error, 1)
	go func() {
		defer client.Close()
		tlsC := tls.Client(client, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
		clientErr <- tlsC.Handshake()
	}()
	if err := l.Serve(server, upl.Addr()); err == nil {
		t.Error("Serve returned nil for a dropped patched pair; want an error that closes the conn")
	}
	if err := <-clientErr; err == nil {
		t.Error("client handshake succeeded; the drop path must close the client leg")
	}
	if d := atomic.LoadInt32(&dials); d != 0 {
		t.Errorf("upstream dials = %d, want 0 (no dial on drop)", d)
	}
	if u := atomic.LoadInt32(&ups); u != 0 {
		t.Errorf("upstream connections = %d, want 0 (no ClientHello propagated)", u)
	}
	if b := atomic.LoadInt32(&upBytes); b != 0 {
		t.Errorf("upstream bytes = %d, want 0", b)
	}
	meta, err := readAllMeta(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"type":"mitm_attempt"`, `"result":"patched_drop"`, `"reason":"cert_rejected"`,
		`"type":"record_summary"`, `"reason":"patched"`,
	} {
		if !strings.Contains(meta, want) {
			t.Errorf("meta missing %s:\n%s", want, meta)
		}
	}
}

// TestLadderPatchedTunnelOptIn pins the opt-in pass-through
// (tunnel_fallback enabled): the patched pair tunnels verbatim — the
// upstream is dialed, receives the client's ClientHello, and the end-to-end
// handshake completes through the tunnel.
func TestLadderPatchedTunnelOptIn(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.TunnelFallback = true
	st, err := newTestStore(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	l.Store = st
	if err := st.MarkPatch("127.0.0.1", "example.com", "cert_rejected", time.Now()); err != nil {
		t.Fatal(err)
	}

	// Recording TLS upstream: the tunnel relays the client's ClientHello
	// here, so the server handshake can only succeed if it arrived.
	var ups, upBytes, upOK int32
	upCert, upKey := buildCert(t, "upstream", []string{"example.com"}, []net.IP{net.ParseIP("127.0.0.1")}, true, nil, nil)
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
			atomic.AddInt32(&ups, 1)
			go func(c net.Conn) {
				defer c.Close()
				tlsS := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{
					{Certificate: [][]byte{upCert.Raw}, PrivateKey: upKey},
				}})
				if err := tlsS.Handshake(); err != nil {
					return
				}
				atomic.StoreInt32(&upOK, 1)
				buf := make([]byte, 256)
				n, _ := tlsS.Read(buf)
				atomic.AddInt32(&upBytes, int32(n))
			}(c)
		}
	}()

	client, server := net.Pipe()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer client.Close()
		defer close(done)
		tlsC := tls.Client(client, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
		if err := tlsC.Handshake(); err != nil {
			t.Errorf("tunnel handshake: %v", err)
			return
		}
		if _, err := tlsC.Write([]byte("ping")); err != nil {
			t.Errorf("tunnel write: %v", err)
		}
	}()
	if err := l.Serve(server, upl.Addr()); err != nil && !isCloseErr(err) {
		t.Fatalf("Serve: %v", err)
	}
	<-done
	if u := atomic.LoadInt32(&ups); u < 1 {
		t.Errorf("upstream connections = %d, want >= 1 (opt-in tunnel dials)", u)
	}
	if k := atomic.LoadInt32(&upOK); k != 1 {
		t.Errorf("upstream handshake = %d, want 1 (the client's ClientHello must reach the upstream)", k)
	}
	if b := atomic.LoadInt32(&upBytes); b < 4 {
		t.Errorf("upstream app bytes = %d, want >= 4 (the relayed 'ping')", b)
	}
	meta, err := readAllMeta(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(meta, `"type":"record_summary"`) || !strings.Contains(meta, `"reason":"patched"`) {
		t.Errorf("meta missing the patched record_summary:\n%s", meta)
	}
}

// TestLadderClientRejectedCarriesError: a fresh pair whose client does not
// trust the forged leaf must carry the client-leg handshake error in the
// client_rejected log line and the mitm_attempt meta event — the
// "client failed to accept prox's chain" signal the operator reads.
func TestLadderClientRejectedCarriesError(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)

	caCert, caKey := buildCert(t, "prox-test-ca", nil, nil, true, nil, nil)
	interCert, interKey := buildCert(t, "prox-test-inter", nil, nil, true, caCert, caKey)
	l.Leaves = fakeLeafProvider{cert: leafFor(t, interCert, interKey, "example.com")}

	// The client trusts a different root: the forged leaf fails
	// verification and the client sends a fatal alert.
	otherCA, _ := buildCert(t, "other-ca", nil, nil, true, nil, nil)
	otherPool := x509.NewCertPool()
	otherPool.AddCert(otherCA)

	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })

	client, server := net.Pipe()
	defer server.Close()
	clientErr := make(chan error, 1)
	go func() {
		defer client.Close()
		tlsC := tls.Client(client, &tls.Config{ServerName: "example.com", RootCAs: otherPool})
		clientErr <- tlsC.Handshake()
	}()
	_ = l.Serve(server, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443})
	if err := <-clientErr; err == nil {
		t.Fatal("client handshake unexpectedly succeeded")
	}

	logOut := buf.String()
	var foundLine, foundErr bool
	for _, line := range strings.Split(logOut, "\n") {
		if strings.Contains(line, `"result":"client_rejected"`) {
			foundLine = true
			if strings.Contains(line, `"err":`) {
				foundErr = true
			}
		}
	}
	if !foundLine {
		t.Errorf("log missing client_rejected line:\n%s", logOut)
	}
	if !foundErr {
		t.Errorf("client_rejected log line has no err field:\n%s", logOut)
	}

	meta, err := readAllMeta(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(meta, "\n") {
		if !strings.Contains(line, "client_rejected") {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad meta line %q: %v", line, err)
		}
		got, _ := ev["err"].(string)
		if got == "" {
			t.Fatalf("mitm_attempt client_rejected event has no err: %s", line)
		}
		if !strings.Contains(got, "tls") {
			t.Errorf("mitm_attempt err %q is not the TLS handshake error", got)
		}
		return
	}
	t.Fatalf("meta missing client_rejected mitm_attempt event:\n%s", meta)
}
