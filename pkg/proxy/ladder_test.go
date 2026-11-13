package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicois/prox/pkg/capture"
	"github.com/nicois/prox/pkg/hooks"
	"github.com/nicois/prox/pkg/sink"
	"github.com/nicois/prox/pkg/sniff"
	"github.com/nicois/prox/pkg/store"
	"github.com/nicois/prox/pkg/tlsutil"
)

// fakeLeafProvider returns a fixed certificate for every host.
type fakeLeafProvider struct{ cert *tls.Certificate }

func (f fakeLeafProvider) Leaf(host, dst string, now time.Time) (*tls.Certificate, error) {
	return f.cert, nil
}

func newLadder(t *testing.T, dataRoot string) *Ladder {
	t.Helper()
	return &Ladder{
		Sink:             func(dr, id string, mb int64) (*sink.Conn, error) { return sink.Open(dr, id, mb, 0o644, 0o755) },
		DataRoot:         dataRoot,
		MaxPeek:          sniff.MaxPeek,
		MaxBytes:         256 << 20,
		HandshakeTimeout: 30 * time.Second,
	}
}

func TestLadderPlainHTTP(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)

	// Fake upstream: echo server on a real loopback port. The ladder
	// dials origDst, so the upstream must be a reachable address.
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	const req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		defer clientConn.Close()
		if _, err := clientConn.Write([]byte(req)); err != nil {
			return
		}
		// The upstream echoes; the echo must be the request verbatim.
		buf := make([]byte, len(req))
		if _, err := io.ReadFull(clientConn, buf); err != nil {
			return
		}
		if string(buf) != req {
			t.Errorf("upstream echo = %q, want the request verbatim", buf)
		}
	}()

	if err := l.Serve(serverConn, up.Addr()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	// The sink recorded the connection lifecycle.
	meta, err := readAllMeta(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"conn_open"`, `"conn_close"`} {
		if !strings.Contains(meta, want) {
			t.Errorf("meta missing %s: %s", want, meta)
		}
	}
}

func TestLadderTLSMitm(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)

	// Root CA + intermediate; the provider mints the leaf from the brief's
	// MintLeaf so the client chain is CA <- intermediate <- leaf.
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

	// Upstream TLS server with its own self-signed cert.
	upCert, upKey := buildCert(t, "upstream", []string{"example.com"}, []net.IP{net.ParseIP("127.0.0.1")}, true, nil, nil)
	upPool := x509.NewCertPool()
	upPool.AddCert(upCert)
	l.UpstreamRoots = upPool

	upl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upl.Close()
	got := make(chan string, 1)
	go func() {
		for {
			c, err := upl.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				tlsC := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{upCert.Raw}, PrivateKey: upKey}}})
				if err := tlsC.Handshake(); err != nil {
					return
				}
				buf := make([]byte, 256)
				n, _ := tlsC.Read(buf)
				if n > 0 {
					got <- string(buf[:n])
					tlsC.Write(buf[:n])
				}
				tlsC.Close()
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
		if _, err := tc.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
			t.Errorf("client write: %v", err)
			return
		}
		buf := make([]byte, 256)
		tc.Read(buf)
	}()

	if err := l.Serve(serverConn, upl.Addr()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	select {
	case line := <-got:
		if !strings.HasPrefix(line, "GET / HTTP/1.1") {
			t.Fatalf("upstream got %q, want the decrypted request", line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("upstream never received the decrypted request")
	}
	meta, err := readAllMeta(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(meta, `"mitm_attempt"`) || !strings.Contains(meta, `"success"`) {
		t.Errorf("meta missing mitm_attempt success: %s", meta)
	}
}

// TestLadderTLSNoSNI: a client that sends no SNI (embedded TLS stacks
// connecting by IP only) must still complete the MITM: the leaf falls
// back to the destination identity and the upstream leg verifies against
// the destination IP (IP SAN).
func TestLadderTLSNoSNI(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)

	caCert, caKey := buildCert(t, "prox-test-ca", nil, nil, true, nil, nil)
	interCert, interKey := buildCert(t, "prox-test-inter", nil, nil, true, caCert, caKey)
	now := time.Now()
	leafTmpl, _, err := tlsutil.MintLeaf(interCert, interKey, "", "127.0.0.1", now.Add(-time.Hour), now.Add(24*time.Hour))
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

	// Upstream self-signed cert whose IP SAN matches the listen address;
	// the no-SNI leg must verify against exactly that.
	upCert, upKey := buildCert(t, "upstream", nil, []net.IP{net.ParseIP("127.0.0.1")}, true, nil, nil)
	upPool := x509.NewCertPool()
	upPool.AddCert(upCert)
	l.UpstreamRoots = upPool

	upl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upl.Close()
	got := make(chan string, 1)
	go func() {
		for {
			c, err := upl.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				tlsC := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{upCert.Raw}, PrivateKey: upKey}}})
				if err := tlsC.Handshake(); err != nil {
					return
				}
				buf := make([]byte, 256)
				n, _ := tlsC.Read(buf)
				if n > 0 {
					got <- string(buf[:n])
				}
				tlsC.Close()
			}(c)
		}
	}()

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		defer clientConn.Close()
		// No SNI: empty ServerName; the client accepts whatever identity
		// the forged leaf claims.
		tc := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})
		if err := tc.Handshake(); err != nil {
			t.Errorf("client handshake: %v", err)
			return
		}
		tc.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	}()

	if err := l.Serve(serverConn, upl.Addr()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	select {
	case line := <-got:
		if !strings.HasPrefix(line, "GET / HTTP/1.1") {
			t.Fatalf("upstream got %q, want the decrypted request", line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("upstream never received the decrypted request")
	}
}

func TestLadderUpstreamMTLS(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	s, err := store.Open(dir + "/index.db")
	if err != nil {
		t.Fatal(err)
	}
	l.Store = s

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
	// The pair is now patched with reason mtls (advance Recheck's explicit
	// now past the interval).
	pairs, err := s.Recheck(time.Now().Add(721*time.Hour), 720*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 1 || pairs[0].Reason != "mtls" {
		t.Fatalf("patched pairs = %+v, want one mtls pair", pairs)
	}
}

func buildCert(t *testing.T, cn string, dns []string, ips []net.IP, isCA bool, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              dns,
		IPAddresses:           ips,
	}
	var signer crypto.Signer = priv
	parentCert := tmpl
	if parent != nil {
		signer, parentCert = parentKey, parent
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, priv.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv
}

func readAllMeta(t *testing.T, dataRoot string) (string, error) {
	t.Helper()
	day := time.Now().Format("20060102")
	entries, err := os.ReadDir(filepath.Join(dataRoot, "conns", day))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dataRoot, "conns", day, e.Name(), "meta.jsonl"))
		if err != nil {
			return "", err
		}
		b.Write(data)
	}
	return b.String(), nil
}

type tlsResultHook struct {
	res    chan hooks.TLSResult
	closes []string
}

func (h *tlsResultHook) Filter() hooks.Match { return hooks.Match{} }
func (h *tlsResultHook) OnOpen(c *hooks.Conn, hc *hooks.HookConn) hooks.Result {
	return hooks.Result{}
}
func (h *tlsResultHook) OnData(c *hooks.Conn, dir hooks.Dir, data []byte) hooks.Result {
	return hooks.Result{}
}
func (h *tlsResultHook) OnClose(c *hooks.Conn, reason string) {
	h.closes = append(h.closes, reason)
}
func (h *tlsResultHook) OnTLSResult(c *hooks.Conn, r hooks.TLSResult) {
	h.res <- r
}

// TestLadderTLSResultSuccess: a completing client leg reports success with
// the negotiated version, and the close reason stays clean.
func TestLadderTLSResultSuccess(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
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
	upCert, upKey := buildCert(t, "upstream", []string{"example.com"}, []net.IP{net.ParseIP("127.0.0.1")}, true, nil, nil)
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
				tlsC := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{upCert.Raw}, PrivateKey: upKey}}})
				if err := tlsC.Handshake(); err != nil {
					return
				}
				buf := make([]byte, 256)
				if n, _ := tlsC.Read(buf); n > 0 {
					tlsC.Write(buf[:n])
				}
				tlsC.Close()
			}(c)
		}
	}()

	obs := &tlsResultHook{res: make(chan hooks.TLSResult, 1)}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(obs)

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
		buf := make([]byte, 256)
		tc.Read(buf)
	}()
	if err := l.Serve(serverConn, upl.Addr()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	select {
	case r := <-obs.res:
		if r.Result != "success" || r.Host != "example.com" || r.Version < uint16(tls.VersionTLS12) {
			t.Errorf("TLSResult = %+v, want success/example.com/TLS>=1.2", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("observer never got the TLS result")
	}
	if len(obs.closes) != 1 || obs.closes[0] != "" {
		t.Errorf("OnClose reasons = %v, want one clean close", obs.closes)
	}
}

// TestLadderTLSResultRejected: a client that does not trust the forged leaf
// reports client_rejected (version 0), and the close reason names it.
func TestLadderTLSResultRejected(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
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

	obs := &tlsResultHook{res: make(chan hooks.TLSResult, 1)}
	l.Hooks = hooks.NewPipeline()
	l.Hooks.Register(obs)

	// The client trusts a different CA, so it rejects the forged leaf.
	other, _ := buildCert(t, "other-ca", nil, nil, true, nil, nil)
	caPool := x509.NewCertPool()
	caPool.AddCert(other)
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		defer clientConn.Close()
		tc := tls.Client(clientConn, &tls.Config{RootCAs: caPool, ServerName: "example.com"})
		tc.Handshake() // expected to fail
	}()
	if err := l.Serve(serverConn, &net.TCPAddr{}); err == nil {
		t.Fatal("Serve: want the client-rejection error")
	}
	select {
	case r := <-obs.res:
		if r.Result != "client_rejected" || r.Version != 0 || r.Host != "example.com" {
			t.Errorf("TLSResult = %+v, want client_rejected/0/example.com", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("observer never got the TLS result")
	}
	if len(obs.closes) != 1 || obs.closes[0] != "client_rejected" {
		t.Errorf("OnClose reasons = %v, want [client_rejected]", obs.closes)
	}
}

// TestLadderTLSResultNoHooks: with no hook registered, a completing
// client leg still lands the TLS outcome in the capture record.
func TestLadderTLSResultNoHooks(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.Capture = capture.NewRegistry()
	var streams []*capture.Stream
	l.Capture.OnConnection(func(st *capture.Stream) {
		streams = append(streams, st)
	})
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
	upCert, upKey := buildCert(t, "upstream", []string{"example.com"}, []net.IP{net.ParseIP("127.0.0.1")}, true, nil, nil)
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
				tlsC := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{upCert.Raw}, PrivateKey: upKey}}})
				if err := tlsC.Handshake(); err != nil {
					return
				}
				buf := make([]byte, 256)
				if n, _ := tlsC.Read(buf); n > 0 {
					tlsC.Write(buf[:n])
				}
				tlsC.Close()
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
		buf := make([]byte, 256)
		tc.Read(buf)
	}()
	if err := l.Serve(serverConn, upl.Addr()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if len(streams) != 1 {
		t.Fatalf("streams = %d, want 1", len(streams))
	}
	info := streams[0].Info()
	if info.TLS == nil || info.TLS.Result != "success" || info.TLS.Host != "example.com" || info.TLS.Version < uint16(tls.VersionTLS12) {
		t.Fatalf("record TLS = %+v, want success/example.com/TLS>=1.2", info.TLS)
	}
}
