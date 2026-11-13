package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nicois/prox/pkg/store"
	"github.com/nicois/prox/pkg/tlsutil"
)

// TestLadderDecisionLogs pins the operator-visible slog events for the three
// connection verdicts: plain relay, MITM success, and the patched drop
// (the tunnel is opt-in via TunnelFallback and pinned in
// TestLadderPatchedTunnelOptIn).
func TestLadderDecisionLogs(t *testing.T) {
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

	// Plain echo upstream for the relay scenario.
	plainUp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plainUp.Close()
	go func() {
		for {
			c, err := plainUp.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				for {
					n, rerr := c.Read(buf)
					if n > 0 {
						c.Write(buf[:n])
					}
					if rerr != nil {
						return
					}
				}
			}(c)
		}
	}()

	// TLS upstream with its own self-signed cert.
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
				n, _ := tlsC.Read(buf)
				if n > 0 {
					tlsC.Write(buf[:n])
				}
				tlsC.Close()
			}(c)
		}
	}()

	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	caPool.AddCert(interCert)

	// 1. Plain HTTP relay.
	{
		clientConn, serverConn := net.Pipe()
		go func() {
			defer clientConn.Close()
			const req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
			clientConn.Write([]byte(req))
			out := make([]byte, len(req))
			if _, err := io.ReadFull(clientConn, out); err != nil {
				return
			}
			if string(out) != req {
				t.Errorf("echo = %q, want the request verbatim", out)
			}
		}()
		if err := l.Serve(serverConn, plainUp.Addr()); err != nil {
			t.Fatalf("Serve plain: %v", err)
		}
	}

	// 2. TLS MITM success (unmarked pair): the client trusts the
	// compromised intermediate, so the forged leaf verifies.
	{
		clientConn, serverConn := net.Pipe()
		go func() {
			defer clientConn.Close()
			tc := tls.Client(clientConn, &tls.Config{RootCAs: caPool, ServerName: "example.com"})
			if err := tc.Handshake(); err != nil {
				t.Errorf("client handshake: %v", err)
				return
			}
			tc.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
			out := make([]byte, 256)
			tc.Read(out)
		}()
		if err := l.Serve(serverConn, upl.Addr()); err != nil {
			t.Fatalf("Serve tls: %v", err)
		}
	}

	// 3. Patched pair is dropped by default: the stored rejection reason
	// is logged and the connection closed (no tunnel without the
	// TunnelFallback opt-in).
	st, err := store.Open(dir + "/index.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkPatch("127.0.0.1", "example.com", "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	l.Store = st
	{
		clientConn, serverConn := net.Pipe()
		go func() {
			defer clientConn.Close()
			tc := tls.Client(clientConn, &tls.Config{RootCAs: caPool, ServerName: "example.com"})
			if err := tc.Handshake(); err == nil {
				t.Error("dropped patched pair completed the client handshake")
			}
		}()
		if err := l.Serve(serverConn, upl.Addr()); err == nil {
			t.Fatal("Serve: the drop path must return an error that closes the conn")
		}
	}

	out := buf.String()
	for _, want := range []string{
		`"msg":"relay"`, `"kind":"plain"`,
		`"msg":"mitm"`, `"result":"success"`,
		`"result":"patched_drop"`, `"reason":"test"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %s:\n%s", want, out)
		}
	}
}
