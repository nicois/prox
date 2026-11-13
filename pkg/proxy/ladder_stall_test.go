package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// captureClientHello returns a syntactically valid ClientHello record for
// serverName (5-byte TLS record header + payload). A throwaway tls.Client
// runs its handshake on one end of a net.Pipe; the record is read from the
// other end before the flight the client never receives. Closing the pipes
// ends the blocked client.
func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	defer serverEnd.Close()
	go func() {
		tc := tls.Client(clientEnd, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
		})
		_ = tc.Handshake() // blocks waiting for the flight; the record is already out
	}()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(serverEnd, hdr); err != nil {
		t.Fatalf("read ClientHello header: %v", err)
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	body := make([]byte, n)
	if _, err := io.ReadFull(serverEnd, body); err != nil {
		t.Fatalf("read ClientHello payload: %v", err)
	}
	rec := make([]byte, 0, 5+n)
	rec = append(rec, hdr...)
	return append(rec, body...)
}

// TestLadderHandshakeStallNoPatch: a client that sends a valid ClientHello
// and then stalls (keeps the connection open, never reads the flight,
// never sends Finished) holds the client-leg handshake open until
// HandshakeTimeout. A stalled client is not evidence the client rejected
// the forged chain — the (ip, host) pair must not be marked patched, but
// the meta journal records client_rejected with the deadline error.
func TestLadderHandshakeStallNoPatch(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.HandshakeTimeout = 250 * time.Millisecond
	st, err := newTestStore(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	l.Store = st
	caCert, caKey := buildCert(t, "prox-test-ca", nil, nil, true, nil, nil)
	l.Leaves = fakeLeafProvider{cert: leafFor(t, caCert, caKey, "example.com")}

	const dstIP = "192.0.2.1"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serveErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serveErr <- err
			return
		}
		defer conn.Close()
		serveErr <- l.Serve(conn, &net.TCPAddr{IP: net.ParseIP(dstIP), Port: 443})
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write(captureClientHello(t, "example.com")); err != nil {
		t.Fatal(err)
	}
	// Hold the connection open and never read: the server's flight stays
	// buffered in the kernel and the server waits for Finished until the
	// handshake timeout fires.
	var errSrv error
	select {
	case errSrv = <-serveErr:
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after the handshake timeout")
	}
	if errSrv == nil {
		t.Fatal("Serve: want the handshake timeout error")
	}
	if !errors.Is(errSrv, context.DeadlineExceeded) {
		t.Fatalf("Serve err = %v; want the handshake deadline", errSrv)
	}

	patched, err := st.IsPatch(dstIP, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if patched {
		t.Errorf("stalled handshake marked (%s, example.com) patched; want no row", dstIP)
	}

	meta, err := readAllMeta(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, line := range strings.Split(meta, "\n") {
		var ev map[string]any
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		if ev["type"] != "mitm_attempt" || ev["result"] != "client_rejected" {
			continue
		}
		found = true
		errStr, _ := ev["err"].(string)
		if !strings.Contains(errStr, "deadline") {
			t.Errorf("mitm_attempt err = %q; want the deadline error", errStr)
		}
	}
	if !found {
		t.Errorf("meta missing mitm_attempt client_rejected: %s", meta)
	}
}

// TestLadderImmediateRejectStillPatches: the control — a client that
// promptly rejects the forged chain (unknown authority) still marks the
// pair patched. Only the handshake-timeout path skips the mark.
func TestLadderImmediateRejectStillPatches(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	st, err := newTestStore(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	l.Store = st
	caCert, caKey := buildCert(t, "prox-test-ca", nil, nil, true, nil, nil)
	l.Leaves = fakeLeafProvider{cert: leafFor(t, caCert, caKey, "example.com")}

	// The client trusts a different CA, so it rejects the forged leaf.
	other, _ := buildCert(t, "other-ca", nil, nil, true, nil, nil)
	caPool := x509.NewCertPool()
	caPool.AddCert(other)

	client, server := net.Pipe()
	defer server.Close()
	go func() {
		defer client.Close()
		tc := tls.Client(client, &tls.Config{RootCAs: caPool, ServerName: "example.com"})
		_ = tc.Handshake() // expected to fail promptly
	}()
	if err := l.Serve(server, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}); err == nil {
		t.Fatal("Serve: want the client-rejection error")
	}

	patched, err := st.IsPatch("192.0.2.1", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !patched {
		t.Error("immediate client rejection did not mark (192.0.2.1, example.com) patched")
	}
}
