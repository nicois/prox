package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

// captureLog redirects the default slog to a buffer (debug level, like the
// existing captured-slog tests) and restores the default on cleanup.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// assertLeafFields pins the presented-leaf fields on one carrier (journal
// line or meta event): the leaf's CN, validity (RFC 3339 UTC), the served
// chain (leaf CN first, the test CA's CN present), the no-SCT state, and a
// non-empty signature algorithm.
func assertLeafFields(t *testing.T, ev map[string]any, where string) {
	t.Helper()
	if got, _ := ev["cn"].(string); got != "example.com" {
		t.Errorf("%s leaf event cn = %q, want example.com", where, got)
	}
	if got, _ := ev["chain"].(string); !strings.HasPrefix(got, "example.com") || !strings.Contains(got, "prox-test-inter") {
		t.Errorf("%s leaf event chain = %q, want the leaf CN first and the test CA's CN present", where, got)
	}
	if got, _ := ev["sct"].(bool); got {
		t.Errorf("%s leaf event sct = true, want false (the test leaf carries no SCT)", where)
	}
	vu, _ := ev["valid_until"].(string)
	if vu == "" {
		t.Fatalf("%s leaf event valid_until is empty", where)
	}
	if !strings.HasSuffix(vu, "Z") {
		t.Errorf("%s leaf event valid_until %q is not RFC 3339 UTC", where, vu)
	}
	if _, err := time.Parse(time.RFC3339, vu); err != nil {
		t.Errorf("%s leaf event valid_until %q is not RFC 3339: %v", where, vu, err)
	}
	if got, _ := ev["sig"].(string); got == "" {
		t.Errorf("%s leaf event sig is empty", where)
	}
}

// TestLeafEventOnClientRejection: a fresh pair whose client does not trust
// the forged leaf must leave a log that shows WHAT was presented, tied to
// the conn: the journal leaf event (with the conn id) and the meta
// leaf_presented event carry the leaf's CN, validity, served chain, SCT
// state and signature — so the rejection is analyzable from the log alone.
func TestLeafEventOnClientRejection(t *testing.T) {
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

	buf := captureLog(t)

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
	var leafLine string
	var rejected bool
	for _, line := range strings.Split(logOut, "\n") {
		if strings.Contains(line, `"msg":"leaf"`) {
			leafLine = line
		}
		if strings.Contains(line, `"result":"client_rejected"`) {
			rejected = true
			if !strings.Contains(line, `"err":`) {
				t.Errorf("client_rejected log line has no err field:\n%s", logOut)
			}
		}
	}
	if !rejected {
		t.Errorf("log missing client_rejected line:\n%s", logOut)
	}
	if leafLine == "" {
		t.Fatalf("journal missing the leaf event:\n%s", logOut)
	}
	var leafEv map[string]any
	if err := json.Unmarshal([]byte(leafLine), &leafEv); err != nil {
		t.Fatalf("bad leaf log line %q: %v", leafLine, err)
	}
	assertLeafFields(t, leafEv, "journal")
	if got, _ := leafEv["host"].(string); got != "example.com" {
		t.Errorf("journal leaf event host = %q, want example.com", got)
	}

	meta, err := readAllMeta(t, dir)
	if err != nil {
		t.Fatal(err)
	}

	// The conn id ties the journal event to the capture record.
	var openID string
	for _, line := range strings.Split(meta, "\n") {
		if !strings.Contains(line, `"type":"conn_open"`) {
			continue
		}
		var open map[string]any
		if err := json.Unmarshal([]byte(line), &open); err != nil {
			t.Fatalf("bad conn_open line %q: %v", line, err)
		}
		openID, _ = open["id"].(string)
	}
	if openID == "" {
		t.Fatalf("meta missing conn_open id:\n%s", meta)
	}
	if got, _ := leafEv["id"].(string); got != openID {
		t.Errorf("journal leaf event id = %q, want the conn id %q", got, openID)
	}

	// Meta: leaf_presented with the same fields, no id (the record has it).
	var foundPresented bool
	for _, line := range strings.Split(meta, "\n") {
		if !strings.Contains(line, `"type":"leaf_presented"`) {
			continue
		}
		foundPresented = true
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad leaf_presented line %q: %v", line, err)
		}
		assertLeafFields(t, ev, "meta")
		if _, ok := ev["id"]; ok {
			t.Errorf("leaf_presented carries an id field; the record id is the capture file's: %s", line)
		}
		// Same fields as the journal event.
		for _, k := range []string{"cn", "valid_until", "chain", "sct", "sig"} {
			if fmt.Sprint(ev[k]) != fmt.Sprint(leafEv[k]) {
				t.Errorf("meta leaf_presented %s = %v, journal leaf %s = %v", k, ev[k], k, leafEv[k])
			}
		}
	}
	if !foundPresented {
		t.Fatalf("meta missing the leaf_presented event:\n%s", meta)
	}
}

// TestLeafEventBeforeMITMSuccess: on the success path the presented-leaf
// event is emitted before the client handshake completes, so it must
// precede the mitm result=success line in the journal.
func TestLeafEventBeforeMITMSuccess(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)

	caCert, caKey := buildCert(t, "prox-test-ca", nil, nil, true, nil, nil)
	interCert, interKey := buildCert(t, "prox-test-inter", nil, nil, true, caCert, caKey)
	l.Leaves = fakeLeafProvider{cert: leafFor(t, interCert, interKey, "example.com")}
	pool := x509.NewCertPool()
	pool.AddCert(interCert)

	buf := captureLog(t)
	if err := tlsClientFlow(t, l, pool, "example.com"); err != nil {
		t.Fatalf("MITM success path: %v", err)
	}

	lines := strings.Split(buf.String(), "\n")
	leafIdx, successIdx := -1, -1
	for i, line := range lines {
		if leafIdx < 0 && strings.Contains(line, `"msg":"leaf"`) {
			leafIdx = i
		}
		if strings.Contains(line, `"result":"success"`) {
			successIdx = i
		}
	}
	if leafIdx < 0 {
		t.Fatalf("journal missing the leaf event:\n%s", buf.String())
	}
	if successIdx < 0 {
		t.Fatalf("journal missing the mitm result=success line:\n%s", buf.String())
	}
	if leafIdx > successIdx {
		t.Errorf("leaf event (line %d) after the mitm success line (line %d); want before", leafIdx, successIdx)
	}
}
