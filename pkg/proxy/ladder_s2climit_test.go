package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/nicois/prox/pkg/capture"
	"github.com/nicois/prox/pkg/hooks"
)

// s2cDrops parses the meta.jsonl of every connection under dataRoot and
// returns the s2c_drop events in file order.
func s2cDrops(t *testing.T, dataRoot string) []map[string]any {
	t.Helper()
	meta, err := readAllMeta(t, dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	var drops []map[string]any
	for _, line := range bytes.Split([]byte(meta), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var ev map[string]any
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		if ev["type"] == "s2c_drop" {
			drops = append(drops, ev)
		}
	}
	return drops
}

// s2cLimitPlainFlow drives one plain flow through l: the scripted upstream
// runs on the relay's upstream connection, and the client writes a request,
// then reads until the flow ends. It returns what the client received.
func s2cLimitPlainFlow(t *testing.T, l *Ladder, upstream func(net.Conn)) []byte {
	t.Helper()
	upl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upl.Close()
	go func() {
		c, err := upl.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		upstream(c)
	}()
	client, server := net.Pipe()
	defer server.Close()
	serveCh := make(chan error, 1)
	go func() { serveCh <- l.Serve(server, upl.Addr()) }()
	gotCh := make(chan []byte, 1)
	go func() {
		defer client.Close()
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		// A net.Pipe end has no CloseWrite, so the relay's s2c half-close
		// cannot EOF the client; end the client leg on a read deadline
		// instead (the scripted upstream finishes well before it).
		_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		var got []byte
		buf := make([]byte, 4096)
		for {
			n, err := client.Read(buf)
			if n > 0 {
				got = append(got, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		gotCh <- got
	}()
	select {
	case err := <-serveCh:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return")
	}
	select {
	case got := <-gotCh:
		return got
	case <-time.After(2 * time.Second):
		t.Fatal("client did not finish reading")
	}
	return nil // unreachable: the timeout branch ends the test
}

// TestLadderS2cLimitPlain: a plain-leg flow with the cap set drops the
// 200-byte chunk (above the limit) whole — still captured — and delivers
// the later 32-byte chunk (within the limit) byte-exact; the drop is
// recorded as s2c_drop with the chunk size, the limit, and the exact
// [start, end) range of the discarded bytes in s2c.bin.
func TestLadderS2cLimitPlain(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.S2cMaxPacket = 64
	payload := bytes.Repeat([]byte{'b'}, 32)
	got := s2cLimitPlainFlow(t, l, func(c net.Conn) {
		_, _ = c.Write(bytes.Repeat([]byte{'a'}, 200))
		// Gap the deliveries: the two writes must reach the relay as two
		// chunks (two upstream read deliveries), not one coalesced one.
		time.Sleep(100 * time.Millisecond)
		_, _ = c.Write(payload)
	})
	if !bytes.Equal(got, payload) {
		t.Fatalf("client got %d bytes (%q...), want exactly the 32-byte within-limit chunk", len(got), got[:min(len(got), 16)])
	}
	drops := s2cDrops(t, dir)
	if len(drops) != 1 {
		t.Fatalf("s2c_drop events = %d, want 1 (the 200-byte chunk above the limit)", len(drops))
	}
	if drops[0]["size"] != float64(200) || drops[0]["limit"] != float64(64) {
		t.Fatalf("s2c_drop = %v, want size 200 and limit 64", drops[0])
	}
	if st, en := drops[0]["start"], drops[0]["end"]; st != float64(0) || en != float64(200) {
		t.Fatalf("s2c_drop = %v, want start 0 and end 200 (the discarded range in s2c.bin)", drops[0])
	}
	_, s2c := readSinkBins(t, dir)
	if len(s2c) != 232 {
		t.Fatalf("s2c.bin = %d bytes, want 232 (dropped chunks are still captured)", len(s2c))
	}
	if got := s2c[0:200]; !bytes.Equal(got, bytes.Repeat([]byte{'a'}, 200)) {
		t.Fatalf("s2c.bin[0:200] != the exact 200 bytes the upstream sent (start/end do not pinpoint the discard)")
	}
	if got := s2c[200:232]; !bytes.Equal(got, payload) {
		t.Fatalf("s2c.bin[200:232] != the 32-byte within-limit chunk delivered to the client")
	}
}

// TestLadderS2cLimitZero: the default (limit 0) forwards every s2c chunk
// and never emits s2c_drop — the byte-identity pin for the default path.
func TestLadderS2cLimitZero(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	payload := bytes.Repeat([]byte{'a'}, 200)
	got := s2cLimitPlainFlow(t, l, func(c net.Conn) {
		_, _ = c.Write(payload)
	})
	if !bytes.Equal(got, payload) {
		t.Fatalf("client got %d bytes, want all 200 (limit 0 forwards everything)", len(got))
	}
	if d := s2cDrops(t, dir); len(d) != 0 {
		t.Fatalf("s2c_drop events = %d, want 0 with the limit unset", len(d))
	}
}

// TestLadderS2cLimitReadOnly: read-only isolation takes precedence over the
// cap — the client receives no s2c bytes (the existing readonly behavior)
// and no s2c_drop event is emitted; the capture still gets everything.
func TestLadderS2cLimitReadOnly(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.IsolationReadOnly = true
	l.S2cMaxPacket = 64
	got := s2cLimitPlainFlow(t, l, func(c net.Conn) {
		_, _ = c.Write(bytes.Repeat([]byte{'a'}, 200))
	})
	if len(got) != 0 {
		t.Fatalf("client got %d bytes under readonly, want 0", len(got))
	}
	if d := s2cDrops(t, dir); len(d) != 0 {
		t.Fatalf("s2c_drop events = %d under readonly, want 0 (the cap is inapplicable)", len(d))
	}
	_, s2c := readSinkBins(t, dir)
	if len(s2c) != 200 {
		t.Fatalf("s2c.bin = %d bytes under readonly, want 200 (capture stays complete)", len(s2c))
	}
}

// TestLadderS2cLimitTLS: a MITM'd TLS flow with the cap set drops the
// large upstream records (one chunk per TLS record, each above the limit)
// and records every drop as s2c_drop with its exact [start, end) range in
// s2c.bin — strictly increasing, disjoint, within the file, and matching
// the size — while the capture still holds the complete decrypted stream.
func TestLadderS2cLimitTLS(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.S2cMaxPacket = 2048
	const sni = "example.com"
	caCert, caKey := buildCert(t, "prox-test-ca", nil, nil, true, nil, nil)
	l.Leaves = fakeLeafProvider{cert: leafFor(t, caCert, caKey, sni)}
	clientPool := x509.NewCertPool()
	clientPool.AddCert(caCert)

	upCert, upKey := buildCert(t, "upstream", []string{sni}, []net.IP{net.ParseIP("127.0.0.1")}, true, nil, nil)
	upPool := x509.NewCertPool()
	upPool.AddCert(upCert)
	l.UpstreamRoots = upPool

	const small, big = 100, 40960
	upl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upl.Close()
	go func() {
		c, err := upl.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tlsS := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{
			{Certificate: [][]byte{upCert.Raw}, PrivateKey: upKey},
		}})
		if err := tlsS.Handshake(); err != nil {
			return
		}
		s := make([]byte, small)
		b := make([]byte, big)
		_, _ = tlsS.Write(s)
		_, _ = tlsS.Write(b)
		_, _ = tlsS.Write(s)
		c.Close()
	}()

	client, server := net.Pipe()
	defer server.Close()
	serveCh := make(chan error, 1)
	go func() { serveCh <- l.Serve(server, upl.Addr()) }()
	// The client's reads may end in an error once the dropped records
	// corrupt the stream; the assertions are on the capture and the
	// events, not on the client's parsing.
	go func() {
		defer client.Close()
		tlsC := tls.Client(client, &tls.Config{ServerName: sni, RootCAs: clientPool})
		if err := tlsC.Handshake(); err != nil {
			return
		}
		buf := make([]byte, 4096)
		for {
			if _, err := tlsC.Read(buf); err != nil {
				return
			}
		}
	}()
	select {
	case err := <-serveCh:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not return")
	}

	drops := s2cDrops(t, dir)
	if len(drops) == 0 {
		t.Fatalf("no s2c_drop events; the %d-byte chunk(s) above the limit must be dropped", big)
	}
	_, s2c := readSinkBins(t, dir)
	if len(s2c) < small+big+small {
		t.Fatalf("s2c.bin = %d bytes, want >= %d (dropped chunks are still captured)", len(s2c), small+big+small)
	}
	var prevEnd float64
	for i, d := range drops {
		if d["limit"] != float64(2048) {
			t.Errorf("drop %d: limit = %v, want 2048", i, d["limit"])
		}
		sz, _ := d["size"].(float64)
		if sz <= 2048 {
			t.Errorf("drop %d: size = %v, want > 2048 (only above-limit chunks drop)", i, d["size"])
		}
		st, ok1 := d["start"].(float64)
		en, ok2 := d["end"].(float64)
		if !ok1 || !ok2 {
			t.Fatalf("drop %d: missing start/end offsets: %v", i, d)
		}
		if st < prevEnd || st >= en || en > float64(len(s2c)) {
			t.Errorf("drop %d: range [%v,%v) is not strictly increasing/disjoint or escapes s2c.bin (len %d)", i, st, en, len(s2c))
		}
		if en-st != sz {
			t.Errorf("drop %d: end-start = %v, want size %v", i, en-st, sz)
		}
		prevEnd = en
	}
}

//  1. Over-cap relay chunk: nothing on the wire, one Dropped record.
//     Harness: newLadder + s2cLimitPlainFlow (ladder_s2climit_test.go).
func TestS2cCapLossRecordedOnStream(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.S2cMaxPacket = 64
	l.Capture = capture.NewRegistry()
	var st *capture.Stream
	l.Capture.OnConnection(func(s *capture.Stream) { st = s })
	hp := hooks.NewPipeline()
	hp.Register(&hooky{dataSeen: map[hooks.Dir]int{}}) // pass-through (mut == nil)
	l.Hooks = hp

	got := s2cLimitPlainFlow(t, l, func(c net.Conn) {
		_, _ = c.Write(bytes.Repeat([]byte{'a'}, 200))
	})
	if len(got) != 0 {
		t.Fatalf("client got %d bytes, want 0 (the 200-byte chunk is above the limit)", len(got))
	}
	found := false
	for _, c := range st.Chunks() {
		if c.Decision == capture.Dropped && c.Reason == "s2c_max_packet" && c.Len == 200 {
			found = true
		}
	}
	if !found {
		t.Fatalf("no cap-loss record on stream: %+v", st.Chunks())
	}
}

//  2. A held 200-byte chunk released under cap 64 passes through the cap:
//     the wire gets only the later 32-byte chunk; the stream records
//     Held(200) + Dropped(200, s2c_max_packet) — never Forwarded(200).
//     hooky (ladder_hooks_test.go) carries its HookConn (hc) for this test.
func TestReleaseCapLossRecordedNotForwarded(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.S2cMaxPacket = 64
	l.Capture = capture.NewRegistry()
	var st *capture.Stream
	l.Capture.OnConnection(func(s *capture.Stream) { st = s })

	h := &hooky{dataSeen: map[hooks.Dir]int{}}
	var held bool
	h.mut = func(dir hooks.Dir, data []byte) hooks.Result {
		if dir != hooks.DirS2C {
			return hooks.Result{}
		}
		if held {
			h.hc.ReleaseS2C() // flush the held 200B chunk through the cap
			held = false
			return hooks.Result{} // the 32B chunk passes (within the limit)
		}
		held = true
		return hooks.Result{Hold: true, Reason: "fw"}
	}
	hp := hooks.NewPipeline()
	hp.Register(h)
	l.Hooks = hp

	got := s2cLimitPlainFlow(t, l, func(c net.Conn) {
		_, _ = c.Write(bytes.Repeat([]byte{'a'}, 200))
		time.Sleep(100 * time.Millisecond)
		_, _ = c.Write(bytes.Repeat([]byte{'b'}, 32))
	})
	if !bytes.Equal(got, bytes.Repeat([]byte{'b'}, 32)) {
		t.Fatalf("client got %d bytes, want exactly the 32-byte within-limit chunk", len(got))
	}
	var heldRec, capRec, fwdRec int
	for _, c := range st.Chunks() {
		switch {
		case c.Decision == capture.Held && c.Len == 200:
			heldRec++
		case c.Decision == capture.Dropped && c.Reason == "s2c_max_packet" && c.Len == 200:
			capRec++
		case c.Decision == capture.Forwarded && c.Len == 200:
			fwdRec++
		}
	}
	if heldRec != 1 || capRec != 1 || fwdRec != 0 {
		t.Fatalf("records Held=%d capDropped=%d forward200=%d, want 1/1/0: %+v",
			heldRec, capRec, fwdRec, st.Chunks())
	}
}

//  3. No hooks at all (l.Hooks == nil): the stream still records the
//     Dropped/s2c_max_packet chunk (the stream mirrors the s2c_drop event
//     even without a hook chain).
func TestS2cCapLossRecordedWithoutHooks(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.S2cMaxPacket = 64
	l.Capture = capture.NewRegistry()
	var st *capture.Stream
	l.Capture.OnConnection(func(s *capture.Stream) { st = s })

	got := s2cLimitPlainFlow(t, l, func(c net.Conn) {
		_, _ = c.Write(bytes.Repeat([]byte{'a'}, 200))
	})
	if len(got) != 0 {
		t.Fatalf("client got %d bytes, want 0", len(got))
	}
	cs := st.Chunks()
	if len(cs) != 1 || cs[0].Decision != capture.Dropped ||
		cs[0].Reason != "s2c_max_packet" || cs[0].Len != 200 {
		t.Fatalf("records = %+v, want exactly one Dropped/s2c_max_packet/200", cs)
	}
}

// 4. G2: with byte capture enabled on the registry, the cap-loss
// Dropped record carries the exact dropped bytes as Payload.
func TestS2cCapLossPayload(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	l.S2cMaxPacket = 64
	l.Capture = capture.NewRegistry()
	l.Capture.EnableBytes()
	var st *capture.Stream
	l.Capture.OnConnection(func(s *capture.Stream) { st = s })
	hp := hooks.NewPipeline()
	hp.Register(&hooky{dataSeen: map[hooks.Dir]int{}}) // pass-through (mut == nil)
	l.Hooks = hp

	want := bytes.Repeat([]byte{'a'}, 200)
	got := s2cLimitPlainFlow(t, l, func(c net.Conn) {
		_, _ = c.Write(want)
	})
	if len(got) != 0 {
		t.Fatalf("client got %d bytes, want 0 (the 200-byte chunk is above the limit)", len(got))
	}
	found := false
	for _, c := range st.Chunks() {
		if c.Decision == capture.Dropped && c.Reason == "s2c_max_packet" && c.Len == 200 {
			found = true
			if !bytes.Equal(c.Payload, want) {
				t.Fatalf("cap-loss Payload = %d bytes, want the exact 200 dropped bytes", len(c.Payload))
			}
		}
	}
	if !found {
		t.Fatalf("no cap-loss record on stream: %+v", st.Chunks())
	}
}
