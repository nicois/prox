package proxy

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"
)

// metaEvents parses the meta.jsonl of every connection under dataRoot and
// returns the events of the given type in file order.
func metaEvents(t *testing.T, dataRoot, typ string) []map[string]any {
	t.Helper()
	meta, err := readAllMeta(t, dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	var evs []map[string]any
	for _, line := range bytes.Split([]byte(meta), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var ev map[string]any
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		if ev["type"] == typ {
			evs = append(evs, ev)
		}
	}
	return evs
}

// TestLadderS2cPerWriteByteRanges: without the cap, every write to s2c.bin
// journals a bytes_s2c event for that write's [start,end) range — the two
// upstream deliveries here are two writes, cumulative — and the close
// summary remains the final bytes_s2c event. bytes_c2s stays a single
// per-flow event.
func TestLadderS2cPerWriteByteRanges(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	got := s2cLimitPlainFlow(t, l, func(c net.Conn) {
		_, _ = c.Write(bytes.Repeat([]byte{'a'}, 200))
		// Gap the deliveries: the two writes must reach the relay as two
		// chunks (two upstream read deliveries), not one coalesced one.
		time.Sleep(100 * time.Millisecond)
		_, _ = c.Write(bytes.Repeat([]byte{'b'}, 32))
	})
	if len(got) != 232 {
		t.Fatalf("client got %d bytes, want 232", len(got))
	}
	evs := metaEvents(t, dir, "bytes_s2c")
	if len(evs) != 3 {
		t.Fatalf("bytes_s2c events = %d, want 3 (per-write x2 + close summary last): %v", len(evs), evs)
	}
	want := []struct{ start, end int64 }{
		{0, 200},
		{200, 232},
		{0, 232}, // close summary, last
	}
	for i, w := range want {
		if evs[i]["start"] != float64(w.start) || evs[i]["end"] != float64(w.end) {
			t.Errorf("bytes_s2c[%d] = {start:%v end:%v}, want {start:%d end:%d}", i, evs[i]["start"], evs[i]["end"], w.start, w.end)
		}
	}
	if c2s := metaEvents(t, dir, "bytes_c2s"); len(c2s) != 1 {
		t.Errorf("bytes_c2s events = %d, want 1", len(c2s))
	}
}

// TestRangeTeeOnRangeSkipsZeroWidth: after the sink's per-connection cap
// is hit, WriteS2C returns a frozen (off, off) range — a successful no-op.
// rangeTee must not fire onRange for such zero-width writes; nonzero
// writes still fire, and Range (the close summary's source) is unchanged
// by the no-op.
func TestRangeTeeOnRangeSkipsZeroWidth(t *testing.T) {
	var calls [][2]int64
	tee := &rangeTee{
		fn: func(b []byte) (int64, int64, error) {
			if len(b) == 4 {
				return 0, 4, nil
			}
			return 4, 4, nil // the sink cap no-op
		},
		onRange: func(st, en int64) { calls = append(calls, [2]int64{st, en}) },
	}
	if _, err := tee.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	if _, err := tee.Write([]byte("past the cap")); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != [2]int64{0, 4} {
		t.Fatalf("onRange calls = %v, want exactly [{0 4}] (zero-width write skipped)", calls)
	}
	if st, en := tee.Range(); st != 0 || en != 4 {
		t.Fatalf("Range() = %d..%d, want 0..4 (unchanged by the no-op)", st, en)
	}
}

// TestLadderS2cPerWriteCapSkipsZeroWidth: once the sink's per-connection
// byte cap is hit, further s2c writes are frozen no-ops; the meta journal
// then holds only per-write events for the bytes actually captured before
// the cap — never zero-width ones — plus the close summary and conn_close:
// meta.jsonl is exempt from the byte cap and keeps being journaled after
// the cap (the pre-existing meta freeze is gone).
func TestLadderS2cPerWriteCapSkipsZeroWidth(t *testing.T) {
	dir := t.TempDir()
	l := newLadder(t, dir)
	// The per-connection cap is shared by both directions; 27 fits the
	// 27-byte request exactly, so only the s2c data overflows it.
	l.MaxBytes = 27
	got := s2cLimitPlainFlow(t, l, func(c net.Conn) {
		_, _ = c.Write(bytes.Repeat([]byte{'a'}, 4))
		time.Sleep(100 * time.Millisecond)
		_, _ = c.Write(bytes.Repeat([]byte{'b'}, 28))
	})
	// The sink cap affects capture only; the client still receives all bytes.
	if len(got) != 32 {
		t.Fatalf("client got %d bytes, want 32", len(got))
	}
	evs := metaEvents(t, dir, "bytes_s2c")
	for i, ev := range evs {
		if st, en := ev["start"], ev["end"]; st == nil || en == nil || st.(float64) >= en.(float64) {
			t.Fatalf("bytes_s2c[%d] = %v is zero-width, want start < end", i, ev)
		}
	}
	// The per-write event for the 4 bytes captured before the cap, then the
	// close summary — the same range, since only 4 bytes were captured.
	// The capped no-op journals no per-write event, and the close summary
	// and conn_close are journaled after the cap: meta is exempt from the
	// byte cap.
	if len(evs) != 2 {
		t.Fatalf("bytes_s2c events = %d, want 2 (per-write + close summary): %v", len(evs), evs)
	}
	for i, ev := range evs {
		if ev["start"] != float64(0) || ev["end"] != float64(4) {
			t.Errorf("bytes_s2c[%d] = {start:%v end:%v}, want {start:0 end:4}", i, ev["start"], ev["end"])
		}
	}
	c2s := metaEvents(t, dir, "bytes_c2s")
	if len(c2s) != 1 {
		t.Fatalf("bytes_c2s events = %d, want 1: %v", len(c2s), c2s)
	}
	if c2s[0]["start"] != float64(0) || c2s[0]["end"] != float64(27) {
		t.Errorf("bytes_c2s = {start:%v end:%v}, want {start:0 end:27}", c2s[0]["start"], c2s[0]["end"])
	}
	if closes := metaEvents(t, dir, "conn_close"); len(closes) != 1 {
		t.Fatalf("conn_close events = %d, want 1", len(closes))
	}
}
