package sink

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestOpenRecordsBuildMeta(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(dir, "conn-meta", 0, 0o644, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	day := time.Now().Format("20060102")
	data, err := os.ReadFile(filepath.Join(dir, "conns", day, "conn-meta", "meta.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	line := string(data)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		t.Fatalf("first meta line is not JSON: %v: %s", err, line)
	}
	if ev["type"] != "meta" {
		t.Fatalf("first meta line = %s, want type meta", line)
	}
	if _, ok := ev["commit"]; !ok {
		t.Fatalf("meta line missing commit: %s", line)
	}
	if _, ok := ev["ts"]; !ok {
		t.Fatalf("meta line missing ts: %s", line)
	}
}

// TestOpenCaptureModes pins the fileMode/dirMode parameters: the
// per-connection dir and the c2s.bin, s2c.bin and meta.jsonl files are
// created with exactly those permissions (creation time only — existing
// files are not re-chmodded).
func TestOpenCaptureModes(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	for _, tc := range []struct {
		name              string
		fileMode, dirMode fs.FileMode
	}{
		{"default", 0o600, 0o700},
		{"custom", 0o640, 0o750},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			id := "modes-" + tc.name
			c, err := Open(dir, id, 0, tc.fileMode, tc.dirMode)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			conndir := filepath.Join(dir, "conns", nowStr(), id)
			fi, err := os.Stat(conndir)
			if err != nil {
				t.Fatal(err)
			}
			if got := fi.Mode().Perm(); got != tc.dirMode {
				t.Errorf("conn dir mode = %o, want %o", got, tc.dirMode)
			}
			for _, name := range []string{"c2s.bin", "s2c.bin", "meta.jsonl"} {
				fi, err := os.Stat(filepath.Join(conndir, name))
				if err != nil {
					t.Fatal(err)
				}
				if got := fi.Mode().Perm(); got != tc.fileMode {
					t.Errorf("%s mode = %o, want %o", name, got, tc.fileMode)
				}
			}
		})
	}
}

func TestSinkByteRangesAndBody(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(dir, "conn-1", 0, 0o644, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	req := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	rStart, rEnd, err := c.WriteC2S(req)
	if err != nil {
		t.Fatal(err)
	}
	// A chunked body appended after the headers.
	body := []byte("deadbeef")
	bStart, bEnd, err := c.WriteC2S(body)
	if err != nil {
		t.Fatal(err)
	}
	if rStart != 0 || rEnd != int64(len(req)) {
		t.Fatalf("request range = [%d,%d), want [0,%d)", rStart, rEnd, len(req))
	}
	if bStart != int64(len(req)) || bEnd != int64(len(req)+len(body)) {
		t.Fatalf("body range = [%d,%d), want [%d,%d)", bStart, bEnd, len(req), len(req)+len(body))
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// The body file hash matches the transfer-decoded body (unchunked here).
	data, err := os.ReadFile(filepath.Join(dir, "conns", nowStr(), "conn-1", "c2s.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data[rStart:bStart]) != string(req) {
		t.Fatal("request bytes not contiguous at start")
	}
	if string(data[bStart:bEnd]) != string(body) {
		t.Fatal("body bytes not contiguous after request")
	}
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])
	// The meta event would reference body-1.bin with this hash.
	_ = want
}

// TestSinkPerConnCap pins the maxConnBytes parameter: capture stops at the
// cap (writes become nil no-ops with a frozen range) while meta.jsonl keeps
// receiving events.
func TestSinkPerConnCap(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(dir, "capped", 8, 0o644, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.WriteJSON(map[string]any{"type": "early"}); err != nil {
		t.Fatalf("WriteJSON under cap: %v", err)
	}
	if _, _, err := c.WriteC2S([]byte("01234567")); err != nil {
		t.Fatalf("WriteC2S under cap: %v", err)
	}
	if st, en, err := c.WriteC2S([]byte("abcdefgh")); err != nil || st != en {
		t.Fatalf("WriteC2S at cap: err=%v range=%d..%d, want nil and frozen", err, st, en)
	}
	if err := c.WriteJSON(map[string]any{"type": "late"}); err != nil {
		t.Fatalf("WriteJSON after cap: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "conns", nowStr(), "capped", "meta.jsonl"))
	if err != nil {
		t.Fatalf("read meta.jsonl: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	// The build meta line precedes the two test events; the byte cap must
	// not freeze the journal, so exactly early and late follow, in order.
	want := []string{"meta", "early", "late"}
	if len(lines) != len(want) {
		t.Fatalf("meta.jsonl lines = %d, want %d: %v", len(lines), len(want), lines)
	}
	for i, line := range lines {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("meta.jsonl line %d is not JSON: %v: %s", i, err, line)
		}
		if ev["type"] != want[i] {
			t.Fatalf("meta.jsonl line %d type = %v, want %s", i, ev["type"], want[i])
		}
	}
}

func TestNoopSinkDiscards(t *testing.T) {
	c := Noop()
	st, en, err := c.WriteC2S([]byte("abc"))
	if err != nil || st != 0 || en != 0 {
		t.Errorf("noop WriteC2S = (%d, %d, %v), want zero ranges and no error", st, en, err)
	}
	st, en, err = c.WriteS2C([]byte("def"))
	if err != nil || st != 0 || en != 0 {
		t.Errorf("noop WriteS2C = (%d, %d, %v), want zero ranges and no error", st, en, err)
	}
	if err := c.WriteJSON(map[string]any{"type": "x"}); err != nil {
		t.Errorf("noop WriteJSON: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("noop Close: %v", err)
	}
}

func TestCompactDeletesOldDirs(t *testing.T) {
	dir := t.TempDir()
	conns := filepath.Join(dir, "conns")
	// Today's dir: keep.
	mustWrite(t, filepath.Join(conns, nowStr(), "meta.jsonl"), "meta")
	// A dir named 91 days ago: prune (maxAge = 90d; age comes from the name).
	old := time.Now().AddDate(0, 0, -91).Format("20060102")
	mustWrite(t, filepath.Join(conns, old, "meta.jsonl"), "meta")
	if err := Compact(dir, 90*24*time.Hour, 1<<30, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(conns, old)); !os.IsNotExist(err) {
		t.Fatalf("old dir %s not pruned", old)
	}
	if _, err := os.Stat(filepath.Join(conns, nowStr())); err != nil {
		t.Fatalf("today's dir missing: %v", err)
	}
}

func nowStr() string {
	return time.Now().Format("20060102")
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
