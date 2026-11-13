// Package sink is the per-connection capture sink: the c2s.bin, s2c.bin,
// and meta.jsonl files under <dataroot>/conns/<YYYYMMDD>/<id>, with a
// per-direction byte cap, plus the retention sweep (Compact) that prunes
// day-dirs by age and total size.
package sink

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nicois/prox/pkg/version"
)

// defaultMaxConnBytes caps per-connection .bin capture.
const defaultMaxConnBytes int64 = 256 << 20

// Conn is one connection's capture: the c2s.bin, s2c.bin, and meta.jsonl
// files created by Open under <dataroot>/conns/<YYYYMMDD>/<id>. WriteC2S
// and WriteS2C append direction bytes (each direction is capped at
// maxConnBytes and then silently discarded), WriteJSON appends a meta.jsonl
// event, and Close closes the files. A zero Conn (Noop) discards
// everything.
type Conn struct {
	dir      string
	c2s      *os.File
	s2c      *os.File
	meta     *os.File
	c2sLen   int64
	s2cLen   int64
	maxBytes int64
	// capped is shared by the c2s and s2c copy goroutines.
	capped atomic.Bool
	// metaBroken is set only on a meta write failure; the byte cap never
	// freezes the journal.
	metaBroken atomic.Bool
	// mu serializes capture writes: a direction can be written by the
	// relay's copy goroutine and by hook-manufactured bytes concurrently.
	mu sync.Mutex
}

// Open opens (creating) the per-connection capture dir
// dataRoot/conns/<YYYYMMDD>/<id> with c2s.bin, s2c.bin and meta.jsonl.
// maxConnBytes caps per-direction capture; <= 0 uses the default.
// fileMode and dirMode set the permissions of the created capture files
// and directories (creation time only; existing files are not
// re-chmodded).
func Open(dataRoot, id string, maxConnBytes int64, fileMode, dirMode fs.FileMode) (*Conn, error) {
	maxBytes := defaultMaxConnBytes
	if maxConnBytes > 0 {
		maxBytes = maxConnBytes
	}
	dir := filepath.Join(dataRoot, "conns", time.Now().Format("20060102"), id)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, err
	}
	c2s, err := os.OpenFile(filepath.Join(dir, "c2s.bin"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		return nil, err
	}
	s2c, err := os.OpenFile(filepath.Join(dir, "s2c.bin"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		c2s.Close()
		return nil, err
	}
	meta, err := os.OpenFile(filepath.Join(dir, "meta.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		c2s.Close()
		s2c.Close()
		return nil, err
	}
	// Head every stream with the build that wrote it, so a capture can
	// be traced to its provenance. Stamped by the build (see
	// pkg/version); unstamped builds record "dev".
	metaData, err := json.Marshal(map[string]any{"type": "meta", "ts": time.Now().UnixMilli(), "commit": version.Commit})
	if err != nil {
		c2s.Close()
		s2c.Close()
		meta.Close()
		return nil, err
	}
	metaData = append(metaData, '\n')
	if _, err := meta.Write(metaData); err != nil {
		c2s.Close()
		s2c.Close()
		meta.Close()
		return nil, err
	}
	return &Conn{dir: dir, c2s: c2s, s2c: s2c, meta: meta, maxBytes: maxBytes}, nil
}

// WriteJSON appends one JSON line to meta.jsonl.
func (c *Conn) WriteJSON(ev any) error {
	if c.meta == nil {
		return nil
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if c.metaBroken.Load() {
		return nil
	}
	if _, err := c.meta.Write(data); err != nil {
		c.metaBroken.Store(true)
		c.capped.Store(true)
		return err
	}
	return nil
}

// WriteC2S appends client→server bytes to c2s.bin and returns the
// [start,end) range written.
func (c *Conn) WriteC2S(b []byte) (int64, int64, error) {
	if c.c2s == nil {
		return 0, 0, nil
	}
	return c.write(c.c2s, &c.c2sLen, b)
}

// WriteS2C appends server→client bytes to s2c.bin and returns the
// [start,end) range written.
func (c *Conn) WriteS2C(b []byte) (int64, int64, error) {
	if c.s2c == nil {
		return 0, 0, nil
	}
	return c.write(c.s2c, &c.s2cLen, b)
}

func (c *Conn) write(f *os.File, off *int64, b []byte) (int64, int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.capped.Load() {
		return *off, *off, nil
	}
	if *off+int64(len(b)) > c.maxBytes {
		c.capped.Store(true)
		return *off, *off, nil
	}
	n, err := f.Write(b)
	if err != nil {
		c.capped.Store(true)
		return *off, *off, err
	}
	start := *off
	*off += int64(n)
	return start, *off, nil
}

// Close closes the capture files.
func (c *Conn) Close() error {
	if c.c2s == nil {
		return nil
	}
	errs := []error{c.c2s.Close(), c.s2c.Close(), c.meta.Close()}
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// Noop returns a Conn that discards everything: the sink factory for
// embedded hosts that want no file capture.
func Noop() *Conn { return &Conn{} }

// Compact prunes connection day-dirs whose name (YYYYMMDD) is older than
// maxAge, then deletes the oldest remaining day-dirs until the dataroot is
// under maxBytes. capBytes is a per-connection cap for accounting only;
// retention here works at day-dir granularity.
func Compact(dataRoot string, maxAge time.Duration, maxBytes, capBytes int64) error {
	_ = capBytes
	conns := filepath.Join(dataRoot, "conns")
	cutoff := time.Now().Add(-maxAge)
	entries, err := os.ReadDir(conns)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var days []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		d, err := time.Parse("20060102", e.Name())
		if err != nil {
			continue
		}
		if d.Before(cutoff) {
			if err := os.RemoveAll(filepath.Join(conns, e.Name())); err != nil {
				return err
			}
			continue
		}
		days = append(days, e.Name())
	}
	if maxBytes > 0 {
		sort.Strings(days)
		total, err := dirSize(conns)
		if err != nil {
			return err
		}
		for _, day := range days {
			if total <= maxBytes {
				break
			}
			size, err := dirSize(filepath.Join(conns, day))
			if err != nil {
				return err
			}
			if err := os.RemoveAll(filepath.Join(conns, day)); err != nil {
				return err
			}
			total -= size
		}
	}
	return nil
}

func dirSize(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})
	return total, err
}
