package hooks

import "sync"

// DefaultHoldLimit bounds one direction's hold buffer (bytes).
const DefaultHoldLimit = 16 << 20

// DefaultHoldHighWater is the depth at which the HoldWatermark event fires.
const DefaultHoldHighWater = 12 << 20

// holdBuf is one direction's bounded hold buffer. Appends block at the
// limit — backpressure: the holding direction's relay loop stalls and TCP
// backpressures that peer; the other direction is untouched. drain empties
// the buffer in one shot. Loss is impossible by construction: nothing is
// ever dropped from the buffer.
type holdBuf struct {
	mu    sync.Mutex
	cond  *sync.Cond
	buf   []byte
	limit int64
	high  int64
	over  bool // the watermark is currently tripped
}

func newHoldBuf() *holdBuf {
	b := &holdBuf{limit: DefaultHoldLimit, high: DefaultHoldHighWater}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *holdBuf) setLimits(limit, high int64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	if limit > 0 {
		b.limit = limit
	}
	if high > 0 {
		b.high = high
	}
	b.mu.Unlock()
}

// depth returns the current depth and the limit.
func (b *holdBuf) depth() (depth, limit int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return int64(len(b.buf)), b.limit
}

// append blocks until the chunk fits, then appends. It reports whether the
// high-water mark was crossed by this append — edge-triggered: it fires
// once per trip and re-arms on the next drain.
func (b *holdBuf) append(c []byte) (watermark bool) {
	b.mu.Lock()
	for int64(len(b.buf)) >= b.limit {
		b.cond.Wait()
	}
	b.buf = append(b.buf, c...)
	wm := !b.over && int64(len(b.buf)) >= b.high
	if wm {
		b.over = true
	}
	b.mu.Unlock()
	return wm
}

// drain empties the buffer and wakes blocked appenders.
func (b *holdBuf) drain() []byte {
	b.mu.Lock()
	out := b.buf
	b.buf = nil
	b.over = false
	b.cond.Broadcast()
	b.mu.Unlock()
	return out
}
