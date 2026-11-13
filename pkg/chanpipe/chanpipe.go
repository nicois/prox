// Package chanpipe is an in-memory full-duplex byte stream for driving
// prox's relay (and other net.Conn consumers) without a network: each
// direction is an independent channel queue, so end0's writes are read by
// end1 and only by end1 — the direction semantics of net.Pipe, without its
// file descriptors.
//
// It exists for tests that use testing/synctest: inside a synctest bubble
// the simulated clock advances only while every group goroutine is
// "durably blocked", and a durable block is one that only another group
// goroutine can unblock — a channel created inside the bubble qualifies, a
// kernel pipe (net.Pipe) does not. Two rules for synctest use:
//
//  1. Create the pipe inside the bubble (synctest.Test's function or a
//     goroutine it starts); channels created outside are not durably
//     blocking and the clock stalls.
//  2. Use it only between group goroutines.
//
// Outside synctest it is an ordinary in-memory conn.
package chanpipe

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// pipe is the shared state of a duplex pipe: one queue per direction.
type pipe struct {
	a    chan []byte // end0 -> end1
	b    chan []byte // end1 -> end0
	done chan struct{}
	once sync.Once
}

// Conn is one end of a chanpipe pipe. It satisfies net.Conn with no-op
// deadlines, which is all the relay and the tests use.
type Conn struct {
	p    *pipe
	out  chan []byte
	in   chan []byte
	pmu  sync.Mutex
	pend []byte
}

// New returns the two ends of a fresh duplex pipe.
func New() (*Conn, *Conn) {
	p := &pipe{a: make(chan []byte), b: make(chan []byte), done: make(chan struct{})}
	return &Conn{p: p, out: p.a, in: p.b},
		&Conn{p: p, out: p.b, in: p.a}
}

// Read blocks until data is available or the peer closes the pipe, and
// returns io.EOF only after any pending bytes are drained.
func (c *Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		c.pmu.Lock()
		if len(c.pend) == 0 {
			c.pmu.Unlock()
			// The data channels are never closed (see Close), so EOF is
			// signalled by the done channel, not by a closed receive.
			// Selecting on done (rather than relying on close(c.in)) is
			// what keeps a concurrent Close from racing a blocked read.
			select {
			case chunk := <-c.in:
				c.pmu.Lock()
				c.pend = append(c.pend, chunk...)
			case <-c.p.done:
				return 0, io.EOF
			}
		}
		n := copy(b, c.pend)
		c.pend = c.pend[n:]
		c.pmu.Unlock()
		return n, nil
	}
}

// Write sends b to the far end. It never panics: the data channels are
// never closed (Close only closes done), so the send case cannot be a send
// on a closed channel. A write that races or follows Close takes the done
// case and returns an error.
func (c *Conn) Write(b []byte) (int, error) {
	chunk := append([]byte(nil), b...)
	select {
	case c.out <- chunk:
		return len(b), nil
	case <-c.p.done:
		return 0, errors.New("chanPipe: closed")
	}
}

// Close shuts down both directions. It closes only the done channel and
// never the data channels: closing a data channel would turn a concurrent
// or subsequent Write into a "send on closed channel" panic (the runtime
// wakes a parked sender on close with success=false, and selectgo then
// jumps to the send-closed panic path). Instead, a blocked Write wakes on
// done and returns an error, and a blocked Read wakes on done and returns
// EOF after any pending bytes are drained. Close is idempotent.
func (c *Conn) Close() error {
	c.p.once.Do(func() {
		close(c.p.done)
	})
	return nil
}

// LocalAddr returns an empty net.TCPAddr; addresses are meaningless for an
// in-memory pipe (net.Conn interface only).
func (c *Conn) LocalAddr() net.Addr { return &net.TCPAddr{} }

// RemoteAddr returns an empty net.TCPAddr; addresses are meaningless for an
// in-memory pipe (net.Conn interface only).
func (c *Conn) RemoteAddr() net.Addr { return &net.TCPAddr{} }

// String returns "chanPipe", for logs and panics that print the conn.
func (c *Conn) String() string { return "chanPipe" }

// SetDeadline is a no-op: the pipe supports no deadlines.
func (c *Conn) SetDeadline(time.Time) error { return nil }

// SetReadDeadline is a no-op: the pipe supports no deadlines.
func (c *Conn) SetReadDeadline(time.Time) error { return nil }

// SetWriteDeadline is a no-op: the pipe supports no deadlines.
func (c *Conn) SetWriteDeadline(time.Time) error { return nil }
