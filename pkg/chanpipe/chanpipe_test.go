package chanpipe

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// TestChunkLargerThanBuffer pins that a chunk bigger than the read buffer
// is reassembled across partial reads without loss.
func TestChunkLargerThanBuffer(t *testing.T) {
	e0, e1 := New()
	defer e0.Close()
	defer e1.Close()
	payload := bytes.Repeat([]byte("abc"), 37) // 111 bytes
	go e0.Write(payload)
	var got []byte
	buf := make([]byte, 10)
	for len(got) < len(payload) {
		n, err := e1.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			t.Fatalf("early err: %v", err)
		}
	}
	if !bytes.Equal(got, payload) {
		t.Error("payload mangled across partial reads")
	}
}

// TestEmptyReadBuffer pins net's Read contract for a zero-length buffer.
func TestEmptyReadBuffer(t *testing.T) {
	e0, e1 := New()
	defer e0.Close()
	defer e1.Close()
	if n, err := e1.Read(nil); n != 0 || err != nil {
		t.Errorf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
}

// TestChanPipeWriteCloseNoPanic hammers the Write/Close race that used to
// panic with "send on closed channel": a writer looping on one end races a
// reader that reads one chunk and closes. Before the fix, Close closed the
// data channels, so a writer parked in its select was woken by the close of
// its send channel (success=false) and selectgo jumped to the send-closed
// panic path. Now Close only closes done, so the writer takes the done case
// and returns an error.
func TestChanPipeWriteCloseNoPanic(t *testing.T) {
	for range 20000 {
		a, b := New()
		stopped := make(chan struct{})
		go func() {
			defer close(stopped)
			for {
				if _, err := b.Write([]byte("x")); err != nil {
					return
				}
			}
		}()
		go func() {
			buf := make([]byte, 1)
			io.ReadFull(a, buf)
			a.Close()
		}()
		<-stopped
	}
}

// TestChanPipeDrainThenEOF pins "reads after Close drain pending then EOF":
// a chunk larger than the read buffer leaves a tail in the end's pending
// buffer, which must be returned before the close produces EOF.
func TestChanPipeDrainThenEOF(t *testing.T) {
	a, b := New()
	closed := make(chan struct{})
	go func() {
		a.Write([]byte("PING"))
		a.Close()
		close(closed)
	}()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(b, buf); err != nil {
		t.Fatalf("first read: %v", err)
	}
	if string(buf) != "PI" {
		t.Fatalf("first read = %q, want PI", buf)
	}
	// "NG" is still pending on b; it must drain before EOF.
	if _, err := io.ReadFull(b, buf); err != nil {
		t.Fatalf("second read: %v", err)
	}
	if string(buf) != "NG" {
		t.Fatalf("second read = %q, want NG", buf)
	}
	if n, err := b.Read(buf); err != io.EOF || n != 0 {
		t.Fatalf("third read = %d, %v; want 0, EOF", n, err)
	}
	<-closed
}

// TestChanPipeWriteAfterClose pins "a write that races or follows Close
// returns an error" (and, implicitly, never panics).
func TestChanPipeWriteAfterClose(t *testing.T) {
	a, b := New()
	a.Close()
	if _, err := b.Write([]byte("x")); err == nil {
		t.Fatal("write after close: want error, got nil")
	}
}

// TestChanPipeCloseIdempotent pins that Close is idempotent and safe to call
// from either end.
func TestChanPipeCloseIdempotent(t *testing.T) {
	a, b := New()
	if err := a.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second close (same end): %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("close (other end): %v", err)
	}
}

// TestChanPipeDirectionIndependence pins the net.Pipe direction semantics:
// a's writes are read by b and only by b, and b's writes are read by a
// and only by a.
func TestChanPipeDirectionIndependence(t *testing.T) {
	a, b := New()
	sent := make(chan struct{})
	go func() {
		a.Write([]byte("from-a"))
		close(sent)
	}()
	buf := make([]byte, 6)
	if _, err := io.ReadFull(b, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "from-a" {
		t.Fatalf("b read = %q, want from-a", buf)
	}
	<-sent
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 6)
		n, _ := io.ReadFull(a, buf)
		done <- string(buf[:n])
	}()
	b.Write([]byte("from-b"))
	select {
	case s := <-done:
		if s != "from-b" {
			t.Errorf("a read %q, want from-b", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a never read b's bytes")
	}
	b.Close()
}
