package proxy

import (
	"io"
	"sync"
	"testing"
	"time"
)

// eofLeg is a small leg whose Read blocks until Close, then returns io.EOF —
// the shape of a local leg that never sends on its own.
type eofLeg struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func (l *eofLeg) Read(p []byte) (int, error) {
	<-l.closed
	return 0, io.EOF
}
func (l *eofLeg) Write(p []byte) (int, error) { return len(p), nil }
func (l *eofLeg) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

// TestLocalConnCloseWrite: a local leg has no half-close, so CloseWrite fully
// closes it — a Read blocked on the leg unblocks with io.EOF, and a later
// Close is a no-op.
func TestLocalConnCloseWrite(t *testing.T) {
	leg := &eofLeg{closed: make(chan struct{})}
	c := localConn{leg}

	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 4))
		done <- err
	}()

	if err := c.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("Read after CloseWrite = %v, want io.EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not unblock after CloseWrite")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v, want nil", err)
	}
}
