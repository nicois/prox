package isolation

import (
	"io"
	"testing"
	"time"

	"github.com/nicois/prox/pkg/hooks"
)

// TestBlackholeWriteDiscards: a write is accepted and reported in full, but
// nothing is retained.
func TestBlackholeWriteDiscards(t *testing.T) {
	b := newBlackhole()
	n, err := b.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len("hello") {
		t.Fatalf("Write n = %d, want %d", n, len("hello"))
	}
}

// TestBlackholeReadBlocksThenEOF: Read blocks until Close, then returns
// io.EOF.
func TestBlackholeReadBlocksThenEOF(t *testing.T) {
	b := newBlackhole()
	done := make(chan error, 1)
	go func() {
		_, err := b.Read(make([]byte, 4))
		done <- err
	}()
	select {
	case <-done:
		t.Fatal("Read returned before Close")
	case <-time.After(100 * time.Millisecond):
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("Read after Close = %v, want io.EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not return after Close")
	}
}

// TestBlackholeWriteAfterClose: a write once closed is an error.
func TestBlackholeWriteAfterClose(t *testing.T) {
	b := newBlackhole()
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := b.Write([]byte("x")); err == nil {
		t.Fatal("Write after Close: want error, got nil")
	}
}

// TestBlackholeCloseIdempotent: repeated Close is a no-op.
func TestBlackholeCloseIdempotent(t *testing.T) {
	b := newBlackhole()
	for i := range 3 {
		if err := b.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i, err)
		}
	}
}

// TestFullFilterZero: the isolation hook matches every flow.
func TestFullFilterZero(t *testing.T) {
	if got := Full().Filter(); got != (hooks.Match{}) {
		t.Fatalf("Filter = %+v, want zero Match", got)
	}
}

// TestFullOnOpenSetsLabel: OnOpen marks the flow's record as full isolation.
func TestFullOnOpenSetsLabel(t *testing.T) {
	c := &hooks.Conn{}
	Full().OnOpen(c, nil)
	if c.Labels["isolation"] != "full" {
		t.Fatalf("Labels[isolation] = %q, want full (labels %v)", c.Labels["isolation"], c.Labels)
	}
}

// TestFullServeLocalLegs: every Serve returns a local decision with a
// distinct, non-nil leg.
func TestFullServeLocalLegs(t *testing.T) {
	h := Full()
	sv, ok := h.(hooks.Serving)
	if !ok {
		t.Fatal("Full() must implement hooks.Serving")
	}
	d1, err := sv.Serve(&hooks.Conn{})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	d2, err := sv.Serve(&hooks.Conn{})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if d1.Mode != hooks.ServeLocal || d2.Mode != hooks.ServeLocal {
		t.Fatalf("modes = %v/%v, want ServeLocal/ServeLocal", d1.Mode, d2.Mode)
	}
	if d1.Local == nil || d2.Local == nil {
		t.Fatal("Local legs must be non-nil")
	}
	if d1.Local == d2.Local {
		t.Fatal("each Serve must return a distinct leg")
	}
}
