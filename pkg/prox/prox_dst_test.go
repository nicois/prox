package prox

import (
	"net"
	"testing"
)

// TestOriginalDstFallback: on a normal (non-TPROXY) loopback connection the
// socket has no IP_TRANSPARENT option, so originalDst must fall back to
// RemoteAddr, never return nil.
func TestOriginalDstFallback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	acceptCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			acceptCh <- c
		}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	sc, ok := <-acceptCh
	if !ok {
		t.Fatal("no accepted connection")
	}
	defer sc.Close()

	got := originalDst(sc)
	if got == nil {
		t.Fatal("originalDst returned nil")
	}
	if want := sc.RemoteAddr().String(); got.String() != want {
		t.Fatalf("fallback = %s, want %s", got, want)
	}
}
