package proxy

import (
	"io"
	"net"
	"time"
)

// localConn adapts a consumer-provided io.ReadWriteCloser to the net.Conn
// plumbing the relay uses for an upstream leg, so a ServeLocal flow runs
// the exact copy/tee/hook code paths of a mirrored one. Addresses are
// placeholders; deadlines are no-ops (the relay never sets them on the
// upstream leg). There is no half-close: the consumer owns the leg's
// lifetime, and the relay closes the leg with the connection.
type localConn struct {
	io.ReadWriteCloser
}

func (localConn) LocalAddr() net.Addr              { return localAddr{} }
func (localConn) RemoteAddr() net.Addr             { return localAddr{} }
func (localConn) SetDeadline(time.Time) error      { return nil }
func (localConn) SetReadDeadline(time.Time) error  { return nil }
func (localConn) SetWriteDeadline(time.Time) error { return nil }

// CloseWrite fully closes the leg: a local leg has no half-close, and the
// relay's CloseWrite when the c2s leg ends is what unblocks the s2c copy
// that is reading the leg. (The TLS path already full-closes the local leg;
// without this, a ServeLocal raw/plain flow leaks when the client goes away
// and the leg never sends.)
func (c localConn) CloseWrite() error { return c.Close() }

type localAddr struct{}

func (localAddr) Network() string { return "local" }
func (localAddr) String() string  { return "local" }
