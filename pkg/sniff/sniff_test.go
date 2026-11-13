package sniff

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// tbHelper is the minimal testing.T surface captureHello needs; *testing.T
// and *testing.F both satisfy it.
type tbHelper interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// captureHello performs a real TLS handshake and returns the first TLS record
// the server saw (the ClientHello). The server completes the handshake so the
// client does not block; the raw ClientHello bytes are captured before the
// handshake re-feeds them to tls.Server.
func captureHello(t tbHelper, serverName string, alpn []string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{serverName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	recCh := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			recCh <- nil
			return
		}
		defer conn.Close()
		// Read the complete first record: a 5-byte header (type/version/length)
		// followed by exactly `length` body bytes. A single Read may return only
		// part of the record if TCP segmented the ClientHello.
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			recCh <- nil
			return
		}
		recLen := int(hdr[3])<<8 | int(hdr[4])
		rec := make([]byte, 0, 5+recLen)
		rec = append(rec, hdr...)
		body := make([]byte, recLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			recCh <- nil
			return
		}
		rec = append(rec, body...)

		// Re-feed the complete record so tls.Server can finish the handshake;
		// otherwise the client blocks forever waiting for a ServerHello.
		mc := io.MultiReader(bytes.NewReader(rec), conn)
		tlsConn := tls.Server(&passthroughConn{r: mc, c: conn}, &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
		})
		if err := tlsConn.Handshake(); err != nil {
			recCh <- nil
			return
		}
		recCh <- rec
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	cli := tls.Client(c, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         alpn,
	})
	if err := cli.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	cli.Close()

	rec := <-recCh
	if rec == nil {
		t.Fatal("did not capture ClientHello record")
	}
	return rec
}

type passthroughConn struct {
	r io.Reader
	c net.Conn
}

func (p *passthroughConn) Read(b []byte) (int, error)    { return p.r.Read(b) }
func (p *passthroughConn) Write(b []byte) (int, error)   { return p.c.Write(b) }
func (p *passthroughConn) Close() error                  { return p.c.Close() }
func (p *passthroughConn) LocalAddr() net.Addr           { return p.c.LocalAddr() }
func (p *passthroughConn) RemoteAddr() net.Addr          { return p.c.RemoteAddr() }
func (p *passthroughConn) SetDeadline(t time.Time) error { return p.c.SetDeadline(t) }
func (p *passthroughConn) SetReadDeadline(t time.Time) error {
	return p.c.SetReadDeadline(t)
}
func (p *passthroughConn) SetWriteDeadline(t time.Time) error {
	return p.c.SetWriteDeadline(t)
}

func TestSniffTLSClientHello(t *testing.T) {
	rec := captureHello(t, "example.com", []string{"h2", "http/1.1"})
	s, err := Sniff(rec)
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if s.Kind != KindTLS {
		t.Fatalf("kind = %v, want KindTLS", s.Kind)
	}
	if s.SNI != "example.com" {
		t.Fatalf("SNI = %q, want example.com", s.SNI)
	}
	if len(s.ALPN) != 2 || s.ALPN[0] != "h2" {
		t.Fatalf("ALPN = %v, want [h2 http/1.1]", s.ALPN)
	}
	if s.JA3 == "" {
		t.Fatal("JA3 is empty")
	}
}

func TestSniffPlainHTTP(t *testing.T) {
	buf := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	s, err := Sniff(buf)
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if s.Kind != KindPlainHTTP {
		t.Fatalf("kind = %v, want KindPlainHTTP", s.Kind)
	}
}

func TestSniffRawTCP(t *testing.T) {
	s, err := Sniff([]byte{0x00, 0x01, 0x02, 0x03, 0x04})
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if s.Kind != KindRawTCP {
		t.Fatalf("kind = %v, want KindRawTCP", s.Kind)
	}
}
