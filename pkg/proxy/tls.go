package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/nicois/prox/pkg/capture"
	"github.com/nicois/prox/pkg/hooks"
	"github.com/nicois/prox/pkg/sink"
	"github.com/nicois/prox/pkg/sniff"
)

// ctSCTExtOID is 1.3.6.1.4.1.11129.2.4.2 (ct_precertificateSct, RFC 6962):
// the extension a minter embeds when the leaf carries signed certificate
// timestamps.
var ctSCTExtOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// serveTLS handles a TLS connection: patched pairs are dropped by default
// (or tunneled verbatim when TunnelFallback is set), otherwise it MITMs.
// The client leg (forged leaf) completes before the upstream leg is dialed.
// Decrypted bytes are teed into the sink.
func (l *Ladder) serveTLS(conn net.Conn, prefix []byte, scn *sink.Conn, s sniff.Sniffed, origDst net.Addr, id string) error {
	host := s.SNI
	dstIP := ""
	if ta, ok := origDst.(*net.TCPAddr); ok {
		dstIP = ta.IP.String()
	}
	if l.Store != nil {
		if patched, err := l.Store.IsPatch(dstIP, host); err == nil && patched {
			if !l.TunnelFallback {
				// Default (tunnel_fallback disabled): the pair rejected
				// our forged leaf or demands mTLS, so MITMing it is
				// futile — drop the connection and log the stored
				// rejection reason. No upstream dial, no hook gate, no
				// bytes propagated: both TLS negotiations must not cross
				// the proxy.
				reason, ok, _ := l.Store.PatchDetail(dstIP, host)
				if !ok || reason == "" {
					reason = "unknown"
				}
				slog.Info("mitm", "id", id, "client", conn.RemoteAddr().String(), "host", host, "dst", origDst.String(), "result", "patched_drop", "reason", reason)
				scn.WriteJSON(evt("mitm_attempt", "host", host, "dst", origDst.String(), "result", "patched_drop", "reason", reason))
				scn.WriteJSON(evt("record_summary", "dst", origDst.String(), "reason", "patched"))
				return fmt.Errorf("proxy: patched pair dropped: %s", reason)
			}
			slog.Info("tunnel", "id", id, "client", conn.RemoteAddr().String(), "host", host, "dst", origDst.String(), "reason", "patched")
			scn.WriteJSON(evt("record_summary", "dst", origDst.String(), "reason", "patched"))
			return l.serveRaw(conn, prefix, scn, origDst, id, "tls", host)
		}
	}
	pipe, cs, dec, err := l.hookGate(connInfo(id, "tls", host, conn.RemoteAddr(), origDst), scn, id)
	if err != nil {
		return err
	}

	// A hook tunnel decision is the pass-through path: no mint, no client
	// leg, verbatim relay (prefix included) — the same shape as the
	// patched-store tunnel. It returns before the deferred close below is
	// registered: serveRawGated owns the drain check and the close, so a
	// tunnel flow ending during a drain emits exactly one drain event.
	if dec.Mode == hooks.ServeTunnel {
		slog.Info("tunnel", "id", id, "client", conn.RemoteAddr().String(), "host", host, "dst", origDst.String(), "reason", "hook")
		scn.WriteJSON(evt("record_summary", "dst", origDst.String(), "reason", "tunnel"))
		return l.serveRawGated(conn, prefix, scn, origDst, id, "tls", host, pipe, cs, dec)
	}

	reason := ""
	defer func() {
		if l.Draining.Load() {
			pipe.Emit(hooks.Event{Kind: hooks.Drain})
		}
		if pipe != nil {
			pipe.Close(reason)
		} else if cs != nil {
			cs.Finish(reason)
		}
	}()

	leaf, err := l.selectLeaf(host, dstIP, time.Now())
	// Parse the presented chain up front: an unparseable chain is a mint
	// failure (there is no leaf to present), and the parsed leaf plus the
	// chain CNs feed the presented-leaf event below.
	certCNs := []string{}
	var leafCert *x509.Certificate
	if err == nil && leaf == nil {
		err = errors.New("proxy: leaf minter returned no certificate")
	}
	if err == nil {
		certCNs = make([]string, 0, len(leaf.Certificate))
		for i, der := range leaf.Certificate {
			c, perr := x509.ParseCertificate(der)
			if perr != nil {
				err = perr
				break
			}
			if i == 0 {
				leafCert = c
			}
			certCNs = append(certCNs, c.Subject.CommonName)
		}
		if leafCert == nil {
			err = errors.New("proxy: leaf has no certificate")
		}
	}
	if err != nil {
		slog.Warn("mitm", "id", id, "client", conn.RemoteAddr().String(), "host", host, "dst", origDst.String(), "result", "mint_failed", "err", err)
		scn.WriteJSON(evt("mitm_attempt", "host", host, "dst", origDst.String(), "result", "mint_failed"))
		tlsOutcome(pipe, cs, capture.TLSInfo{Host: host, Result: "mint_failed"})
		reason = "mint_failed"
		return fmt.Errorf("proxy: mint leaf: %w", err)
	}
	// WHAT the client leg will present — CN, validity, served chain, SCT
	// presence, signature — tied to the conn id, so a client_rejected is
	// analyzable from the log alone. Emitted after the mint and before the
	// client handshake: it precedes both the success and the rejection.
	// sct: the leaf carries the RFC 6962 signed-certificate-timestamp
	// extension (the same extension pkg/tlsutil embeds after a CT-log
	// submission), if any.
	sct := false
	for _, ext := range leafCert.Extensions {
		if ext.Id.Equal(ctSCTExtOID) && len(ext.Value) > 0 {
			sct = true
			break
		}
	}
	validUntil := leafCert.NotAfter.UTC().Format(time.RFC3339)
	sig := leafCert.SignatureAlgorithm.String()
	slog.Info("leaf", "id", id, "host", host, "cn", leafCert.Subject.CommonName, "valid_until", validUntil, "chain", strings.Join(certCNs, ","), "sct", sct, "sig", sig)
	scn.WriteJSON(evt("leaf_presented", "cn", leafCert.Subject.CommonName, "valid_until", validUntil, "chain", strings.Join(certCNs, ","), "sct", sct, "sig", sig))
	server := tls.Server(&prefixedConn{Conn: conn, prefix: bytes.NewReader(prefix)}, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		// We never offer a client certificate. An upstream that requires
		// one rejects the upstream leg; that is the mTLS signal.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return nil, nil
		},
	})
	hctx, cancel := context.WithTimeout(context.Background(), l.handshakeTimeout())
	defer cancel()
	if err := server.HandshakeContext(hctx); err != nil {
		slog.Info("mitm", "id", id, "client", conn.RemoteAddr().String(), "host", host, "dst", origDst.String(), "result", "client_rejected", "err", err)
		// A stalled client (handshake timeout) is not evidence the client
		// rejected the forged chain — do not mark the pair.
		if !errors.Is(err, context.DeadlineExceeded) {
			l.markPatched(dstIP, host, "cert_rejected")
		}
		scn.WriteJSON(evt("mitm_attempt", "host", host, "dst", origDst.String(), "result", "client_rejected", "err", errString(err)))
		tlsOutcome(pipe, cs, capture.TLSInfo{Host: host, Result: "client_rejected"})
		reason = "client_rejected"
		return err
	}
	slog.Info("mitm", "id", id, "client", conn.RemoteAddr().String(), "host", host, "dst", origDst.String(), "result", "success")
	scn.WriteJSON(evt("mitm_attempt", "host", host, "dst", origDst.String(), "result", "success"))
	tlsOutcome(pipe, cs, capture.TLSInfo{Host: host, Version: server.ConnectionState().Version, Result: "success"})

	// The remote leg: a dialed, TLS-verified upstream (mirror) or the
	// consumer's plain leg (local). Local keeps the client-leg TLS outcome
	// above ("success": the client handshake completed) — the absence of a
	// real upstream is the flow's serve mode, not a handshake failure.
	var up net.Conn
	if dec.Mode == hooks.ServeLocal {
		up = localConn{dec.Local}
		defer up.Close()
		slog.Info("relay", "id", id, "client", conn.RemoteAddr().String(), "kind", "local", "host", host, "dst", origDst.String())
	} else {
		var upErr error
		up, upErr = l.dialUpstream(origDst)
		if upErr != nil {
			slog.Warn("mitm", "id", id, "client", conn.RemoteAddr().String(), "host", host, "dst", origDst.String(), "result", "upstream_dial_failed", "err", upErr)
			pipe.Emit(hooks.Event{Kind: hooks.UpstreamConnectFailed, Detail: errString(upErr)})
			reason = "upstream_dial_failed"
			return upErr
		}
		defer up.Close()
		serverName := host
		if serverName == "" {
			// No SNI on the client leg: verify the upstream against the
			// destination IP (Go checks IP SANs for IP-literal names).
			serverName = dstIP
		}
		upTLS := tls.Client(up, &tls.Config{
			ServerName: serverName,
			RootCAs:    l.UpstreamRoots,
			MinVersion: tls.VersionTLS12,
		})
		if err := upTLS.HandshakeContext(hctx); err != nil {
			if isMTLSErr(err) {
				// Only an upstream that demands a client certificate is a
				// patching signal (design §5.2): it will refuse the site
				// forever, so stop MITMing it.
				slog.Warn("mitm", "id", id, "client", conn.RemoteAddr().String(), "host", host, "dst", origDst.String(), "result", "mtls", "err", err)
				l.markPatched(dstIP, host, "mtls")
				scn.WriteJSON(evt("record_summary", "reason", "mtls"))
				reason = "mtls"
				return err
			}
			// Any other upstream-side failure (untrusted upstream cert, SNI
			// mismatch, timeout) is not a patching signal: log it and let
			// the client retry.
			slog.Warn("mitm", "id", id, "client", conn.RemoteAddr().String(), "host", host, "dst", origDst.String(), "result", "upstream_error", "err", err)
			scn.WriteJSON(evt("record_summary", "reason", "upstream_error"))
			reason = "upstream_error"
			return err
		}
		up = upTLS
	}

	// The decrypted app data passes the hook verdict before it is teed into
	// the sink ranges and first lines, so the capture records what went on
	// the wire.
	pipe.SetCloseFn(func() { up.Close(); server.Close() })
	var reqLine, respLine string
	c2s := &rangeTee{fn: scn.WriteC2S, line: &reqLine}
	s2c := newS2cTee(scn, &respLine)
	c2sW := pipe.Writer(hooks.DirC2S, io.MultiWriter(up, c2s))
	s2cW := l.s2cWriter(pipe, server, s2c, scn, cs, id)
	errC2S := make(chan error, 1)
	errS2C := make(chan error, 1)
	go func() {
		_, err := io.Copy(c2sW, server)
		up.Close()
		errC2S <- err
	}()
	go func() {
		_, err := io.Copy(s2cW, up)
		// The upstream stopped sending: close the client leg so the c2s
		// copy can terminate (tls cannot half-close, and the upstream is
		// done with the connection, so no further client data is expected).
		conn.Close()
		errS2C <- err
	}()
	ea, eb := <-errC2S, <-errS2C
	fireRelayEndEvents(pipe, ea, eb)
	for _, err := range []error{ea, eb} {
		if err != nil && isMTLSErr(err) {
			// The upstream completed the handshake but rejected our
			// no-cert client leg on the first app-data read; Go
			// surfaces that alert as the copy error, not as a
			// handshake failure.
			slog.Warn("mitm", "id", id, "client", conn.RemoteAddr().String(), "host", host, "dst", origDst.String(), "result", "mtls", "err", err)
			l.markPatched(dstIP, host, "mtls")
			scn.WriteJSON(evt("record_summary", "reason", "mtls"))
			reason = "mtls"
			return err
		}
	}

	pipe.Seal()
	if reqLine != "" {
		scn.WriteJSON(evt("http_request", "line", reqLine))
	}
	if respLine != "" {
		scn.WriteJSON(evt("http_response", "line", respLine))
	}
	scn.WriteJSON(bytesRange("bytes_c2s", c2s))
	scn.WriteJSON(bytesRange("bytes_s2c", s2c))
	if !isCloseErr(ea) {
		reason = errString(ea)
	} else if !isCloseErr(eb) {
		reason = errString(eb)
	}
	if !isCloseErr(ea) {
		return ea
	}
	if !isCloseErr(eb) {
		return eb
	}
	return nil
}

// selectLeaf returns the leaf to present on the client leg: the consumer's
// LeafSelector first (authoritative when it speaks), the built-in minter as
// the default.
func (l *Ladder) selectLeaf(host, dst string, now time.Time) (*tls.Certificate, error) {
	if l.LeafSelector != nil {
		cert, err := l.LeafSelector(host, dst)
		if err != nil {
			return nil, err
		}
		if cert != nil {
			return cert, nil
		}
	}
	if l.Leaves == nil {
		return nil, errors.New("proxy: no leaf minter configured for TLS")
	}
	return l.Leaves.Leaf(host, dst, now)
}

// tlsOutcome attaches the client-leg TLS result to the capture record and
// notifies observer hooks. The pipe is nil when no hook matched; the stream
// is nil when no capture registry is configured — both are possible.
func tlsOutcome(pipe *hooks.Pipe, cs *capture.Stream, r capture.TLSInfo) {
	if pipe != nil {
		pipe.NotifyTLS(r)
		return
	}
	if cs != nil {
		rp := r
		cs.SetTLS(&rp)
	}
}

// isCloseErr reports whether err is an artifact of one side of the tunnel
// being closed (our own conn/upTLS Close, or the peer closing early) rather
// than a transport failure.
func isCloseErr(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "read on closed pipe") ||
		strings.Contains(s, "write on closed pipe")
}

// prefixedConn replays the bytes Serve peeked before handing reads to the
// live conn. The TLS server needs the ClientHello bytes again; Serve has
// already consumed them from the connection.
type prefixedConn struct {
	net.Conn
	prefix *bytes.Reader
}

func (p *prefixedConn) Read(b []byte) (int, error) {
	if p.prefix != nil {
		n, err := p.prefix.Read(b)
		if n > 0 {
			return n, nil
		}
		if err == io.EOF {
			p.prefix = nil
			return p.Conn.Read(b)
		}
		return 0, err
	}
	return p.Conn.Read(b)
}

func (l *Ladder) markPatched(ip, host, reason string) {
	if l.Store == nil {
		return
	}
	if err := l.Store.MarkPatch(ip, host, reason, time.Now()); err != nil {
		slog.Warn("patched store", "ip", ip, "host", host, "err", err)
		return
	}
	slog.Info("patched", "ip", ip, "host", host, "reason", reason)
}

// isMTLSErr reports whether err looks like the upstream demanding a client
// certificate.
func isMTLSErr(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "certificate required") ||
		strings.Contains(msg, "client didn't provide a certificate")
}
