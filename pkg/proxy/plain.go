package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"strings"

	"github.com/nicois/prox/pkg/hooks"
	"github.com/nicois/prox/pkg/sink"
)

// servePlain relays a plain HTTP connection to origDst, writing the peeked
// prefix verbatim and teeing both directions into the sink.
func (l *Ladder) servePlain(conn net.Conn, prefix []byte, scn *sink.Conn, origDst net.Addr, id string) error {
	info := connInfo(id, "plain_http", "", conn.RemoteAddr(), origDst)
	pipe, cs, dec, err := l.hookGate(info, scn, id)
	if err != nil {
		return err
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
	// ServeTunnel on a plain flow is the mirror path: there is no TLS to
	// skip, so the decision makes no difference.
	var up net.Conn
	if dec.Mode == hooks.ServeLocal {
		up = localConn{dec.Local}
		slog.Info("relay", "id", id, "client", conn.RemoteAddr().String(), "kind", "local", "dst", origDst.String())
	} else {
		up, err = l.dialUpstream(origDst)
		if err != nil {
			slog.Warn("relay", "id", id, "client", conn.RemoteAddr().String(), "kind", "plain", "dst", origDst.String(), "err", err)
			pipe.Emit(hooks.Event{Kind: hooks.UpstreamConnectFailed, Detail: errString(err)})
			reason = errString(err)
			return err
		}
		slog.Info("relay", "id", id, "client", conn.RemoteAddr().String(), "kind", "plain", "dst", origDst.String())
	}
	defer up.Close()
	pipe.SetCloseFn(func() { up.Close(); conn.Close() })

	reqLine := firstLine(prefix)
	var respLine string
	c2s := &rangeTee{fn: scn.WriteC2S}
	s2c := newS2cTee(scn, &respLine)
	ea, eb := l.copyTee(io.MultiReader(bytes.NewReader(prefix), conn), conn, up,
		pipe.Writer(hooks.DirC2S, io.MultiWriter(up, c2s)),
		l.s2cWriter(pipe, conn, s2c, scn, cs, id))
	serveErr := ea
	fireRelayEndEvents(pipe, ea, eb)
	pipe.Seal()
	if reqLine != "" {
		scn.WriteJSON(evt("http_request", "line", reqLine))
	}
	if respLine != "" {
		scn.WriteJSON(evt("http_response", "line", respLine))
	}
	scn.WriteJSON(bytesRange("bytes_c2s", c2s))
	scn.WriteJSON(bytesRange("bytes_s2c", s2c))
	reason = errString(serveErr)
	return serveErr
}

// firstLine returns the first newline-terminated line of b, "" if none.
func firstLine(b []byte) string {
	if before, _, ok := bytes.Cut(b, []byte{'\n'}); ok {
		return strings.TrimRight(string(before), "\r")
	}
	return ""
}
