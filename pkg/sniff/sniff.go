package sniff

import (
	"fmt"
	"strings"
)

type Kind int

const (
	KindPlainHTTP Kind = iota
	KindTLS
	KindRawTCP
)

// String names the kind for logging and meta events.
func (k Kind) String() string {
	switch k {
	case KindPlainHTTP:
		return "plain_http"
	case KindTLS:
		return "tls"
	default:
		return "raw_tcp"
	}
}

const MaxPeek = 64 * 1024

type Sniffed struct {
	Kind Kind
	SNI  string
	JA3  string
	ALPN []string
}

// Sniff classifies the first bytes of a connection. buf must contain the
// first record (up to MaxPeek). It returns the sniffed metadata and does
// not consume anything beyond buf.
func Sniff(buf []byte) (Sniffed, error) {
	if len(buf) < 5 {
		return Sniffed{Kind: KindRawTCP}, nil
	}
	if buf[0] != 0x16 { // handshake record type
		if isHTTPRequestLine(buf) {
			return Sniffed{Kind: KindPlainHTTP}, nil
		}
		return Sniffed{Kind: KindRawTCP}, nil
	}
	// buf[1:3] record version; require 0x0301..0x0304
	ver := int(buf[1])<<8 | int(buf[2])
	if ver < 0x0301 || ver > 0x0304 {
		return Sniffed{Kind: KindRawTCP}, nil
	}
	length := int(buf[3])<<8 | int(buf[4])
	if len(buf) < 5+length {
		return Sniffed{Kind: KindRawTCP}, nil
	}
	body := buf[5 : 5+length]
	return parseHello(body)
}

// isHTTPRequestLine reports whether buf begins with an HTTP request line
// (METHOD SP ...), as opposed to arbitrary TCP bytes. It only inspects the
// leading method token, so it never reads beyond buf.
func isHTTPRequestLine(buf []byte) bool {
	i := 0
	for i < len(buf) && buf[i] != ' ' {
		if buf[i] < 'A' || buf[i] > 'Z' {
			return false
		}
		i++
	}
	return i > 0 && i < len(buf)
}

func parseHello(body []byte) (Sniffed, error) {
	// body is the TLS record payload: a handshake message of [1-byte type][3-
	// byte uint24 length] followed by the bare ClientHello body. Skip the 4-
	// byte header and slice to the ClientHello body before parsing.
	if len(body) < 4+2+32+1+2+2+4 {
		return Sniffed{}, fmt.Errorf("clientHello too short")
	}
	msgLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if len(body) < 4+msgLen {
		return Sniffed{}, fmt.Errorf("handshake length exceeds record")
	}
	body = body[4 : 4+msgLen]
	// Every field read goes through r, which reports zero values and stays
	// invalid (ok = false) once the message is shorter than its declared
	// structure: crafted packets with inconsistent lengths must return an
	// error, never panic (Sniff runs on the first bytes of every connection).
	r := &helloReader{b: body, ok: true}
	clientVer := r.u16()
	r.skip(32)          // random
	r.skip(int(r.u8())) // session ID
	cipherLen := int(r.u16())
	var ciphers []uint16
	for k := 0; k+2 <= cipherLen; k += 2 {
		ciphers = append(ciphers, r.u16())
	}
	r.skip(int(r.u8())) // compression methods
	extLen := int(r.u16())
	exts := r.take(extLen)
	if !r.ok {
		return Sniffed{}, fmt.Errorf("truncated clientHello")
	}

	var sni string
	var alpn []string
	var curves []uint16
	var formats []uint8
	var extsList []uint16

	i := 0
	for i+4 <= len(exts) {
		et := int(exts[i])<<8 | int(exts[i+1])
		el := int(exts[i+2])<<8 | int(exts[i+3])
		if i+4+el > len(exts) {
			return Sniffed{}, fmt.Errorf("extension overruns block")
		}
		ev := exts[i+4 : i+4+el]
		i += 4 + el
		extsList = append(extsList, uint16(et))
		switch et {
		case 0x0000: // server_name
			sni = parseSNI(ev)
		case 0x0010: // application_layer_protocol_negotiation
			alpn = parseALPN(ev)
		case 0x000a: // supported_groups
			curves = parseCurves(ev)
		case 0x000b: // ec_point_formats
			formats = parseECFormats(ev)
		}
	}

	return Sniffed{
		Kind: KindTLS,
		SNI:  sni,
		JA3:  ja3(clientVer, ciphers, extsList, curves, formats),
		ALPN: alpn,
	}, nil
}

// helloReader bounds-checks every ClientHello field read. ok is false once
// the message is shorter than its declared structure; readers then report
// zero values and keep ok false.
type helloReader struct {
	b   []byte
	off int
	ok  bool
}

func (r *helloReader) u8() byte {
	if !r.ok || r.off >= len(r.b) {
		r.ok = false
		return 0
	}
	v := r.b[r.off]
	r.off++
	return v
}

func (r *helloReader) u16() uint16 {
	if !r.ok || r.off+2 > len(r.b) {
		r.ok = false
		return 0
	}
	v := uint16(r.b[r.off])<<8 | uint16(r.b[r.off+1])
	r.off += 2
	return v
}

func (r *helloReader) skip(n int) {
	if !r.ok || n < 0 || r.off+n > len(r.b) {
		r.ok = false
		return
	}
	r.off += n
}

func (r *helloReader) take(n int) []byte {
	if !r.ok || n < 0 || r.off+n > len(r.b) {
		r.ok = false
		return nil
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v
}

func parseSNI(ev []byte) string {
	// server_name_list (2 bytes) + entries
	if len(ev) < 2 {
		return ""
	}
	listLen := int(ev[0])<<8 | int(ev[1])
	if len(ev) < 2+listLen {
		return ""
	}
	entries := ev[2 : 2+listLen]
	for j := 0; j+3 <= len(entries); {
		nameType := entries[j]
		nameLen := int(entries[j+1])<<8 | int(entries[j+2])
		if nameType != 0 {
			return ""
		}
		if j+3+nameLen > len(entries) {
			return ""
		}
		return string(entries[j+3 : j+3+nameLen])
	}
	return ""
}

func parseALPN(ev []byte) []string {
	if len(ev) < 2 {
		return nil
	}
	listLen := int(ev[0])<<8 | int(ev[1])
	if len(ev) < 2+listLen {
		return nil
	}
	data := ev[2 : 2+listLen]
	var out []string
	for j := 0; j < len(data); {
		l := int(data[j])
		j++
		if j+l > len(data) {
			break
		}
		out = append(out, string(data[j:j+l]))
		j += l
	}
	return out
}

func parseCurves(ev []byte) []uint16 {
	if len(ev) < 2 {
		return nil
	}
	listLen := int(ev[0])<<8 | int(ev[1])
	if len(ev) < 2+listLen || listLen%2 != 0 {
		return nil
	}
	data := ev[2 : 2+listLen]
	var out []uint16
	for j := 0; j+2 <= len(data); j += 2 {
		out = append(out, uint16(data[j])<<8|uint16(data[j+1]))
	}
	return out
}

func parseECFormats(ev []byte) []uint8 {
	if len(ev) < 2 {
		return nil
	}
	listLen := int(ev[0])
	if len(ev) < 1+listLen {
		return nil
	}
	return ev[1 : 1+listLen]
}

func ja3(clientVer uint16, ciphers []uint16, exts []uint16, curves []uint16, formats []uint8) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d,%d,%d,%d,%d", clientVer, len(ciphers), len(exts), len(curves), len(formats))
	for _, c := range ciphers {
		fmt.Fprintf(&b, "-%d", c)
	}
	for _, e := range exts {
		fmt.Fprintf(&b, "-%d", e)
	}
	for _, c := range curves {
		fmt.Fprintf(&b, "-%d", c)
	}
	for _, f := range formats {
		fmt.Fprintf(&b, "-%d", f)
	}
	return b.String()
}
