package sniff

import "testing"

// TestSniffMalformedHello pins the remotely triggerable panic regression:
// crafted ClientHellos with inconsistent lengths must return an error, not
// panic (Sniff runs on the first bytes of every accepted connection).
func TestSniffMalformedHello(t *testing.T) {
	// Record: type 0x16, version 0x0301, payload length 0x002f (47).
	rec := func(payload []byte) []byte {
		out := []byte{0x16, 0x03, 0x01, byte(len(payload) >> 8), byte(len(payload))}
		return append(out, payload...)
	}

	pkts := [][]byte{
		// Handshake msgLen 4: the trimmed ClientHello body is 4 bytes, so
		// every field read past the client version overflows.
		rec(append([]byte{0x16, 0x00, 0x00, 0x04}, make([]byte, 43)...)),

		// Full fixed prefix (client version + random + sidLen 0 + cipherLen 0
		// + compLen 0) with extLen 0xFFFE: the extensions slice bounds-check
		// must reject, not panic.
		rec(append(
			[]byte{0x16, 0x00, 0x00, 0x28, 0x03, 0x01},    // type, msgLen 40, client version
			append(make([]byte, 32+1+2+1), 0xFF, 0xFE)..., // random, sidLen, cipherLen, compLen, extLen 65534
		)),

		// extLen 4 with a first extension claiming 65535 bytes of content:
		// the per-extension length must be bounds-checked inside the loop.
		rec(append(
			[]byte{0x16, 0x00, 0x00, 0x2c, 0x03, 0x01},                            // type, msgLen 44, client version
			append(make([]byte, 32+1+2+1), 0x00, 0x04, 0x00, 0x00, 0xFF, 0xFF)..., // ...fixed prefix, extLen 4, extension overrun
		)),
	}
	for i, pkt := range pkts {
		if _, err := Sniff(pkt); err == nil {
			t.Errorf("case %d: malformed ClientHello accepted", i)
		}
	}
}

// FuzzSniff must never panic on arbitrary input.
func FuzzSniff(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x2f, 0x16, 0x00, 0x00, 0x04})
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add(captureHello(f, "example.com", nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Sniff(b)
	})
}
