package tlsutil

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nicois/prox/pkg/config"
)

// TestProviderLogsSCTFallback pins the operator-visible log when the CT log
// is unreachable: the leaf is still served (SCT-less) and a warning records
// the fallback with the log URL.
func TestProviderLogsSCTFallback(t *testing.T) {
	certDER, keyDER := testCA(t)
	dir := t.TempDir()
	p, err := NewProvider([]config.CAPath{{
		CertPEM: writePEM(t, dir, "inter.crt", "CERTIFICATE", certDER),
		KeyPEM:  writePEM(t, dir, "inter.key", "EC PRIVATE KEY", keyDER),
	}}, config.MITM{
		ValidityDays:      7,
		ReintBeforeExpiry: 24 * time.Hour,
		CTLogURL:          "http://127.0.0.1:9/ct", // closed port: fast refusal
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })

	leaf, err := p.Leaf("example.com", "93.184.216.34", time.Now())
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if leaf == nil {
		t.Fatal("leaf is nil after CT failure")
	}
	out := buf.String()
	if !strings.Contains(out, `"msg":"sct"`) {
		t.Fatalf("missing sct event: %s", out)
	}
	if !strings.Contains(out, `"embedded":false`) {
		t.Fatalf("missing embedded=false fallback: %s", out)
	}
	if !strings.Contains(out, `"url":"http://127.0.0.1:9/ct"`) {
		t.Fatalf("missing ct log url in fallback: %s", out)
	}
}
