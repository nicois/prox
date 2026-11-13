package prox

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureDataDocConvergent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "AGENTS.md")

	ensureDataDoc(dir, 0o700)
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("first install: %v", err)
	}
	if !bytes.Equal(got, dataModelDoc) {
		t.Fatal("installed content differs from embedded doc")
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}

	// Same content: no rewrite (startup must not churn the file).
	ensureDataDoc(dir, 0o700)
	fi2, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(fi2.ModTime()) {
		t.Fatal("identical content rewritten on second call")
	}

	// Diverged content: replaced.
	if err := os.WriteFile(target, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	ensureDataDoc(dir, 0o700)
	got, err = os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dataModelDoc) {
		t.Fatal("stale content not replaced")
	}
}
