package store

import (
	"testing"
	"time"
)

func TestStoreMarkAndLookup(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/index.db")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	if err := s.MarkPatch("192.0.2.9", "device.local", "cert_rejected", now); err != nil {
		t.Fatal(err)
	}
	ok, err := s.IsPatch("192.0.2.9", "device.local")
	if err != nil || !ok {
		t.Fatalf("IsPatch = %v, %v; want true, nil", ok, err)
	}
	// Different host for same IP is not patched.
	ok, _ = s.IsPatch("192.0.2.9", "other.local")
	if ok {
		t.Fatal("different host should not be patched")
	}
}

func TestStoreRecheckInterval(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/index.db")
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(1700000000, 0)
	if err := s.MarkPatch("192.0.2.1", "a.local", "mtls", t0); err != nil {
		t.Fatal(err)
	}
	// 719h in (< 720h interval): nothing due yet.
	pairs, err := s.Recheck(t0.Add(719*time.Hour), 720*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 0 {
		t.Fatalf("Recheck = %v, want none before interval", pairs)
	}
	// 721h in (> interval): the pair is due.
	pairs, err = s.Recheck(t0.Add(721*time.Hour), 720*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 1 || pairs[0].Reason != "mtls" {
		t.Fatalf("Recheck = %v, want one mtls pair", pairs)
	}
}

func TestStoreUnmark(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/index.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkPatch("192.0.2.2", "b.local", "other", time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}
	if err := s.Unmark("192.0.2.2", "b.local"); err != nil {
		t.Fatal(err)
	}
	ok, err := s.IsPatch("192.0.2.2", "b.local")
	if err != nil || ok {
		t.Fatalf("IsPatch after Unmark = %v, %v; want false, nil", ok, err)
	}
}
