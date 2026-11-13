package tlsutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"
)

// testAIA is a minimal AuthorityInfoAccessSyntax with one OCSP entry,
// encoded as x509.ParseCertificate expects: IMPLICIT context tag [6] over
// the URL bytes.
func testAIA(t *testing.T) []byte {
	t.Helper()
	oid, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1})
	if err != nil {
		t.Fatal(err)
	}
	url := "http://ocsp.example"
	uri := append([]byte{0x86, byte(len(url))}, url...)
	entry := make([]byte, 0, len(oid)+len(uri)+2)
	entry = append(entry, 0x30, byte(len(oid)+len(uri)))
	entry = append(entry, oid...)
	entry = append(entry, uri...)
	aia := make([]byte, 0, len(entry)+2)
	aia = append(aia, 0x30, byte(len(entry)))
	return append(aia, entry...)
}

// buildIntermediate returns a self-signed intermediate cert + signer with a
// P-256 ECDSA key (the fixture's key type).
func buildIntermediate(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return buildIntermediateWithKey(t, priv)
}

// buildIntermediateWithKey self-signs the test intermediate with priv, so
// tests can exercise non-EC intermediates (RSA, ed25519).
func buildIntermediateWithKey(t *testing.T, priv crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "eMudhra G3 (compromised)"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	// Give the test intermediate an AIA extension (IA5String URI, as in
	// real certificates) so the leaf's inheritance of it is observable.
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: aiaOID, Value: testAIA(t)})
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv
}

func TestMintLeafFreshKey(t *testing.T) {
	inter, key := buildIntermediate(t)
	now := time.Now()
	leaf, leafKey, err := MintLeaf(inter, key, "example.com", "", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	leafPub, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	interPub, err := x509.MarshalPKIXPublicKey(inter.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(leafPub, interPub) {
		t.Fatal("leaf public key equals the intermediate's public key (forgery tell)")
	}
	leafKeyPub, err := x509.MarshalPKIXPublicKey(leafKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leafPub, leafKeyPub) {
		t.Fatal("returned key's public key does not match the leaf's public key")
	}
	// The returned key is a working signer for the leaf: sign/verify
	// roundtrip against the leaf's own public key.
	msg := []byte("fix-i1 signer roundtrip")
	digest := sha256.Sum256(msg)
	sig, err := leafKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("leaf key Sign: %v", err)
	}
	if err := leaf.CheckSignature(x509.ECDSAWithSHA256, msg, sig); err != nil {
		t.Fatalf("leaf does not verify the returned key's signature: %v", err)
	}
}

// TestMintLeafSignedByIntermediate is a regression guard for finding I1:
// despite having its own keypair, the leaf must remain genuinely signed by
// the intermediate.
func TestMintLeafSignedByIntermediate(t *testing.T) {
	inter, key := buildIntermediate(t)
	now := time.Now()
	leaf, _, err := MintLeaf(inter, key, "example.com", "", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	if err := leaf.CheckSignatureFrom(inter); err != nil {
		t.Fatalf("leaf.CheckSignatureFrom(intermediate): %v", err)
	}
}

// TestMintLeafKeyFollowsIntermediate pins the leaf key type to the
// intermediate's key type: ECDSA intermediate ⇒ P-256 leaf key, RSA
// intermediate ⇒ 2048-bit leaf key, any other intermediate key type ⇒ error.
func TestMintLeafKeyFollowsIntermediate(t *testing.T) {
	now := time.Now()
	sub := now.Add(-time.Hour)

	assertLeafKeyMatches := func(t *testing.T, leaf *x509.Certificate, leafKey crypto.Signer) {
		t.Helper()
		leafPub, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		keyPub, err := x509.MarshalPKIXPublicKey(leafKey.Public())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(leafPub, keyPub) {
			t.Fatal("returned key's public key does not match the leaf's public key")
		}
	}

	t.Run("ECDSA", func(t *testing.T) {
		inter, key := buildIntermediate(t) // P-256 ECDSA fixture
		leaf, leafKey, err := MintLeaf(inter, key, "example.com", "", sub, now)
		if err != nil {
			t.Fatalf("MintLeaf: %v", err)
		}
		assertLeafKeyMatches(t, leaf, leafKey)
		lk, ok := leafKey.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("leaf key type = %T, want *ecdsa.PrivateKey", leafKey)
		}
		if lk.Curve != elliptic.P256() {
			t.Fatalf("leaf key = ECDSA on %s, want P-256", lk.Curve.Params().Name)
		}
	})

	t.Run("RSA", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		inter, key := buildIntermediateWithKey(t, priv)
		leaf, leafKey, err := MintLeaf(inter, key, "example.com", "", sub, now)
		if err != nil {
			t.Fatalf("MintLeaf: %v", err)
		}
		assertLeafKeyMatches(t, leaf, leafKey)
		lk, ok := leafKey.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("leaf key type = %T, want *rsa.PrivateKey", leafKey)
		}
		if lk.N.BitLen() != 2048 {
			t.Fatalf("leaf key = RSA %d, want RSA 2048", lk.N.BitLen())
		}
	})

	t.Run("unsupported", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		inter, key := buildIntermediateWithKey(t, priv)
		if _, _, err := MintLeaf(inter, key, "example.com", "", sub, now); err == nil {
			t.Fatal("MintLeaf must reject an intermediate key type that is not ECDSA or RSA")
		}
	})
}

func TestMintLeafHostname(t *testing.T) {
	inter, key := buildIntermediate(t)
	now := time.Now()
	leaf, leafKey, err := MintLeaf(inter, key, "example.com", "93.184.216.34", now.Add(-7*24*time.Hour), now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	if leaf.Subject.CommonName != "example.com" {
		t.Fatalf("CN = %q, want example.com", leaf.Subject.CommonName)
	}
	if !leaf.BasicConstraintsValid || leaf.IsCA {
		t.Fatal("leaf must be a non-CA")
	}
	// The leaf's SubjectKeyId is derived from the leaf's own key (finding
	// I1): with the old contract this pinned the intermediate's key.
	pub, err := x509.MarshalPKIXPublicKey(leafKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	wantSKI := sha256.Sum256(pub)
	if !bytes.Equal(leaf.SubjectKeyId, wantSKI[:]) {
		t.Fatalf("SubjectKeyId = %x, want %x", leaf.SubjectKeyId, wantSKI)
	}
	if got, want := extValue(leaf, aiaOID), extValue(inter, aiaOID); len(want) == 0 || !bytes.Equal(got, want) {
		t.Fatalf("leaf AIA = %x, want the intermediate's %x", got, want)
	}
	if !slices.Contains(leaf.DNSNames, "example.com") {
		t.Fatalf("DNSNames = %v, want example.com", leaf.DNSNames)
	}
	if !containsIP(leaf.IPAddresses, net.ParseIP("93.184.216.34")) {
		t.Fatalf("IPAddresses = %v, want 93.184.216.34", leaf.IPAddresses)
	}
	if leaf.NotBefore.After(now.Add(-6*24*time.Hour)) || leaf.NotAfter.Before(now.Add(6*24*time.Hour)) {
		t.Fatalf("validity window out of bounds: %v..%v", leaf.NotBefore, leaf.NotAfter)
	}
	// Verify the leaf chains to the intermediate.
	roots := x509.NewCertPool()
	roots.AddCert(inter)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "example.com"}); err != nil {
		t.Fatalf("leaf does not verify against intermediate: %v", err)
	}
}

func TestMintLeafNoSNI(t *testing.T) {
	inter, key := buildIntermediate(t)
	now := time.Now()
	// No SNI: dst is an IP literal.
	leaf, _, err := MintLeaf(inter, key, "", "192.0.2.5", now.Add(-7*24*time.Hour), now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	if leaf.Subject.CommonName != "192.0.2.5" {
		t.Fatalf("CN = %q, want 192.0.2.5", leaf.Subject.CommonName)
	}
	if !containsIP(leaf.IPAddresses, net.ParseIP("192.0.2.5")) {
		t.Fatalf("IPAddresses = %v, want 192.0.2.5", leaf.IPAddresses)
	}
}

// extValue returns the raw value of the first extension with oid.
func extValue(c *x509.Certificate, oid asn1.ObjectIdentifier) []byte {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return e.Value
		}
	}
	return nil
}

func containsIP(haystack []net.IP, needle net.IP) bool {
	for _, h := range haystack {
		if h.Equal(needle) {
			return true
		}
	}
	return false
}
