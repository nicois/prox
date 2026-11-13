package tlsutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nicois/prox/pkg/config"
)

func writePEM(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return p
}

// testCA builds a self-signed intermediate and returns its cert and key DER.
func testCA(t *testing.T) (certDER, keyDER []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err = x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	return certDER, keyDER
}

// assertServedKeyIsLeafKey pins the served tls.Certificate to the fix for
// finding I1: the served PrivateKey's public key matches the served leaf
// cert's public key and is not the intermediate's own public key.
func assertServedKeyIsLeafKey(t *testing.T, leaf *tls.Certificate, interDER []byte) {
	t.Helper()
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse served leaf: %v", err)
	}
	signer, ok := leaf.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("served PrivateKey type %T does not implement crypto.Signer", leaf.PrivateKey)
	}
	servedPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	leafPub, err := x509.MarshalPKIXPublicKey(leafCert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(servedPub, leafPub) {
		t.Fatal("served key's public key does not match the served leaf's public key")
	}
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}
	interPub, err := x509.MarshalPKIXPublicKey(inter.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(servedPub, interPub) {
		t.Fatal("served key is the intermediate's own key (forgery tell)")
	}
}

// TestProviderServesLeafKey pins the fix for security finding I1 at the
// provider level: the served tls.Certificate carries the leaf's own private
// key, not the intermediate's.
func TestProviderServesLeafKey(t *testing.T) {
	certDER, keyDER := testCA(t)
	dir := t.TempDir()
	p, err := NewProvider([]config.CAPath{{
		CertPEM: writePEM(t, dir, "inter.crt", "CERTIFICATE", certDER),
		KeyPEM:  writePEM(t, dir, "inter.key", "EC PRIVATE KEY", keyDER),
	}}, config.MITM{ValidityDays: 7, ReintBeforeExpiry: 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	leaf, err := p.Leaf("example.com", "93.184.216.34", time.Now())
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	assertServedKeyIsLeafKey(t, leaf, certDER)
}

// TestProviderServesLeafKeyWithSCT pins that the CT re-issue preserves the
// leaf's own public key: after withSCT embeds an SCT, the served leaf still
// matches the served key, still verifies against the intermediate, and is
// not the intermediate's key.
func TestProviderServesLeafKeyWithSCT(t *testing.T) {
	certDER, keyDER := testCA(t)
	// Mock CT log: accepts any submission and returns one fake SCT, like
	// TestSubmitSCTEmbedsExtension.
	logServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"scts": []map[string]any{
				{
					"sct_version": "0",
					"id":          map[string]any{"key_id": "AAAA"},
					"timestamp":   1700000000000,
					"extensions":  "",
					"signature":   "BQIA",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer logServer.Close()

	dir := t.TempDir()
	p, err := NewProvider([]config.CAPath{{
		CertPEM: writePEM(t, dir, "inter.crt", "CERTIFICATE", certDER),
		KeyPEM:  writePEM(t, dir, "inter.key", "EC PRIVATE KEY", keyDER),
	}}, config.MITM{ValidityDays: 7, CTLogURL: logServer.URL + "/ct"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	leaf, err := p.Leaf("example.com", "93.184.216.34", time.Now())
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	hasSCT := false
	for _, e := range leafCert.Extensions {
		if e.Id.Equal(ctExtOID) {
			hasSCT = true
		}
	}
	if !hasSCT {
		t.Fatal("served leaf has no SCT extension; the CT re-issue did not happen")
	}
	inter, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := leafCert.CheckSignatureFrom(inter); err != nil {
		t.Fatalf("re-issued leaf does not verify against the intermediate: %v", err)
	}
	assertServedKeyIsLeafKey(t, leaf, certDER)
}

func TestProviderLeafMintsAndCaches(t *testing.T) {
	certDER, keyDER := testCA(t)
	dir := t.TempDir()
	p, err := NewProvider([]config.CAPath{{
		CertPEM: writePEM(t, dir, "inter.crt", "CERTIFICATE", certDER),
		KeyPEM:  writePEM(t, dir, "inter.key", "EC PRIVATE KEY", keyDER),
	}}, config.MITM{ValidityDays: 7, ReintBeforeExpiry: 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	now := time.Now()
	leaf1, err := p.Leaf("example.com", "93.184.216.34", now)
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(leaf1.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "example.com" {
		t.Fatalf("CN = %q, want example.com", cert.Subject.CommonName)
	}
	if !slices.Contains(cert.DNSNames, "example.com") {
		t.Fatalf("DNSNames = %v, want example.com", cert.DNSNames)
	}
	if cert.BasicConstraintsValid && cert.IsCA {
		t.Fatal("leaf must be a non-CA")
	}
	// The leaf chains to the intermediate.
	inter, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(inter)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "example.com"}); err != nil {
		t.Fatalf("leaf does not verify against intermediate: %v", err)
	}
	// Cached: same leaf within the reuse window.
	leaf2, err := p.Leaf("example.com", "93.184.216.34", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leaf1.Certificate[0], leaf2.Certificate[0]) {
		t.Fatal("leaf not cached within the reuse window")
	}
	// Different host: a different leaf.
	leaf3, err := p.Leaf("other.example", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(leaf1.Certificate[0], leaf3.Certificate[0]) {
		t.Fatal("different hosts share a leaf")
	}
}

func TestProviderRoundRobin(t *testing.T) {
	certA, keyA := testCA(t)
	certB, keyB := testCA(t)
	dir := t.TempDir()
	p, err := NewProvider([]config.CAPath{
		{CertPEM: writePEM(t, dir, "a.crt", "CERTIFICATE", certA), KeyPEM: writePEM(t, dir, "a.key", "EC PRIVATE KEY", keyA)},
		{CertPEM: writePEM(t, dir, "b.crt", "CERTIFICATE", certB), KeyPEM: writePEM(t, dir, "b.key", "EC PRIVATE KEY", keyB)},
	}, config.MITM{ValidityDays: 7})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	now := time.Now()
	la, err := p.Leaf("a.example", "", now)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := p.Leaf("b.example", "", now)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(la.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	cb, err := x509.ParseCertificate(lb.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ca.AuthorityKeyId, cb.AuthorityKeyId) {
		t.Fatal("two hosts minted by the same CA; expected round-robin")
	}
}

func TestProviderNoCA(t *testing.T) {
	p, err := NewProvider(nil, config.MITM{ValidityDays: 7})
	if err != nil {
		t.Fatalf("NewProvider with no CA must succeed: %v", err)
	}
	if _, err := p.Leaf("example.com", "93.184.216.34", time.Now()); err == nil {
		t.Fatal("Leaf must fail with no CA configured")
	}
}

// issue signs a CA cert for cn with the given parent CA and returns the
// cert and key DER.
func issue(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, serial int64, cn string) (certDER, keyDER []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err = x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, parent, priv.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return certDER, keyDER
}

// TestProviderServesExtraChain verifies a chain_pem cert is appended after
// the intermediate: a client whose trust store holds only the self-signed
// root (e.g. a host ca-certificates bundle that lacks emSign Root TLS CA - G3)
// cannot build the path without it.
func TestProviderServesExtraChain(t *testing.T) {
	rootDER, rootKeyDER := testCA(t)
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := x509.ParseECPrivateKey(rootKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	subrootDER, subrootKeyDER := issue(t, root, rootKey, 2, "Test Subroot")
	subroot, err := x509.ParseCertificate(subrootDER)
	if err != nil {
		t.Fatal(err)
	}
	subrootKey, err := x509.ParseECPrivateKey(subrootKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	interDER, interKeyDER := issue(t, subroot, subrootKey, 3, "Test Intermediate")

	dir := t.TempDir()
	p, err := NewProvider([]config.CAPath{{
		CertPEM:  writePEM(t, dir, "inter.crt", "CERTIFICATE", interDER),
		KeyPEM:   writePEM(t, dir, "inter.key", "EC PRIVATE KEY", interKeyDER),
		ChainPEM: writePEM(t, dir, "subroot.crt", "CERTIFICATE", subrootDER),
	}}, config.MITM{ValidityDays: 7})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	leaf, err := p.Leaf("example.com", "93.184.216.34", time.Now())
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if len(leaf.Certificate) != 3 {
		t.Fatalf("served %d certs, want 3 (leaf, intermediate, chain)", len(leaf.Certificate))
	}
	if !bytes.Equal(leaf.Certificate[1], interDER) {
		t.Fatal("served chain[1] is not the intermediate")
	}
	if !bytes.Equal(leaf.Certificate[2], subrootDER) {
		t.Fatal("served chain[2] is not the chain_pem cert")
	}
	lcert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}
	// Client whose store holds only the root verifies with the served chain.
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(inter)
	intermediates.AddCert(subroot)
	if _, err := lcert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "example.com"}); err != nil {
		t.Fatalf("leaf does not verify with the served chain: %v", err)
	}
	// Negative control: without the chain_pem cert the path cannot be built.
	noSub := x509.NewCertPool()
	noSub.AddCert(inter)
	if _, err := lcert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: noSub, DNSName: "example.com"}); err == nil {
		t.Fatal("leaf unexpectedly verified without the chain_pem cert")
	}
}
