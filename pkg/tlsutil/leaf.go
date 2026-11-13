// Package tlsutil mints forged per-host leaf certificates: a fresh leaf
// keypair per mint (key type following the intermediate's), the
// intermediate's AIA (OCSP/CRL URLs) inherited so clients follow the
// genuine CA's revocation paths, and — when a CT log is configured — the
// log's SCT embedded before the leaf is served.
package tlsutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"time"
)

// aiaOID is AuthorityInformationAccess (1.3.6.1.5.5.7.1.1): a forged leaf
// inherits the real intermediate's AIA so clients follow the genuine CA's
// OCSP/CRL paths.
var aiaOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}

// buildSANs derives SubjectAltName entries from the SNI (host) and the
// original destination (dst). host may be empty. A host that parses as an IP
// becomes an iPAddress SAN; otherwise a dNSName. dst is added when it differs
// from host, again as an IP or a hostname depending on its form.
func buildSANs(host, dst string) (dns []string, ips []net.IP) {
	if host != "" {
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, host)
		}
	}
	if dst != "" && dst != host {
		if ip := net.ParseIP(dst); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, dst)
		}
	}
	return dns, ips
}

// MintLeaf forges a leaf certificate signed by the compromised intermediate
// (key) for a single TLS connection. The leaf has its own keypair, generated
// from the intermediate's key type (ECDSA ⇒ P-256, RSA ⇒ 2048 bits; any other
// intermediate key type is an error) and signed by the intermediate, so the
// leaf's public key and SubjectKeyId are its own rather than the issuer's.
// The leaf's SANs cover the SNI (host) and the original destination (dst);
// CN is host when present else dst. The leaf is a non-CA server-auth
// certificate valid in [notBefore, notAfter]. It returns the leaf
// certificate and the leaf's private key.
func MintLeaf(intermediate *x509.Certificate, key crypto.Signer, host, dst string, notBefore, notAfter time.Time) (*x509.Certificate, crypto.Signer, error) {
	dns, ips := buildSANs(host, dst)
	cn := host
	if cn == "" {
		cn = dst
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	leafKey, err := newLeafKey(key.Public())
	if err != nil {
		return nil, nil, err
	}
	// Go only fills SubjectKeyId for CAs; server certificates should carry
	// one (OCSP and AIA consumers expect it).
	pubKey, err := x509.MarshalPKIXPublicKey(leafKey.Public())
	if err != nil {
		return nil, nil, err
	}
	ski := sha256.Sum256(pubKey)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dns,
		IPAddresses:           ips,
		SubjectKeyId:          ski[:],
	}
	if aia, ok := buildAIA(intermediate); ok {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, aia)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, intermediate, leafKey.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, leafKey, nil
}

// newLeafKey generates the fresh keypair a forged leaf gets, following the
// intermediate's key type: ECDSA ⇒ P-256, RSA ⇒ 2048 bits. Any other
// intermediate key type is unsupported and an error.
func newLeafKey(interKey any) (crypto.Signer, error) {
	switch interKey.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case *rsa.PublicKey:
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unsupported intermediate key type %T", interKey)
	}
}

var (
	ocspOID      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	caIssuersOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

// buildAIA rebuilds the AIA extension from the intermediate's parsed OCSP
// and ca-issuer URLs: x509.ParseCertificate consumes AIA into fields, so it
// is not present in ExtraExtensions. URIs are encoded as IA5String, as
// RFC 5280 requires for accessLocation (asn1.Marshal's default string type
// is not IA5String and is not extracted back by x509.ParseCertificate).
func buildAIA(inter *x509.Certificate) (pkix.Extension, bool) {
	if len(inter.OCSPServer) == 0 && len(inter.CRLDistributionPoints) == 0 {
		return pkix.Extension{}, false
	}
	var content []byte
	addEntry := func(oid asn1.ObjectIdentifier, url string) {
		oidDER, err := asn1.Marshal(oid)
		if err != nil {
			return
		}
		// accessLocation is a GeneralName: uniformResourceIdentifier is
		// the URL bytes under an IMPLICIT context tag [6] (0x86), per the
		// IMPLICIT tagging in RFC 5280 4.2.1.6.
		uri := append([]byte{0x86, byte(len(url))}, url...)
		entry := make([]byte, 0, len(oidDER)+len(uri)+2)
		entry = append(entry, 0x30, byte(len(oidDER)+len(uri)))
		entry = append(entry, oidDER...)
		entry = append(entry, uri...)
		content = append(content, entry...)
	}
	for _, u := range inter.OCSPServer {
		addEntry(ocspOID, u)
	}
	for _, u := range inter.CRLDistributionPoints {
		addEntry(caIssuersOID, u)
	}
	if len(content) == 0 {
		return pkix.Extension{}, false
	}
	der := make([]byte, 0, len(content)+2)
	der = append(der, 0x30, byte(len(content)))
	der = append(der, content...)
	return pkix.Extension{Id: aiaOID, Value: der}, true
}

func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
