package tlsutil

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

// ctExtOID is 1.3.6.1.4.1.11129.2.4.2 (ct_precertificateSct).
var ctExtOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// sctJSON is one SCT as returned by a CT log's JSON API (RFC 6962 §2.1).
type sctJSON struct {
	ID struct {
		KeyID string `json:"key_id"`
	} `json:"id"`
	Timestamp  int64  `json:"timestamp"`
	Extensions string `json:"extensions"`
	Signature  string `json:"signature"`
}

type ctLogResponse struct {
	SCTs []sctJSON `json:"scts"`
}

// SubmitSCT posts the leaf with its issuer chain to a CT log's addchain
// endpoint and returns the DER of the SignedCertificateTimestampList. Logs
// require the chain to reach a self- or cross-signed trust anchor, so chain
// must be the full issuer path (intermediate + any extra chain certs).
func SubmitSCT(ctx context.Context, client *http.Client, logURL string, leafDER []byte, chain [][]byte) ([]byte, error) {
	chains := make([]string, len(chain))
	for i, der := range chain {
		chains[i] = b64(der)
	}
	reqBody := struct {
		LeafInput string   `json:"leaf_input"`
		Chain     []string `json:"chain"`
	}{
		LeafInput: b64(leafDER),
		Chain:     chains,
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(reqBody); err != nil {
		return nil, err
	}
	url := logURL + "/ct/v1/addchain"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ct log %s returned %d", url, resp.StatusCode)
	}
	var out ctLogResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return marshalSCTList(out.SCTs)
}

// marshalSCTList encodes the log's SCTs into the RFC 6962
// SignedCertificateTimestampList structure.
func marshalSCTList(scts []sctJSON) ([]byte, error) {
	type logID struct {
		Version int
		KeyID   []byte
	}
	type sct struct {
		Version    int
		LogID      logID
		Timestamp  int64
		Extensions []byte
		Signature  asn1.RawValue
	}
	list := make([]sct, len(scts))
	for i, in := range scts {
		keyID, err := base64.StdEncoding.DecodeString(in.ID.KeyID)
		if err != nil {
			return nil, fmt.Errorf("sct[%d] key_id: %w", i, err)
		}
		ext, err := base64.StdEncoding.DecodeString(in.Extensions)
		if err != nil {
			return nil, fmt.Errorf("sct[%d] extensions: %w", i, err)
		}
		sig, err := base64.StdEncoding.DecodeString(in.Signature)
		if err != nil {
			return nil, fmt.Errorf("sct[%d] signature: %w", i, err)
		}
		list[i] = sct{
			Version:    0, // CTVersion is 0 (RFC 6962 §2.1)
			LogID:      logID{Version: 0, KeyID: keyID},
			Timestamp:  in.Timestamp,
			Extensions: ext,
			Signature:  asn1.RawValue{FullBytes: sig},
		}
	}
	return asn1.Marshal(list)
}

// EmbedSCT appends the SCT list extension (OID 1.3.6.1.4.1.11129.2.4.2) to
// tmpl.ExtraExtensions and returns tmpl.
func EmbedSCT(tmpl *x509.Certificate, sctList []byte) *x509.Certificate {
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: ctExtOID, Value: sctList})
	return tmpl
}

func b64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
