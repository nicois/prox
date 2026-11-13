package tlsutil

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubmitSCTEmbedsExtension(t *testing.T) {
	leafDER := []byte("leaf-bytes")
	interDER := []byte("intermediate-bytes")
	extraDER := []byte("extra-chain-cert")
	// Mock CT log returning one fake SCT; rejects a chain that is not
	// exactly [intermediate, extra] (pins the full issuer path).
	var gotChain []string
	logServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			LeafInput string
			Chain     []string
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		gotChain = body.Chain
		if len(body.Chain) != 2 || body.Chain[0] != b64(interDER) || body.Chain[1] != b64(extraDER) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
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

	sctList, err := SubmitSCT(context.Background(), logServer.Client(), logServer.URL, leafDER, [][]byte{interDER, extraDER})
	if err != nil {
		t.Fatalf("SubmitSCT: %v", err)
	}
	if len(sctList) == 0 {
		t.Fatal("SubmitSCT returned empty SCT list")
	}
	if len(gotChain) != 2 || gotChain[0] != b64(interDER) || gotChain[1] != b64(extraDER) {
		t.Fatalf("log received chain %q, want [intermediate, extra]", gotChain)
	}

	tmpl := &x509.Certificate{}
	EmbedSCT(tmpl, sctList)
	if len(tmpl.ExtraExtensions) == 0 {
		t.Fatal("EmbedSCT did not append an extension")
	}
	// The appended extension must carry the CT OID and the SCT list as its value.
	found := false
	for _, ext := range tmpl.ExtraExtensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}) && bytes.Equal(ext.Value, sctList) {
			found = true
		}
	}
	if !found {
		t.Fatal("CT extension OID 1.3.6.1.4.1.11129.2.4.2 not present")
	}
}
