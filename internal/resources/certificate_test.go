package resources

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/camptocamp/go-puppetca/puppetca"
)

// One self-signed cert serves as server cert, client cert and CA.
func selfSigned(t *testing.T) (certPEM, keyPEM string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
}

func TestDeleteCertRevokesFirst(t *testing.T) {
	for _, tc := range []struct {
		revokeStatus int
		wantErr      bool
		wantCalls    []string
	}{
		{http.StatusNoContent, false, []string{"PUT {\"desired_state\":\"revoked\"}", "DELETE "}},
		{http.StatusConflict, false, []string{"PUT {\"desired_state\":\"revoked\"}", "DELETE "}},
		{http.StatusNotFound, false, []string{"PUT {\"desired_state\":\"revoked\"}", "DELETE "}},
		{http.StatusForbidden, true, []string{"PUT {\"desired_state\":\"revoked\"}"}}, // must not delete unrevoked
	} {
		var calls []string
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/puppet-ca/v1/certificate_status/node.example" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			body, _ := io.ReadAll(r.Body)
			calls = append(calls, r.Method+" "+string(body))
			if r.Method == http.MethodPut {
				w.WriteHeader(tc.revokeStatus)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		certPEM, keyPEM := selfSigned(t)
		pair, _ := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
		srv.StartTLS()

		client, err := puppetca.NewClient(srv.URL, keyPEM, certPEM, certPEM)
		if err != nil {
			t.Fatal(err)
		}
		err = deleteCert(context.Background(), &client, "node.example", "")
		srv.Close()

		if (err != nil) != tc.wantErr {
			t.Errorf("status %d: err = %v, wantErr %v", tc.revokeStatus, err, tc.wantErr)
		}
		if len(calls) != len(tc.wantCalls) {
			t.Fatalf("status %d: calls = %q, want %q", tc.revokeStatus, calls, tc.wantCalls)
		}
		for i := range calls {
			if calls[i] != tc.wantCalls[i] {
				t.Errorf("status %d: call %d = %q, want %q", tc.revokeStatus, i, calls[i], tc.wantCalls[i])
			}
		}
	}
}
