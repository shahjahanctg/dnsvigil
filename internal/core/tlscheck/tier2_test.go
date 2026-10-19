package tlscheck

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/dnsvigil/dnsvigil/internal/core/finding"
)

func mustTestPair(t *testing.T) (*x509.Certificate, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, &caTmpl, &caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, &leafTmpl, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)
	return leaf, ca, caKey
}

func TestFingerprintFinding(t *testing.T) {
	leaf, _, _ := mustTestPair(t)
	f := fingerprintFinding(leaf)
	if f.Kind != "tls-fingerprint" || len(f.What) != len("sha256=")+64 {
		t.Errorf("fingerprint finding malformed: %+v", f)
	}
	if f.Detail == "" || !strings.Contains(f.Detail, "serial=") {
		t.Errorf("fingerprint detail should carry serial: %q", f.Detail)
	}
}

func TestSCTFinding(t *testing.T) {
	none := sctFinding(tls.ConnectionState{})
	if none.What != "no ct log entry" || none.Severity != finding.SeverityInfo {
		t.Errorf("no-SCT finding = %+v", none)
	}
	has := sctFinding(tls.ConnectionState{SignedCertificateTimestamps: [][]byte{{1}, {2}}})
	if has.What != "ct log entry present" || has.Detail != "scts=2" {
		t.Errorf("SCT finding = %+v", has)
	}
}

func TestStaplingFindings(t *testing.T) {
	empty := staplingFindings(tls.ConnectionState{}, Context{})
	if len(empty) != 1 || empty[0].What != "no OCSP staple" {
		t.Errorf("no staple without revocation should be one INFO finding: %+v", empty)
	}
	// With CheckRevocation and no OCSP endpoint: still INFO, no query attempted.
	leaf, _, _ := mustTestPair(t)
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	withRev := staplingFindings(state, Context{CheckRevocation: true})
	if len(withRev) != 2 || withRev[1].Kind != "tls-revocation" {
		t.Errorf("revocation-without-staple should add a tls-revocation finding: %+v", withRev)
	}
}

func TestOCSPResponseFindingsGoodAndRevoked(t *testing.T) {
	_, issuer, issuerKey := mustTestPair(t)

	build := func(status int) []byte {
		resp, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{
			Status:       status,
			SerialNumber: big.NewInt(3),
			ThisUpdate:   time.Now().Add(-time.Hour),
			NextUpdate:   time.Now().Add(time.Hour),
		}, issuerKey)
		if err != nil {
			t.Fatalf("CreateResponse: %v", err)
		}
		return resp
	}

	good := ocspResponseFindings(build(ocsp.Good))
	if len(good) != 1 || good[0].Severity != finding.SeverityInfo || good[0].What != "ocsp good" {
		t.Errorf("good response classification = %+v", good)
	}

	revoked := ocspResponseFindings(build(ocsp.Revoked))
	if len(revoked) != 1 || revoked[0].Severity != finding.SeverityCritical || revoked[0].What != "revoked" {
		t.Errorf("revoked response classification = %+v", revoked)
	}

	garbage := ocspResponseFindings([]byte("not a response"))
	if garbage[0].Severity != finding.SeverityLow {
		t.Errorf("unreadable response must be Low: %+v", garbage)
	}

	_ = issuer
}
