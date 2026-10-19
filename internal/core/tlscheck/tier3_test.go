package tlscheck

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soc-tool/internal/core/finding"
	"github.com/soc-tool/internal/core/target"
)

// targetFor parses a target for tests that only need an address.
func targetFor(t *testing.T, addr string) target.Target {
	t.Helper()
	got, err := target.ParseTarget(addr)
	if err != nil {
		t.Fatalf("parse target %q: %v", addr, err)
	}
	return got
}

func synthCert(t *testing.T, opts ...func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	cert := &x509.Certificate{
		SerialNumber:       big.NewInt(11),
		Subject:            pkix.Name{CommonName: "example.test"},
		Issuer:             pkix.Name{CommonName: "Test CA"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKey:          &key.PublicKey,
		RawIssuer:          []byte("issuer"),
		RawSubject:         []byte("subject"),
	}
	for _, o := range opts {
		o(cert)
	}
	return cert
}

func TestSignatureStrengthWeakSHA1IsHigh(t *testing.T) {
	// FR-C13: SHA-1 (and MD5) signatures must be flagged High.
	weak := synthCert(t, func(c *x509.Certificate) { c.SignatureAlgorithm = x509.SHA1WithRSA })
	got := signatureStrengthFindings(weak)
	if len(got) != 2 || got[0].Kind != "tls-signature" {
		t.Fatalf("signature findings = %+v", got)
	}
	if got[0].Severity != finding.SeverityHigh || !strings.Contains(strings.ToLower(got[0].Because), "sha-1") {
		t.Errorf("SHA-1 must be High with a plain-language reason: %+v", got[0])
	}

	strong := signatureStrengthFindings(synthCert(t))
	if strong[0].Severity != finding.SeverityInfo {
		t.Errorf("SHA-256 signature should be Info: %+v", strong[0])
	}
}

func TestSignatureStrengthWeakShortKeyIsHigh(t *testing.T) {
	short, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa 1024: %v", err)
	}
	cert := synthCert(t, func(c *x509.Certificate) { c.PublicKey = &short.PublicKey })
	got := signatureStrengthFindings(cert)
	if len(got) != 2 || got[1].Kind != "tls-key" {
		t.Fatalf("key findings = %+v", got)
	}
	if got[1].Severity != finding.SeverityHigh || !strings.Contains(got[1].What, "RSA-1024") {
		t.Errorf("1024-bit RSA must be flagged High: %+v", got[1])
	}
}

func TestChainCompleteness(t *testing.T) {
	// FR-C17: leaf-only presentation with an external issuer, an ordered
	// chain, and a misordered chain are three distinct outcomes.
	leaf := synthCert(t, func(c *x509.Certificate) {
		c.RawSubject = []byte("leaf")
		c.RawIssuer = []byte("intermediate")
	})
	only := chainCompletenessFinding([]*x509.Certificate{leaf}, nil)
	if only.Kind != "tls-chain-incomplete" || only.Severity != finding.SeverityMedium {
		t.Errorf("leaf-only chain = %+v", only)
	}

	inter := synthCert(t, func(c *x509.Certificate) {
		c.RawSubject = []byte("intermediate")
		c.RawIssuer = []byte("root")
	})
	root := synthCert(t, func(c *x509.Certificate) {
		c.RawSubject = []byte("root")
		c.RawIssuer = []byte("root")
	})
	good := chainCompletenessFinding([]*x509.Certificate{leaf, inter, root}, nil)
	if good.What != "chain complete and in order" || good.Severity != finding.SeverityInfo {
		t.Errorf("ordered chain = %+v", good)
	}

	misordered := chainCompletenessFinding([]*x509.Certificate{leaf, root, inter}, nil)
	if misordered.Severity != finding.SeverityHigh {
		t.Errorf("misordered chain must be High: %+v", misordered)
	}
}

func TestClassificationDVOVEV(t *testing.T) {
	// FR-C19: DV by default, OV when an organisation is named, EV when a
	// CA/Browser Forum EV policy identifier is present.
	dv := classificationFinding([]*x509.Certificate{synthCert(t)})
	if dv.What != "validation=DV" {
		t.Errorf("DV classification = %+v", dv)
	}

	ov := classificationFinding([]*x509.Certificate{synthCert(t, func(c *x509.Certificate) {
		c.Subject.Organization = []string{"Example Ltd"}
	})})
	if ov.What != "validation=OV" || !strings.Contains(ov.Because, "Example Ltd") {
		t.Errorf("OV classification = %+v", ov)
	}

	evOID := asn1.ObjectIdentifier{2, 23, 140, 1, 1}
	ev := classificationFinding([]*x509.Certificate{synthCert(t, func(c *x509.Certificate) {
		c.PolicyIdentifiers = []asn1.ObjectIdentifier{evOID}
	})})
	if ev.What != "validation=EV" {
		t.Errorf("EV classification = %+v", ev)
	}
}

func TestSNIFindingsGatedByEnumerate(t *testing.T) {
	// FR-C20 costs extra handshakes, so it must stay off unless asked for.
	if got := sniFindings(targetFor(t, "example.test:443"), false); got != nil {
		t.Errorf("sni findings must be nil without enumeration: %+v", got)
	}
}

func TestCRLGatedByRevocationSwitch(t *testing.T) {
	leaf := synthCert(t)
	if got := crlFindings(Context{}, leaf, nil); got != nil {
		t.Errorf("crl findings must be nil without --check-revocation: %+v", got)
	}
	noEndpoint := crlFindings(Context{CheckRevocation: true}, leaf, nil)
	if len(noEndpoint) != 1 || noEndpoint[0].What != "no crl endpoint" {
		t.Errorf("certificate without a CRL endpoint = %+v", noEndpoint)
	}
}

// crlTestChain builds a CA that is allowed to sign CRLs plus a leaf, which
// the shared mustTestPair fixture cannot do (it sets no key usage bits).
func crlTestChain(t *testing.T) (*x509.Certificate, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := x509.Certificate{
		SerialNumber:          big.NewInt(21),
		Subject:               pkix.Name{CommonName: "CRL Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTmpl, &caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := x509.Certificate{
		SerialNumber: big.NewInt(22),
		Subject:      pkix.Name{CommonName: "example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"example.test"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf, ca, caKey
}

func TestCRLRevocationDetection(t *testing.T) {
	// FR-C10: a CRL that lists the serial must be Critical, and a clean CRL
	// must stay Info. Both are served offline by httptest.
	leaf, ca, caKey := crlTestChain(t)

	serve := func(revoke bool) *httptest.Server {
		var entries []x509.RevocationListEntry
		if revoke {
			entries = append(entries, x509.RevocationListEntry{
				SerialNumber:   leaf.SerialNumber,
				RevocationTime: time.Now().Add(-time.Hour),
				ReasonCode:     1,
			})
		}
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:                    big.NewInt(7),
			ThisUpdate:                time.Now().Add(-time.Hour),
			NextUpdate:                time.Now().Add(time.Hour),
			RevokedCertificateEntries: entries,
		}, ca, caKey)
		if err != nil {
			t.Fatalf("create crl: %v", err)
		}
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = w.Write(der)
		}))
	}

	revoked := serve(true)
	defer revoked.Close()
	withRevoked := leaf
	withRevoked.CRLDistributionPoints = []string{revoked.URL}
	got := crlFindings(Context{CheckRevocation: true}, withRevoked, ca)
	if len(got) != 1 || got[0].Severity != finding.SeverityCritical || got[0].What != "revoked" {
		t.Fatalf("revoked certificate must be Critical: %+v", got)
	}

	clean := serve(false)
	defer clean.Close()
	withClean := leaf
	withClean.CRLDistributionPoints = []string{clean.URL}
	ok := crlFindings(Context{CheckRevocation: true}, withClean, ca)
	if len(ok) != 1 || ok[0].What != "crl good" || ok[0].Severity != finding.SeverityInfo {
		t.Errorf("clean CRL = %+v", ok)
	}
}

func TestCRLRevocationWinsOverACleanEndpoint(t *testing.T) {
	// FR-C10: a certificate can advertise several CRL distribution points. A
	// clean list must not end the search while another endpoint revokes the
	// certificate.
	leaf, ca, caKey := crlTestChain(t)

	serve := func(revoke bool) *httptest.Server {
		var entries []x509.RevocationListEntry
		if revoke {
			entries = append(entries, x509.RevocationListEntry{
				SerialNumber:   leaf.SerialNumber,
				RevocationTime: time.Now().Add(-time.Hour),
				ReasonCode:     4,
			})
		}
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:                    big.NewInt(31),
			ThisUpdate:                time.Now().Add(-time.Hour),
			NextUpdate:                time.Now().Add(time.Hour),
			RevokedCertificateEntries: entries,
		}, ca, caKey)
		if err != nil {
			t.Fatalf("create crl: %v", err)
		}
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(der)
		}))
	}

	clean := serve(false)
	defer clean.Close()
	revoking := serve(true)
	defer revoking.Close()

	withBoth := leaf
	withBoth.CRLDistributionPoints = []string{clean.URL, revoking.URL}
	got := crlFindings(Context{CheckRevocation: true}, withBoth, ca)
	if len(got) != 1 || got[0].What != "revoked" || got[0].Severity != finding.SeverityCritical {
		t.Fatalf("a revoking endpoint must win over a clean one: %+v", got)
	}
}

func TestCRLTolerantOfUnreadableEndpoint(t *testing.T) {
	// A broken endpoint (HTML error page) must not hide a readable one, and
	// the unreadable endpoint must be named when nothing can be read.
	leaf, ca, caKey := crlTestChain(t)
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>not a crl</html>"))
	}))
	defer broken.Close()

	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(41),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
	}, ca, caKey)
	if err != nil {
		t.Fatalf("create crl: %v", err)
	}
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(der)
	}))
	defer good.Close()

	withBoth := leaf
	withBoth.CRLDistributionPoints = []string{broken.URL, good.URL}
	got := crlFindings(Context{CheckRevocation: true}, withBoth, ca)
	if len(got) != 1 || got[0].What != "crl good" {
		t.Fatalf("a readable endpoint should be used when another is unreadable: %+v", got)
	}
	if !strings.Contains(got[0].Detail, broken.URL) {
		t.Errorf("the unreadable endpoint should stay in the evidence: %q", got[0].Detail)
	}

	onlyBroken := leaf
	onlyBroken.CRLDistributionPoints = []string{broken.URL}
	unreadable := crlFindings(Context{CheckRevocation: true}, onlyBroken, ca)
	if unreadable[0].What != "crl unreachable" || !strings.Contains(unreadable[0].Detail, broken.URL) {
		t.Errorf("with no readable endpoint the unreadable one must be named: %+v", unreadable[0])
	}
}

func TestCRLUnreachableIsLow(t *testing.T) {
	leaf, ca, _ := crlTestChain(t)
	leaf.CRLDistributionPoints = []string{"http://127.0.0.1:1/revoked.crl"}
	got := crlFindings(Context{CheckRevocation: true}, leaf, ca)
	if len(got) != 1 || got[0].Severity != finding.SeverityLow || got[0].What != "crl unreachable" {
		t.Errorf("unreachable CRL must be Low and honest about it: %+v", got)
	}
}

func TestTLSChecksStopAtBudget(t *testing.T) {
	// NFR-3: a spent budget must stop the pass without dialing, so a slow
	// target cannot hold the run open.
	fs, err := Run(Context{Deadline: time.Now().Add(-time.Second)}, targetFor(t, "127.0.0.1:1"))
	if err != nil {
		t.Fatalf("Run with a spent budget returned an error: %v", err)
	}
	if len(fs) != 1 || fs[0].Kind != "tls-budget" {
		t.Fatalf("budget finding = %+v", fs)
	}
	if fs[0].Severity != finding.SeverityLow || !strings.Contains(fs[0].Detail, "skipped=") {
		t.Errorf("budget finding should be Low and name the skipped work: %+v", fs[0])
	}
}
