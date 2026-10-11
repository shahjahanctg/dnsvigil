package tlscheck

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/soc-tool/internal/core/finding"
)

// mustCert builds a self-signed certificate for tests.
func mustCert(t *testing.T, host string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: host, Organization: []string{"soc-tool test"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{host},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func TestHostnameFindingMismatchIsCritical(t *testing.T) {
	// FR-C5: a certificate that does not cover the requested host must be Critical.
	cert := mustCert(t, "example.org", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	f := hostnameFinding(cert, "example.com")
	if f.Severity != finding.SeverityCritical {
		t.Errorf("mismatch severity = %v, want Critical", f.Severity)
	}
	if f.What != "hostname mismatch" {
		t.Errorf("mismatch What = %q", f.What)
	}
	if f.Because == "" {
		t.Error("mismatch finding must carry a plain-language reason (FR-S7)")
	}
	if !strings.Contains(f.Detail, "example.org") {
		t.Errorf("mismatch Detail should name the cert's CN: %q", f.Detail)
	}
}

func TestHostnameFindingMatchIsInfo(t *testing.T) {
	cert := mustCert(t, "example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	f := hostnameFinding(cert, "example.com")
	if f.Severity != finding.SeverityInfo {
		t.Errorf("match severity = %v, want Info", f.Severity)
	}
	if f.What != "hostname matches" {
		t.Errorf("match What = %q", f.What)
	}
}

func TestHostnameFindingNilIsCritical(t *testing.T) {
	f := hostnameFinding(nil, "example.com")
	if f.Severity != finding.SeverityCritical {
		t.Errorf("nil-leaf severity = %v, want Critical", f.Severity)
	}
}

func TestDaysRemaining(t *testing.T) {
	if d := daysRemaining(time.Now().Add(30 * 24 * time.Hour)); d < 29 || d > 31 {
		t.Errorf("daysRemaining(+30d) = %d, want ~30", d)
	}
	if d := daysRemaining(time.Now().Add(-24 * time.Hour)); d >= 0 {
		t.Errorf("daysRemaining(past) = %d, want negative", d)
	}
	if d := daysRemaining(time.Time{}); d != 0 {
		t.Errorf("daysRemaining(zero) = %d, want 0", d)
	}
}

type strErr string

func (e strErr) Error() string { return string(e) }

func TestIsUnreachable(t *testing.T) {
	// Transport failures are unreachable; TLS trust errors are not (they are
	// certificate findings, not connectivity problems).
	for _, msg := range []string{
		"dial tcp 1.2.3.4:443: connect: connection refused",
		"lookup example.test: no such host",
		"read tcp: i/o timeout",
	} {
		if !isUnreachable(strErr(msg)) {
			t.Errorf("isUnreachable(%q) = false, want true", msg)
		}
	}
	if isUnreachable(strErr("tls: failed to verify certificate: x509: certificate signed by unknown authority")) {
		t.Error("trust errors must not be classified as unreachable")
	}
}

func TestIsUnreachableWithNetTimeoutError(t *testing.T) {
	// A real net.Error with Timeout()=true must be classified unreachable.
	e := &net.DNSError{Err: "timed out", Name: "example.test", IsTimeout: true}
	var ne net.Error = e
	if !isUnreachable(ne) {
		t.Error("net.Error timeout should be unreachable")
	}
}

func TestSeverityNamesStable(t *testing.T) {
	// CLI output contract used by printReport must stay stable.
	want := map[finding.Severity]string{
		finding.SeverityInfo:     "INFO",
		finding.SeverityLow:      "LOW",
		finding.SeverityMedium:   "MEDIUM",
		finding.SeverityHigh:     "HIGH",
		finding.SeverityCritical: "CRITICAL",
	}
	for sev, name := range want {
		if got := sev.Name(); got != name {
			t.Errorf("Severity(%d).Name() = %q, want %q", int(sev), got, name)
		}
	}
	if got := finding.Severity(42).Name(); got != "UNKNOWN" {
		t.Errorf("unknown severity name = %q, want UNKNOWN", got)
	}
}

func TestErrorsPackageLinked(t *testing.T) {
	// Guard against the errors import being dropped accidentally.
	if errors.New("x").Error() != "x" {
		t.Fatal("errors package broken")
	}
}
