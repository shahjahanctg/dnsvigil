package tlscheck

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dnsvigil/dnsvigil/internal/core/finding"
	"github.com/dnsvigil/dnsvigil/internal/core/target"
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
		Subject:               pkix.Name{CommonName: host, Organization: []string{"dnsvigil test"}},
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

func TestDialTLSTimesOutOnSilentServer(t *testing.T) {
	// NFR-3 regression: a host that accepts the TCP connection and then never
	// speaks TLS used to hang the whole run, because the handshake had no
	// deadline. It must instead come back as an unreachable result.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn // accept and stay silent
		}
	}()

	tgt, err := target.ParseTarget(ln.Addr().String())
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	start := time.Now()
	conn, err := dialTLS(Context{Timeout: 500 * time.Millisecond}, tgt)
	elapsed := time.Since(start)
	if conn != nil {
		conn.Close()
		t.Fatal("a silent server must not yield a connection")
	}
	if err == nil {
		t.Fatal("a silent server must produce an error")
	}
	if elapsed > 3*time.Second {
		t.Errorf("dial honoured %s instead of the 500ms budget", elapsed)
	}
	if !isUnreachable(err) {
		t.Errorf("a timed-out handshake should read as unreachable, got %v", err)
	}
}

func TestDialTimeoutDefaultAndOverride(t *testing.T) {
	if got := (Context{}).DialTimeout(); got != DefaultDialTimeout {
		t.Errorf("default dial timeout = %s, want %s", got, DefaultDialTimeout)
	}
	if got := (Context{Timeout: time.Second}).DialTimeout(); got != time.Second {
		t.Errorf("operator dial timeout = %s, want 1s", got)
	}
}

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

func TestProtocolCipherFindings(t *testing.T) {
	// FR-C7: negotiated protocol/cipher is reported; TLS 1.0 host is flagged.
	weak := protocolCipherFindings(tls.ConnectionState{Version: tls.VersionTLS10, CipherSuite: tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA})
	foundWeakProto, foundWeakCipher, base := false, false, false
	for _, f := range weak {
		switch f.Kind {
		case "tls-protocol":
			base = true
			if !strings.Contains(f.What, "TLS 1.0") || !strings.Contains(f.What, "3DES_EDE") {
				t.Errorf("tls-protocol What = %q", f.What)
			}
		case "tls-protocol-weak":
			foundWeakProto = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("outdated protocol severity = %v, want High", f.Severity)
			}
		case "tls-cipher-weak":
			foundWeakCipher = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("weak cipher severity = %v, want High", f.Severity)
			}
		}
	}
	if !base || !foundWeakProto || !foundWeakCipher {
		t.Errorf("TLS 1.0 + 3DES must produce base/weak-protocol/weak-cipher findings: %+v", weak)
	}

	strong := protocolCipherFindings(tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256})
	if len(strong) != 1 || strong[0].Kind != "tls-protocol" {
		t.Errorf("TLS 1.3 + AES-GCM must produce exactly one base finding: %+v", strong)
	}
}

func TestServedChainFinding(t *testing.T) {
	// FR-C3: the served chain is enumerated like openssl s_client shows it.
	leaf := mustCert(t, "example.com", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	f := servedChainFinding([]*x509.Certificate{leaf})
	if f.What != "chain_depth=1" {
		t.Errorf("served chain What = %q", f.What)
	}
	if !strings.Contains(f.Detail, "subject=example.com") || !strings.Contains(f.Detail, "depth=0") {
		t.Errorf("served chain Detail should list each cert: %q", f.Detail)
	}
}

func TestWarnDaysOverride(t *testing.T) {
	// FR-C4: the operator override is respected, zero means default.
	if got := (Context{}).WarnDays(); got != DefaultExpiryWarnDays {
		t.Errorf("default WarnDays = %d, want %d", got, DefaultExpiryWarnDays)
	}
	if got := (Context{ExpiryWarnDays: 10}).WarnDays(); got != 10 {
		t.Errorf("override WarnDays = %d, want 10", got)
	}

	soon := mustCert(t, "example.com", time.Now().Add(-time.Hour), time.Now().Add(20*24*time.Hour)).NotAfter
	remaining := daysRemaining(soon)
	f := expiryFinding(&x509.Certificate{NotAfter: soon}, remaining, 10)
	if f.Kind == "tls-expiry" && f.Severity == finding.SeverityHigh {
		t.Errorf("20 days left must not be HIGH at a 10-day threshold: %+v", f)
	}
	f30 := expiryFinding(&x509.Certificate{NotAfter: soon}, remaining, 30)
	if f30.Kind != "tls-expiry" || f30.Severity != finding.SeverityHigh {
		t.Errorf("20 days left must be HIGH at the 30-day threshold: %+v", f30)
	}
}

func TestTrustErrorFindingsNonTrustError(t *testing.T) {
	// Non TLS trust errors must not be mapped to certificate findings;
	// the real mappings (expired, unknown authority, hostname) are proven
	// end to end against live in-process TLS servers in the engine tests.
	for _, err := range []error{
		errors.New("connect: unexpected reply"),
		&net.AddrError{Err: "bad address", Addr: "x"},
	} {
		if fs, ok := trustErrorFindings(err); ok {
			t.Errorf("non-trust error %v incorrectly mapped to findings: %+v", err, fs)
		}
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
