// Package tlscheck verifies certificates presented by operator-supplied
// targets (FR-C3–C7, FR-C13–C19).
package tlscheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/dnsvigil/dnsvigil/internal/core/finding"
	"github.com/dnsvigil/dnsvigil/internal/core/target"
)

// DefaultExpiryWarnDays is the FR-C4 warning window when the operator does
// not override it per run.
const DefaultExpiryWarnDays = 30

// DefaultDialTimeout bounds one handshake attempt (NFR-3): a host that accepts
// nothing must become a recorded result, not a hang.
const DefaultDialTimeout = 5 * time.Second

// Context carries the things certificate checks need that aren't on the stream itself.
type Context struct {
	Logger         func(...any)
	CustomResolver string
	Proxy          string
	// RootCAs is an optional trust anchor used by tests so in-process TLS
	// servers (with self-signed or lab CAs) can be checked. When nil the
	// system's default pool is used.
	RootCAs *x509.CertPool
	// ExpiryWarnDays overrides the days-to-expiry warning threshold
	// (FR-C4). Zero means the default.
	ExpiryWarnDays int
	// Timeout bounds the TCP connect and the TLS handshake. Zero means
	// DefaultDialTimeout; it is the operator's --timeout.
	Timeout time.Duration
	// Deadline bounds the whole check pass (NFR-2/3): once it passes, the
	// remaining work is skipped and recorded.
	Deadline time.Time
	// CheckRevocation enables OCSP revocation verification (FR-C10, off by
	// default per spec). Without it, stapling presence is still reported.
	CheckRevocation bool
	// Enumerate enables protocol/cipher probing (FR-C15/C16); off by
	// default to keep single-host checks within the NFR-2 time bound.
	Enumerate bool
}

// budgetExceeded reports whether the run's time budget has been spent.
func (c Context) budgetExceeded() bool {
	return !c.Deadline.IsZero() && time.Now().After(c.Deadline)
}

// budgetFinding records what a spent budget prevented from running.
func budgetFinding(skipped []string) finding.Finding {
	return finding.Finding{
		Kind:     "tls-budget",
		Severity: finding.SeverityLow,
		What:     "run budget exhausted",
		Because:  "the run reached its time budget, so the remaining checks were skipped rather than letting the run continue past the bound",
		Detail:   "skipped=" + strings.Join(skipped, ", "),
	}
}

// Run checks a single target's TLS certificate and returns findings.
func Run(ctx Context, t target.Target) ([]finding.Finding, error) {
	if ctx.budgetExceeded() {
		return []finding.Finding{budgetFinding([]string{"all certificate checks"})}, nil
	}
	conn, err := dialTLS(ctx, t)
	if err != nil {
		if isUnreachable(err) {
			return []finding.Finding{{
				Kind:     "tls-connect",
				Severity: finding.SeverityMedium,
				What:     "unreachable",
				Because:  "the host could not be reached at the given address",
				Detail:   err.Error(),
			}}, nil
		}
		// Trust failures are certificate findings, not connectivity problems
		// (FR-C5/C6): the server responded, the certificate failed to satisfy
		// the client's trust requirements.
		if f, ok := trustErrorFindings(err); ok {
			return f, nil
		}
		return nil, fmt.Errorf("cannot connect: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return []finding.Finding{{
			Kind:     "tls-certs",
			Severity: finding.SeverityHigh,
			What:     "no certificates returned",
			Because:  "the TLS handshake succeeded but no server certificate was returned",
		}}, nil
	}

	certs := state.PeerCertificates
	leaf := certs[0]
	f := make([]finding.Finding, 0, 12)

	// Basic facts.
	f = append(f, finding.Finding{
		Kind:     "tls-identity",
		Severity: finding.SeverityInfo,
		What:     fmt.Sprintf("subject=%s", leaf.Subject.CommonName),
		Because:  fmt.Sprintf("the certificate's subject common name is %q", leaf.Subject.CommonName),
		Detail: fmt.Sprintf("subject=%s\nissuer=%s\nserial=%s",
			leaf.Subject, leaf.Issuer, leaf.SerialNumber.String()),
	})

	// Validity window + expiry (FR-C3/C4).
	remaining := daysRemaining(leaf.NotAfter)
	f = append(f, finding.Finding{
		Kind:     "tls-validity",
		Severity: finding.SeverityInfo,
		What:     fmt.Sprintf("not_before=%s not_after=%s", leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339)),
		Because: fmt.Sprintf(
			"the certificate is valid from %s until %s",
			leaf.NotBefore.Format("2006-01-02"),
			leaf.NotAfter.Format("2006-01-02")),
		Detail: fmt.Sprintf("not_before=%s\nnot_after=%s\ndays_remaining=%d",
			leaf.NotBefore.Format(time.RFC3339),
			leaf.NotAfter.Format(time.RFC3339),
			remaining),
	})
	f = append(f, expiryFinding(leaf, remaining, ctx.WarnDays()))

	// Hostname / SAN match (FR-C5).
	f = append(f, hostnameFinding(leaf, t.Host))

	// Chain validation against the trust store.
	f = append(f, chainFinding(leaf, t.Host))

	// Served chain enumeration (FR-C3) and completeness (FR-C17), judged
	// against the trust store actually in use for this run.
	f = append(f, servedChainFinding(certs))
	f = append(f, chainCompletenessFinding(certs, ctx.trustStore()))

	// Signature algorithm, key strength (FR-C13) and DV/OV/EV (FR-C19).
	f = append(f, signatureStrengthFindings(leaf)...)
	f = append(f, classificationFinding(certs))

	// Negotiated protocol + cipher (FR-C7).
	f = append(f, protocolCipherFindings(state)...)

	// Tier 2: fingerprint (FR-C8), stapling (FR-C11), optional revocation
	// (FR-C10), CT presence (FR-C12), optional enumeration (FR-C15/C16).
	f = append(f, fingerprintFinding(leaf))
	f = append(f, staplingFindings(state, ctx)...)
	f = append(f, sctFinding(state))

	// CRL revocation (FR-C10) needs the issuer that signed the leaf.
	var issuer *x509.Certificate
	if len(certs) > 1 {
		issuer = certs[1]
	}
	f = append(f, crlFindings(ctx, leaf, issuer)...)

	if ctx.budgetExceeded() {
		f = append(f, budgetFinding([]string{"protocol/cipher enumeration", "sni probing"}))
	} else {
		f = append(f, enumerationFindings(t, ctx.Enumerate)...)
		f = append(f, sniFindings(t, ctx.Enumerate)...)
	}

	return f, nil
}

// trustStore returns the certificate pool used to decide whether a served
// chain terminates at a known anchor (FR-C17).
func (c Context) trustStore() *x509.CertPool {
	if c.RootCAs != nil {
		return c.RootCAs
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil
	}
	return pool
}

// WarnDays resolves the FR-C4 threshold (operator override or default).
func (c Context) WarnDays() int {
	if c.ExpiryWarnDays > 0 {
		return c.ExpiryWarnDays
	}
	return DefaultExpiryWarnDays
}

func expiryFinding(leaf *x509.Certificate, remaining, warnDays int) finding.Finding {
	if remaining <= 0 {
		return finding.Finding{
			Kind:     "tls-expiry",
			Severity: finding.SeverityCritical,
			What:     "expired",
			Because:  "the certificate is past its validity date",
			Detail:   fmt.Sprintf("expired %s", leaf.NotAfter.Format(time.RFC3339)),
		}
	}
	if remaining <= warnDays {
		return finding.Finding{
			Kind:     "tls-expiry",
			Severity: finding.SeverityHigh,
			What:     fmt.Sprintf("expires in %d days", remaining),
			Because: fmt.Sprintf(
				"the certificate expires in %d days, inside the %d-day warning window",
				remaining, warnDays),
			Detail: fmt.Sprintf("expires %s\ndays_remaining=%d\nwarn_days=%d",
				leaf.NotAfter.Format(time.RFC3339), remaining, warnDays),
		}
	}
	if remaining > 398 {
		return finding.Finding{
			Kind:     "tls-validity-length",
			Severity: finding.SeverityMedium,
			What:     "validity exceeds 398 days",
			Because:  "the certificate's validity period exceeds the CA/B Forum maximum of 398 days",
			Detail:   fmt.Sprintf("days_remaining=%d\nmax_allowed=398", remaining),
		}
	}
	return finding.Finding{
		Kind:     "tls-expiry-ok",
		Severity: finding.SeverityInfo,
		What:     fmt.Sprintf("days_remaining=%d", remaining),
		Because: fmt.Sprintf(
			"the certificate has %d days left, outside the %d-day warning window",
			remaining, warnDays),
	}
}

func hostnameFinding(leaf *x509.Certificate, host string) finding.Finding {
	if leaf == nil {
		return finding.Finding{
			Kind:     "tls-hostname",
			Severity: finding.SeverityCritical,
			What:     "certificate has no subject",
			Because:  "the server returned a certificate with no identifiable subject",
		}
	}
	matched := false
	for _, name := range leaf.DNSNames {
		if strings.EqualFold(name, host) {
			matched = true
			break
		}
	}
	if !matched && strings.EqualFold(leaf.Subject.CommonName, host) {
		matched = true
	}
	if !matched && ipEqualFold(leaf, host) {
		matched = true
	}
	if matched {
		return finding.Finding{
			Kind:     "tls-hostname",
			Severity: finding.SeverityInfo,
			What:     "hostname matches",
			Because:  fmt.Sprintf("the certificate covers %q", host),
		}
	}
	return finding.Finding{
		Kind:     "tls-hostname",
		Severity: finding.SeverityCritical,
		What:     "hostname mismatch",
		Because:  fmt.Sprintf("the certificate does not cover %q", host),
		Detail:   fmt.Sprintf("dns_names=%v\nips=%v\ncn=%q", leaf.DNSNames, leaf.IPAddresses, leaf.Subject.CommonName),
	}
}

// ipEqualFold matches an IP-literal host against the certificate's IP SANs.
func ipEqualFold(leaf *x509.Certificate, host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cand := range leaf.IPAddresses {
		if cand.Equal(ip) {
			return true
		}
	}
	return false
}

func chainFinding(leaf *x509.Certificate, host string) finding.Finding {
	err := leaf.VerifyHostname(host)
	if err == nil {
		return finding.Finding{
			Kind:     "tls-chain",
			Severity: finding.SeverityInfo,
			What:     "chain verified",
			Because:  "the leaf certificate verified against the trust store for the requested host",
		}
	}
	return finding.Finding{
		Kind:     "tls-chain",
		Severity: finding.SeverityHigh,
		What:     "chain could not be verified for host",
		Because: fmt.Sprintf("the certificate could not be verified for %q: %s",
			host, err.Error()),
		Detail: err.Error(),
	}
}

// servedChainFinding enumerates every certificate presented by the server
// (FR-C3 "served chain") so the report matches what openssl s_client shows.
func servedChainFinding(certs []*x509.Certificate) finding.Finding {
	var lines []string
	for i, c := range certs {
		lines = append(lines, fmt.Sprintf("depth=%d subject=%s issuer=%s serial=%s",
			i, c.Subject.CommonName, c.Issuer.CommonName, c.SerialNumber.String()))
	}
	return finding.Finding{
		Kind:     "tls-chain-served",
		Severity: finding.SeverityInfo,
		What:     fmt.Sprintf("chain_depth=%d", len(certs)),
		Because: fmt.Sprintf(
			"the server presented a chain of %d certificate(s); the full list is in the detail for specialist review",
			len(certs)),
		Detail: strings.Join(lines, "\n"),
	}
}

// protocolCipherFindings reports the negotiated TLS protocol and cipher and
// flags weak/outdated combinations (FR-C7).
func protocolCipherFindings(state tls.ConnectionState) []finding.Finding {
	version := tlsVersionName(state.Version)
	cipher := tls.CipherSuiteName(state.CipherSuite)

	fs := []finding.Finding{{
		Kind:     "tls-protocol",
		Severity: finding.SeverityInfo,
		What:     fmt.Sprintf("protocol=%s cipher=%s", version, cipher),
		Because: fmt.Sprintf(
			"the connection negotiated TLS protocol %s with cipher suite %s",
			version, cipher),
	}}

	if state.Version < tls.VersionTLS12 {
		fs = append(fs, finding.Finding{
			Kind:     "tls-protocol-weak",
			Severity: finding.SeverityHigh,
			What:     fmt.Sprintf("outdated protocol %s", version),
			Because: fmt.Sprintf(
				"the server negotiated %s, which lacks the protections of TLS 1.2+",
				version),
			Detail: fmt.Sprintf("negotiated=%s\nmin_recommended=TLS 1.2", version),
		})
	}
	if reason := weakCipherReason(cipher, state.Version); reason != "" {
		fs = append(fs, finding.Finding{
			Kind:     "tls-cipher-weak",
			Severity: finding.SeverityHigh,
			What:     fmt.Sprintf("weak cipher %s", cipher),
			Because:  reason,
			Detail:   fmt.Sprintf("cipher=%s\nprotocol=%s", cipher, version),
		})
	}
	return fs
}

// tlsVersionName maps a negotiated protocol constant to its stable name.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}

// weakCipherReason returns a plain-language reason when a negotiated cipher
// is considered weak, or "" when the cipher is acceptable.
func weakCipherReason(cipher string, version uint16) string {
	c := strings.ToUpper(cipher)
	switch {
	case strings.Contains(c, "3DES"):
		return "the negotiated cipher uses 3DES, which provides only small effective key size"
	case strings.Contains(c, "RC4"):
		return "the negotiated cipher uses RC4, which is broken for most purposes"
	case strings.Contains(c, "NULL") || strings.Contains(c, "ANON"):
		return "the negotiated cipher provides no encryption or no authentication"
	case strings.Contains(c, "SHA1"):
		return "the negotiated cipher authenticates with SHA-1"
	case strings.Contains(c, "CBC") && version < tls.VersionTLS13:
		return "the negotiated cipher uses CBC mode on a pre-TLS 1.3 protocol, which is vulnerable to padding-oracle style attacks"
	}
	return ""
}

// trustErrorFindings converts a TLS handshake trust failure into findings
// (FR-C5/C6) so untrusted, self-signed, hostname-mismatched, and expired
// server certificates are flagged results rather than dead errors.
func trustErrorFindings(err error) ([]finding.Finding, bool) {
	var te *tls.CertificateVerificationError
	if !errors.As(err, &te) {
		return nil, false
	}
	inner := te.Unwrap()
	if inner == nil {
		return nil, false
	}

	var hostErr x509.HostnameError
	if errors.As(inner, &hostErr) {
		return []finding.Finding{{
			Kind:     "tls-hostname",
			Severity: finding.SeverityCritical,
			What:     "hostname mismatch",
			Because: fmt.Sprintf("the server's certificate does not cover %q, so the connection cannot be trusted",
				hostErr.Host),
			Detail: inner.Error(),
		}}, true
	}

	var unknownAuth x509.UnknownAuthorityError
	if errors.As(inner, &unknownAuth) {
		return []finding.Finding{{
			Kind:     "tls-chain",
			Severity: finding.SeverityCritical,
			What:     "untrusted chain",
			Because:  "the certificate chain cannot be verified against the trust store: it is self-signed, from an unrecognised CA, or the intermediates were not served",
			Detail:   inner.Error(),
		}}, true
	}

	var invalid x509.CertificateInvalidError
	if errors.As(inner, &invalid) {
		return []finding.Finding{{
			Kind:     invalidReasonKind(invalid.Reason),
			Severity: finding.SeverityCritical,
			What:     invalidReasonWhat(invalid.Reason),
			Because:  invalidReasonBecause(invalid.Reason),
			Detail:   inner.Error(),
		}}, true
	}
	return nil, false
}

func invalidReasonKind(reason x509.InvalidReason) string {
	switch reason {
	case x509.Expired:
		return "tls-expiry"
	case x509.CANotAuthorizedForThisName, x509.CANotAuthorizedForExtKeyUsage:
		return "tls-chain"
	default:
		return "tls-validity-trust"
	}
}

func invalidReasonWhat(reason x509.InvalidReason) string {
	if reason == x509.Expired {
		return "expired"
	}
	return "certificate rejected by verifier"
}

func invalidReasonBecause(reason x509.InvalidReason) string {
	if reason == x509.Expired {
		return "the certificate is past its validity date"
	}
	if reason == x509.CANotAuthorizedForThisName {
		return "the CA did not authorise the requested name in this certificate"
	}
	if reason == x509.CANotAuthorizedForExtKeyUsage {
		return "the CA is not authorised to issue certificates for this usage"
	}
	return "the certificate failed verification against the trust store"
}

func dialTLS(ctx Context, t target.Target) (*tls.Conn, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: t.Host,
	}
	if ctx.RootCAs != nil {
		config.RootCAs = ctx.RootCAs
	}
	budget := ctx.DialTimeout()
	// Both halves need bounding: the dialer's Timeout covers the TCP connect,
	// and the context deadline covers the handshake, which otherwise waits
	// forever on a host that accepts the connection and then goes quiet.
	dialer := &net.Dialer{Timeout: budget}
	connCtx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	d := &tls.Dialer{NetDialer: dialer, Config: config}
	conn, err := d.DialContext(connCtx, "tcp", t.Addr())
	if err != nil {
		return nil, err
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("unexpected connection type %T", conn)
	}
	return tlsConn, nil
}

// DialTimeout resolves the per-attempt bound (NFR-3).
func (c Context) DialTimeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultDialTimeout
}

func daysRemaining(notAfter time.Time) int {
	if notAfter.IsZero() {
		return 0
	}
	d := notAfter.Sub(time.Now())
	return int(math.Round(d.Hours() / 24))
}

func isUnreachable(err error) bool {
	ne, ok := err.(net.Error)
	if ok && ne.Timeout() {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := err.Error()
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "operation was canceled") ||
		strings.Contains(msg, "network is unreachable") {
		return true
	}
	return false
}
