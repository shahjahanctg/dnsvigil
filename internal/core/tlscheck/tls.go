// Package tlscheck verifies certificates presented by operator-supplied
// targets (FR-C3–C7, FR-C13–C19).
package tlscheck

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/soc-tool/internal/core/finding"
	"github.com/soc-tool/internal/core/target"
)

// Context carries the things certificate checks need that aren't on the stream itself.
type Context struct {
	Logger         func(...any)
	CustomResolver string
	Proxy          string
	// RootCAs is an optional trust anchor used by tests so in-process TLS
	// servers (with self-signed or lab CAs) can be checked. When nil the
	// system's default pool is used.
	RootCAs *x509.CertPool
}

// Run checks a single target's TLS certificate and returns findings.
func Run(ctx Context, t target.Target) ([]finding.Finding, error) {
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
			daysRemaining(leaf.NotAfter)),
	})

	// Expiry threshold.
	remaining := daysRemaining(leaf.NotAfter)
	if remaining <= 0 {
		f = append(f, finding.Finding{
			Kind:     "tls-expiry",
			Severity: finding.SeverityCritical,
			What:     "expired",
			Because:  "the certificate is past its validity date",
			Detail:   fmt.Sprintf("expired %s", leaf.NotAfter.Format(time.RFC3339)),
		})
	} else if remaining <= 30 {
		f = append(f, finding.Finding{
			Kind:     "tls-expiry",
			Severity: finding.SeverityHigh,
			What:     fmt.Sprintf("expires in %d days", remaining),
			Because: fmt.Sprintf(
				"the certificate expires in %d days, inside the 30-day warning window",
				remaining),
			Detail: fmt.Sprintf("expires %s\ndays_remaining=%d", leaf.NotAfter.Format(time.RFC3339), remaining),
		})
	} else if remaining > 398 {
		f = append(f, finding.Finding{
			Kind:     "tls-validity-length",
			Severity: finding.SeverityMedium,
			What:     "validity exceeds 398 days",
			Because:  "the certificate's validity period exceeds the CA/B Forum maximum of 398 days",
			Detail:   fmt.Sprintf("days_remaining=%d\nmax_allowed=398", remaining),
		})
	}

	// Hostname / SAN match.
	f = append(f, hostnameFinding(leaf, t.Host))

	// Chain validation.
	if err := leaf.VerifyHostname(t.Host); err != nil {
		if strings.Contains(err.Error(), "x509: certificate has no matching host key") ||
			strings.Contains(err.Error(), "x509: cannot validate certificate for") {
			f = append(f, finding.Finding{
				Kind:     "tls-chain",
				Severity: finding.SeverityHigh,
				What:     "chain failed to verify for host",
				Because:  fmt.Sprintf("the certificate could not be verified against the default trust store for %q", t.Host),
				Detail:   err.Error(),
			})
		} else {
			f = append(f, finding.Finding{
				Kind:     "tls-chain",
				Severity: finding.SeverityHigh,
				What:     "chain could not be verified",
				Because:  fmt.Sprintf("the certificate chain could not be verified: %s", err.Error()),
				Detail:   err.Error(),
			})
		}
	} else {
		f = append(f, finding.Finding{
			Kind:     "tls-chain",
			Severity: finding.SeverityInfo,
			What:     "chain verified",
			Because:  "the leaf certificate verified against the default trust store for the requested host",
		})
	}

	return f, nil
}

func dialTLS(ctx Context, t target.Target) (*tls.Conn, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: t.Host,
	}
	if ctx.RootCAs != nil {
		config.RootCAs = ctx.RootCAs
	}
	var dial net.Dialer
	conn, err := tls.DialWithDialer(&dial, t.Addr(), t.Host, config)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func daysRemaining(notAfter time.Time) int {
	if notAfter.IsZero() {
		return 0
	}
	d := notAfter.Sub(time.Now())
	return int(math.Round(d.Hours() / 24))
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
		Detail:   fmt.Sprintf("dns_names=%v\ncn=%q", leaf.DNSNames, leaf.Subject.CommonName),
	}
}

func isUnreachable(err error) bool {
	ne, ok := err.(net.Error)
	if ok && ne.Timeout() {
		return true
	}
	if strings.Contains(err.Error(), "connection refused") ||
		strings.Contains(err.Error(), "no such host") ||
		strings.Contains(err.Error(), "i/o timeout") {
		return true
	}
	return false
}
