package tlscheck

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/soc-tool/internal/core/finding"
	"github.com/soc-tool/internal/core/target"
	"golang.org/x/crypto/ocsp"
)

// probeTimeout caps each enumeration dial so a run stays bounded (NFR-2/3).
const probeTimeout = 3 * time.Second

// fingerprintFinding records the SHA-256 fingerprint and serial (FR-C8).
func fingerprintFinding(leaf *x509.Certificate) finding.Finding {
	sum := sha256.Sum256(leaf.Raw)
	return finding.Finding{
		Kind:     "tls-fingerprint",
		Severity: finding.SeverityInfo,
		What:     fmt.Sprintf("sha256=%x", sum[:]),
		Because:  "the leaf certificate's SHA-256 fingerprint is recorded so future runs can detect changes",
		Detail: fmt.Sprintf("sha256=%x\nserial=%s",
			sum[:], leaf.SerialNumber.String()),
	}
}

// staplingFindings reports OCSP stapling status (FR-C11) and, when the
// operator enables revocation checking (FR-C10, off by default), the revocation
// outcome from the stapled response.
func staplingFindings(state tls.ConnectionState, ctx Context) []finding.Finding {
	if len(state.OCSPResponse) == 0 {
		out := []finding.Finding{{
			Kind:     "tls-ocsp-stapling",
			Severity: finding.SeverityInfo,
			What:     "no OCSP staple",
			Because:  "the server did not include a stapled OCSP response in the handshake",
		}}
		if ctx.CheckRevocation {
			out = append(out, revocationFindingsNoStaple(state)...)
		}
		return out
	}
	out := []finding.Finding{{
		Kind:     "tls-ocsp-stapling",
		Severity: finding.SeverityInfo,
		What:     "ocsp stapled",
		Because:  "the server included a stapled OCSP response, so revocation status travels with the handshake",
	}}
	if ctx.CheckRevocation {
		out = append(out, ocspResponseFindings(state.OCSPResponse)...)
	}
	return out
}

// ocspResponseFindings classifies a DER OCSP response.
func ocspResponseFindings(der []byte) []finding.Finding {
	resp, err := ocsp.ParseResponse(der, nil)
	if err != nil {
		return []finding.Finding{{
			Kind:     "tls-revocation",
			Severity: finding.SeverityLow,
			What:     "ocsp response unreadable",
			Because:  "a stapled OCSP response was present but could not be parsed, so revocation is uncertain",
			Detail:   err.Error(),
		}}
	}
	sev := finding.SeverityInfo
	what := "ocsp good"
	because := "the CA reports the certificate as good"
	switch resp.Status {
	case ocsp.Revoked:
		sev, what, because = finding.SeverityCritical, "revoked", "the CA reports the certificate revoked"
	case ocsp.Unknown:
		sev, what, because = finding.SeverityMedium, "ocsp unknown", "the CA does not know this certificate"
	}
	return []finding.Finding{{
		Kind:     "tls-revocation",
		Severity: sev,
		What:     what,
		Because:  because,
		Detail:   fmt.Sprintf("status=%d this_update=%s next_update=%s", resp.Status, resp.ThisUpdate.Format(time.RFC3339), resp.NextUpdate.Format(time.RFC3339)),
	}}
}

// revocationFindingsNoStaple queries the certificate's advertised OCSP
// responder when the operator enabled revocation checking (FR-C10).
func revocationFindingsNoStaple(state tls.ConnectionState) []finding.Finding {
	leaf := state.PeerCertificates[0]
	if len(leaf.OCSPServer) == 0 {
		return []finding.Finding{{
			Kind:     "tls-revocation",
			Severity: finding.SeverityInfo,
			What:     "no ocsp endpoint",
			Because:  "the certificate does not advertise an OCSP responder and the server did not staple a response",
		}}
	}
	url := leaf.OCSPServer[0]
	req, err := ocsp.CreateRequest(leaf, nil, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return []finding.Finding{{
			Kind:     "tls-revocation",
			Severity: finding.SeverityLow,
			What:     "ocsp request failed",
			Because:  "building an OCSP request for the advertised responder failed",
			Detail:   err.Error(),
		}}
	}
	der, err := postOCSP(url, req)
	if err != nil {
		return []finding.Finding{{
			Kind:     "tls-revocation",
			Severity: finding.SeverityLow,
			What:     "ocsp server unreachable",
			Because:  "the OCSP responder did not answer the revocation query",
			Detail:   err.Error(),
		}}
	}
	return ocspResponseFindings(der)
}

// postOCSP performs an OCSP POST against the responder and returns the DER
// response body. It uses the standard library HTTP client only.
func postOCSP(url string, req []byte) ([]byte, error) {
	res, err := http.Post(url, "application/ocsp-request", bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ocsp responder status %d", res.StatusCode)
	}
	return io.ReadAll(io.LimitReader(res.Body, 1<<20))
}

// sctFinding reports Certificate Transparency presence (FR-C12).
func sctFinding(state tls.ConnectionState) finding.Finding {
	haveSCTs := len(state.SignedCertificateTimestamps) > 0
	what, because, detail := "no ct log entry", "no Signed Certificate Timestamps were presented, so CT inclusion is not evidenced by the handshake", "scts=0"
	if haveSCTs {
		what = "ct log entry present"
		because = "the server presented Signed Certificate Timestamps, showing inclusion into public CT logs was attempted"
		detail = fmt.Sprintf("scts=%d", len(state.SignedCertificateTimestamps))
	}
	return finding.Finding{
		Kind:     "tls-ct",
		Severity: finding.SeverityInfo,
		What:     what,
		Because:  because,
		Detail:   detail,
	}
}

// enumerationFindings probes which protocol versions and cipher suites the
// server actually offers (FR-C15/C16). It dials with InsecureSkipVerify so
// verification noise does not mask the transport answer.
func enumerationFindings(t targetLike, enumerate bool) []finding.Finding {
	if !enumerate {
		return nil
	}
	var fs []finding.Finding
	fs = append(fs, protocolEnumeration(t)...)
	fs = append(fs, cipherEnumeration(t)...)
	return fs
}

type targetLike = target.Target

// offeredProtocols tries each modern protocol version and reports what the
// server accepted.
func protocolEnumeration(t targetLike) []finding.Finding {
	type version struct {
		id   uint16
		name string
	}
	versions := []version{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
	}
	var offered []string
	for _, v := range versions {
		if probeConfig(t, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         v.id,
		}) {
			offered = append(offered, v.name)
		}
	}
	fulsev := finding.SeverityInfo
	what := "protocols offered: " + joinedOrNone(offered)
	f := finding.Finding{
		Kind:     "tls-protocols-offered",
		Severity: fulsev,
		What:     what,
		Because:  "the server accepted a handshake with each listed protocol version during enumeration",
		Detail:   "offered=" + joinedOrNone(offered),
	}
	return []finding.Finding{f}
}

// cipherEnumeration forces single cipher suites and records what is accepted.
func cipherEnumeration(t targetLike) []finding.Finding {
	supported := tls.CipherSuites()
	var accepted []string
	var weak []string
	for _, suite := range supported {
		ok := probeConfig(t, &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{suite.ID},
			MinVersion:         tls.VersionTLS12,
		})
		if !ok {
			continue
		}
		accepted = append(accepted, suite.Name)
		if reason := weakCipherReason(suite.Name, tls.VersionTLS12); reason != "" {
			weak = append(weak, suite.Name)
		}
	}
	out := []finding.Finding{{
		Kind:     "tls-ciphers-accepted",
		Severity: finding.SeverityInfo,
		What:     "ciphers accepted: " + shortList(accepted, 6),
		Because:  "the server completed a handshake with every listed cipher suite when forced one at a time",
		Detail:   "accepted=" + joinedOrNone(accepted),
	}}
	if len(weak) > 0 {
		out = append(out, finding.Finding{
			Kind:     "tls-cipher-weak",
			Severity: finding.SeverityHigh,
			What:     fmt.Sprintf("weak cipher offered: %s", shortList(weak, 6)),
			Because:  "the server accepts a cipher suite considered weak, so older handshakes could downgrade to it",
			Detail:   "weak=" + joinedOrNone(weak),
		})
	}
	return out
}

func probeConfig(t targetLike, cfg *tls.Config) bool {
	cfg.ServerName = serverNameFor(t.Addr())
	dialer := &net.Dialer{Timeout: probeTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", t.Addr(), cfg)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// serverNameFor infers a SNI name from host:port.
func serverNameFor(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if ip := net.ParseIP(host); ip != nil {
		return "" // IP literals do not carry SNI
	}
	return host
}

func joinedOrNone(list []string) string {
	if len(list) == 0 {
		return "(none)"
	}
	return joinList(list)
}

func joinList(list []string) string {
	out := ""
	for i, s := range list {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

func shortList(list []string, max int) string {
	if len(list) <= max {
		return joinedOrNone(list)
	}
	return fmt.Sprintf("%d suites (%s, ...)", len(list), joinList(list[:max]))
}
