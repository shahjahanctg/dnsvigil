package tlscheck

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/soc-tool/internal/core/finding"
)

// signatureStrengthFindings covers FR-C13: the signature algorithm that
// signed the certificate and the strength of its public key.
func signatureStrengthFindings(leaf *x509.Certificate) []finding.Finding {
	var out []finding.Finding

	alg := leaf.SignatureAlgorithm.String()
	if weakSignatureReason(leaf.SignatureAlgorithm) != "" {
		out = append(out, finding.Finding{
			Kind:     "tls-signature",
			Severity: finding.SeverityHigh,
			What:     "weak signature algorithm " + alg,
			Because:  weakSignatureReason(leaf.SignatureAlgorithm),
			Detail:   fmt.Sprintf("signature_algorithm=%s", alg),
		})
	} else {
		out = append(out, finding.Finding{
			Kind:     "tls-signature",
			Severity: finding.SeverityInfo,
			What:     "signature=" + alg,
			Because:  fmt.Sprintf("the certificate is signed with %s, which is not deprecated", alg),
			Detail:   fmt.Sprintf("signature_algorithm=%s", alg),
		})
	}

	bits := publicKeyBits(leaf)
	if reason := weakKeyReason(leaf.PublicKey, bits); reason != "" {
		out = append(out, finding.Finding{
			Kind:     "tls-key",
			Severity: finding.SeverityHigh,
			What:     fmt.Sprintf("weak key %s-%d", publicKeyType(leaf), bits),
			Because:  reason,
			Detail:   fmt.Sprintf("key_algorithm=%s\nkey_bits=%d", publicKeyType(leaf), bits),
		})
	} else if bits > 0 {
		out = append(out, finding.Finding{
			Kind:     "tls-key",
			Severity: finding.SeverityInfo,
			What:     fmt.Sprintf("key=%s-%d bits", publicKeyType(leaf), bits),
			Because:  fmt.Sprintf("the certificate's public key is %s with %d bits", publicKeyType(leaf), bits),
			Detail:   fmt.Sprintf("key_algorithm=%s\nkey_bits=%d", publicKeyType(leaf), bits),
		})
	}
	return out
}

func weakSignatureReason(alg x509.SignatureAlgorithm) string {
	switch alg {
	case x509.MD2WithRSA, x509.MD5WithRSA:
		return "the certificate is signed with MD5/MD2, whose collision resistance is broken, so a forged certificate could be produced"
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return "the certificate is signed with SHA-1, which is no longer considered collision resistant"
	case x509.DSAWithSHA256:
		return "the certificate is signed with DSA, which is deprecated for TLS certificates"
	}
	return ""
}

func publicKeyType(leaf *x509.Certificate) string {
	switch leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return leaf.PublicKeyAlgorithm.String()
	}
}

func publicKeyBits(leaf *x509.Certificate) int {
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

func weakKeyReason(pub any, bits int) string {
	switch pub.(type) {
	case *rsa.PublicKey:
		if bits > 0 && bits < 2048 {
			return "the RSA key is shorter than 2048 bits, which is below the current minimum accepted by browsers and CAs"
		}
	case *ecdsa.PublicKey:
		if bits > 0 && bits < 256 {
			return "the ECDSA key uses a curve smaller than 256 bits, which no longer meets the 128-bit security level"
		}
	default:
		return "the certificate uses a public key algorithm that is not recommended for TLS certificates"
	}
	return ""
}

// chainCompletenessFinding is FR-C17: the served chain must run leaf →
// intermediate(s) → trusted anchor in the right order, referencing the next
// certificate in the list. An anchor held in the trust store is a valid
// terminal: cross-signed roots that are not self-signed are normal.
func chainCompletenessFinding(certs []*x509.Certificate, roots *x509.CertPool) finding.Finding {
	if len(certs) == 0 {
		return finding.Finding{}
	}
	leaf := certs[0]
	// A single certificate that is not self-signed means the issuer was not
	// served: many clients then fail to build a path.
	if len(certs) == 1 && !bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
		return finding.Finding{
			Kind:     "tls-chain-incomplete",
			Severity: finding.SeverityMedium,
			What:     "no intermediates served",
			Because: fmt.Sprintf("only the leaf certificate was served; clients must fetch or cache the issuer %q themselves, which fails where AIA fetching is blocked",
				leaf.Issuer.CommonName),
			Detail: fmt.Sprintf("depth=0 subject=%s\nissuer=%s\nserved=1", leaf.Subject.CommonName, leaf.Issuer.CommonName),
		}
	}
	for i := 0; i+1 < len(certs); i++ {
		if !bytes.Equal(certs[i].RawIssuer, certs[i+1].RawSubject) {
			return finding.Finding{
				Kind:     "tls-chain-incomplete",
				Severity: finding.SeverityHigh,
				What:     "chain misordered or broken",
				Because: fmt.Sprintf("certificate at depth %d names issuer %q but the next certificate served is %q, so the chain does not link up",
					i, certs[i].Issuer.CommonName, certs[i+1].Subject.CommonName),
				Detail: fmt.Sprintf("depth=%d subject=%s issuer=%s\nnext_subject=%s",
					i, certs[i].Subject.CommonName, certs[i].Issuer.CommonName, certs[i+1].Subject.CommonName),
			}
		}
	}
	last := certs[len(certs)-1]
	selfSigned := bytes.Equal(last.RawIssuer, last.RawSubject)

	// The decisive question is whether a client can build a path from the leaf
	// to a trust anchor using only what was served (plus its own store). This
	// treats a cross-signed root chain as complete, which is what browsers do.
	verifyErr := verifyServedChain(certs, roots)
	if verifyErr != nil && !selfSigned {
		return finding.Finding{
			Kind:     "tls-chain-incomplete",
			Severity: finding.SeverityLow,
			What:     "chain does not reach a trust anchor",
			Because: fmt.Sprintf("a client cannot build a path from the leaf to a trusted root using the %d certificate(s) served (deepest is %q, issued by %q)",
				len(certs), last.Subject.CommonName, last.Issuer.CommonName),
			Detail: fmt.Sprintf("served=%d\ndeepest_subject=%s\ndeepest_issuer=%s\nverify_error=%v",
				len(certs), last.Subject.CommonName, last.Issuer.CommonName, verifyErr),
		}
	}
	because := "every certificate served names the next one's subject as its issuer, and a client can build a path from the leaf to a trust anchor with what was served"
	if selfSigned {
		because = "every certificate served names the next one's subject as its issuer, and the chain ends at a self-signed root"
	}
	return finding.Finding{
		Kind:     "tls-chain-incomplete",
		Severity: finding.SeverityInfo,
		What:     "chain complete and in order",
		Because:  because,
		Detail:   fmt.Sprintf("served=%d\nterminal=%s", len(certs), last.Issuer.CommonName),
	}
}

// verifyServedChain attempts to build a path from the leaf to a trust anchor
// using the served certificates as intermediates.
func verifyServedChain(certs []*x509.Certificate, roots *x509.CertPool) error {
	if roots == nil {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return err
		}
		roots = pool
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
	})
	return err
}

// cabfEVPolicyOIDs are the CA/Browser Forum extended-validation policy OIDs
// (2.23.140.1.1 and its predecessors) used by FR-C19's EV classification.
var cabfEVPolicyOIDs = map[string]bool{
	"2.23.140.1.1":        true,
	"1.3.6.1.4.1.34697.2": true,
	"1.3.6.1.4.1.17326":   true,
	"2.16.840.1.114412":   true,
	"1.3.6.1.4.1.23223":   true,
	"1.3.6.1.4.1.6334":    true,
}

// classificationFinding is FR-C19: DV/OV/EV classification plus the CA
// hierarchy, taken from the served chain.
func classificationFinding(certs []*x509.Certificate) finding.Finding {
	if len(certs) == 0 {
		return finding.Finding{}
	}
	leaf := certs[0]

	class := "DV"
	reason := "the certificate carries no organisation identity, which is what a domain-validated certificate looks like"
	switch {
	case hasEVPolicy(leaf):
		class = "EV"
		reason = "the certificate carries a CA/Browser Forum extended-validation policy identifier"
	case len(leaf.Subject.Organization) > 0:
		class = "OV"
		reason = fmt.Sprintf("the certificate names the organisation %q, which is what an organisation-validated certificate looks like",
			leaf.Subject.Organization[0])
	}

	var chain []string
	for i, c := range certs {
		chain = append(chain, fmt.Sprintf("depth=%d subject=%s issuer=%s", i, c.Subject.CommonName, c.Issuer.CommonName))
	}
	return finding.Finding{
		Kind:     "tls-classification",
		Severity: finding.SeverityInfo,
		What:     "validation=" + class,
		Because:  reason,
		Detail: fmt.Sprintf("level=%s\nissuer=%s\nchain_length=%d\n%s",
			class, leaf.Issuer.CommonName, len(certs), strings.Join(chain, "\n")),
	}
}

func hasEVPolicy(leaf *x509.Certificate) bool {
	for _, oid := range leaf.PolicyIdentifiers {
		if cabfEVPolicyOIDs[oid.String()] || strings.HasPrefix(oid.String(), "2.23.140.1.1") {
			return true
		}
	}
	return false
}

// sniFindings is FR-C20: connect with the additional names a host is likely
// to answer for and report how many distinct certificates are presented.
// Extra handshakes, so it rides on the enumeration opt-in.
func sniFindings(t targetLike, enabled bool) []finding.Finding {
	if !enabled {
		return nil
	}
	host := t.Host
	names := []string{host}
	// A bare apex name is commonly answered by a separate www certificate.
	if strings.Contains(host, ".") && !strings.HasPrefix(host, "www.") {
		names = append(names, "www."+host)
	}

	type seen struct {
		name string
		fp   string
	}
	var results []seen
	unique := map[string]bool{}
	for _, name := range names {
		fp, ok := leafFingerprintFor(t, name)
		if !ok {
			results = append(results, seen{name: name, fp: "(handshake failed)"})
			continue
		}
		results = append(results, seen{name: name, fp: fp})
		unique[fp] = true
	}

	var lines []string
	for _, r := range results {
		lines = append(lines, fmt.Sprintf("sni=%s fn=%s", r.name, r.fp))
	}
	if len(unique) <= 1 {
		return []finding.Finding{{
			Kind:     "tls-sni",
			Severity: finding.SeverityInfo,
			What:     fmt.Sprintf("sni_certificates=%d", len(unique)),
			Because:  "every probed server name was answered with the same certificate",
			Detail:   strings.Join(lines, "\n"),
		}}
	}
	return []finding.Finding{{
		Kind:     "tls-sni",
		Severity: finding.SeverityInfo,
		What:     fmt.Sprintf("sni_certificates=%d", len(unique)),
		Because: fmt.Sprintf("the host presents %d different certificates depending on the requested server name",
			len(unique)),
		Detail: strings.Join(lines, "\n"),
	}}
}

// leafFingerprintFor completes a handshake with a specific SNI name and
// returns the SHA-256 fingerprint of the leaf certificate.
func leafFingerprintFor(t targetLike, name string) (string, bool) {
	cfg := &tls.Config{
		InsecureSkipVerify:       true,
		ServerName:               name,
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: false,
	}
	dialer := &net.Dialer{Timeout: probeTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", t.Addr(), cfg)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", false
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	return fmt.Sprintf("sha256:%x", sum[:12]), true
}

// crlFindings is FR-C10's CRL half: fetch each advertised CRL distribution
// point, verify it against the issuer that signed it, and look the leaf's
// serial number up in the revocation list.
func crlFindings(ctx Context, leaf, issuer *x509.Certificate) []finding.Finding {
	if !ctx.CheckRevocation {
		return nil
	}
	if len(leaf.CRLDistributionPoints) == 0 {
		return []finding.Finding{{
			Kind:     "tls-crl",
			Severity: finding.SeverityInfo,
			What:     "no crl endpoint",
			Because:  "the certificate does not advertise a CRL distribution point, so revocation can only be answered by OCSP",
		}}
	}
	// Every advertised endpoint is read, because a clean list on one endpoint
	// must not hide a revocation published on another.
	var unreadable, clean []string
	for _, url := range leaf.CRLDistributionPoints {
		list, err := fetchCRL(url)
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s: %v", url, err))
			continue
		}
		if issuer != nil {
			if err := list.CheckSignatureFrom(issuer); err != nil {
				unreadable = append(unreadable, fmt.Sprintf("%s: crl signature not verifiable from the served issuer (%v)", url, err))
				continue
			}
		}
		for _, entry := range list.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				detail := fmt.Sprintf("crl=%s\nserial=%s\nrevoked_at=%s",
					url, leaf.SerialNumber.String(), entry.RevocationTime.Format(time.RFC3339))
				if len(unreadable) > 0 {
					detail += "\nunreadable:\n" + strings.Join(unreadable, "\n")
				}
				return []finding.Finding{{
					Kind:     "tls-crl",
					Severity: finding.SeverityCritical,
					What:     "revoked",
					Because: fmt.Sprintf("the CRL at %s lists this certificate's serial number as revoked (%s)",
						url, entry.RevocationTime.Format(time.RFC3339)),
					Detail: detail,
				}}
			}
		}
		clean = append(clean, fmt.Sprintf("crl=%s\nserial=%s\nnext_update=%s",
			url, leaf.SerialNumber.String(), list.NextUpdate.Format(time.RFC3339)))
	}

	if len(clean) > 0 {
		detail := strings.Join(clean, "\n")
		because := "no advertised CRL distribution point lists this certificate's serial number"
		if len(unreadable) > 0 {
			detail += "\nunreadable:\n" + strings.Join(unreadable, "\n")
			because = "the readable CRL distribution point(s) do not list this certificate's serial number; the rest could not be read, which the detail records"
		}
		return []finding.Finding{{
			Kind:     "tls-crl",
			Severity: finding.SeverityInfo,
			What:     "crl good",
			Because:  because,
			Detail:   detail,
		}}
	}
	return []finding.Finding{{
		Kind:     "tls-crl",
		Severity: finding.SeverityLow,
		What:     "crl unreachable",
		Because:  "no advertised CRL distribution point could be read, so revocation status is unknown from CRLs",
		Detail:   strings.Join(unreadable, "\n"),
	}}
}

// fetchCRL downloads and parses a CRL, accepting DER or PEM.
func fetchCRL(url string) (*x509.RevocationList, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("unsupported CRL scheme in %s", url)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crl server returned status %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(body); block != nil {
		body = block.Bytes
	}
	return x509.ParseRevocationList(body)
}
