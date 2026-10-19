package dnscheck

import (
	"fmt"
	"strings"
	"time"

	"github.com/dnsvigil/dnsvigil/internal/core/finding"
	"github.com/miekg/dns"
)

// rootAnchor is IANA's published root KSK-2017 trust anchor (key tag 20326,
// RSASHA256, SHA-256 digest). Starting from a configured anchor is what makes a
// result a validation rather than an observation that records exist.
var rootAnchor = &dns.DS{
	Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
	KeyTag:     20326,
	Algorithm:  dns.RSASHA256,
	DigestType: dns.SHA256,
	Digest:     "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
}

// rootTrustAnchor returns the anchor in force (tests replace it).
func rootTrustAnchor() *dns.DS { return rootAnchor }

// setRootTrustAnchor swaps the anchor and returns the restore function.
func setRootTrustAnchor(ds *dns.DS) func() {
	previous := rootAnchor
	rootAnchor = ds
	return func() { rootAnchor = previous }
}

// signedAnswer is one query's records plus the signatures that cover them.
type signedAnswer struct {
	records []dns.RR
	sigs    []*dns.RRSIG
	err     error
}

// fetchSigned asks for a record set with the EDNS0 DO bit set, so the covering
// RRSIGs come back with it, and splits the answer.
func fetchSigned(ctx Context, name string, qtype uint16, timeout time.Duration) signedAnswer {
	rrs, err := lookupDO(ctx, name, qtype, timeout)
	out := signedAnswer{err: err}
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.RRSIG:
			if v.TypeCovered == qtype {
				out.sigs = append(out.sigs, v)
			}
		default:
			if rr.Header().Rrtype == qtype {
				out.records = append(out.records, rr)
			}
		}
	}
	return out
}

// verifyRRset checks that some signature over rrs verifies against the key with
// the matching key tag in keys.
func verifyRRset(rrs []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY) error {
	if len(rrs) == 0 {
		return fmt.Errorf("no records to verify")
	}
	if len(sigs) == 0 {
		return fmt.Errorf("no RRSIG covers %s", rrs[0].Header().Name)
	}
	byTag := map[uint16]*dns.DNSKEY{}
	for _, k := range keys {
		byTag[k.KeyTag()] = k
	}
	var lastErr error
	for _, sig := range sigs {
		key := byTag[sig.KeyTag]
		if key == nil {
			continue
		}
		if err := sig.Verify(key, rrs); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("no served key matches the RRSIG key tag over %s", rrs[0].Header().Name)
}

// keysMatchingDS returns the DNSKEYs whose digest matches one of the DS records.
func keysMatchingDS(dsRRs []dns.RR, keys []*dns.DNSKEY) *dns.DNSKEY {
	for _, rr := range dsRRs {
		ds, ok := rr.(*dns.DS)
		if !ok {
			continue
		}
		for _, key := range keys {
			if !strings.EqualFold(key.Header().Name, ds.Header().Name) {
				continue
			}
			if key.Algorithm != ds.Algorithm {
				continue
			}
			computed := key.ToDS(ds.DigestType)
			if computed != nil && strings.EqualFold(computed.Digest, ds.Digest) {
				return key
			}
		}
	}
	return nil
}

// zoneSuffixes lists the delegation levels from the top of the tree down to the
// host: "com", "example.com", and the host itself when it is deeper.
func zoneSuffixes(host string) []string {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(host), "."), ".")
	var out []string
	for i := len(labels) - 1; i >= 0; i-- {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

// dnssecChainFinding validates the delegation chain from the root anchor to
// host (FR-D3). It reports:
//
//	dnssec validated  — every level from the root down to the zone holding the
//	                    name chained: DS digest matched a served DNSKEY and each
//	                    RRset carried a verifying RRSIG
//	dnssec insecure   — a delegation in the path publishes no DS, so validating
//	                    resolvers treat everything below it as unsigned
//	dnssec bogus      — a signature or digest in the path does not hold (High)
//	dnssec unvalidated— the anchor's key is not in the served root DNSKEY set
func dnssecChainFinding(ctx Context, host string, timeout time.Duration) finding.Finding {
	anchor := rootTrustAnchor()
	if anchor == nil {
		return finding.Finding{
			Kind:     "dns-dnssec",
			Severity: finding.SeverityMedium,
			What:     "dnssec unvalidated",
			Because:  "no root trust anchor is configured, so no chain could be validated",
		}
	}

	root := fetchSigned(ctx, ".", dns.TypeDNSKEY, timeout)
	if root.err != nil || len(root.records) == 0 {
		return finding.Finding{
			Kind:     "dns-dnssec",
			Severity: finding.SeverityLow,
			What:     "dnssec unavailable",
			Because:  "the root DNSKEY could not be retrieved, so no chain could be validated",
			Detail:   describeErr(root.err),
		}
	}
	rootKeys := asDNSKEYs(root.records)
	anchorKey := keysMatchingDS([]dns.RR{anchor}, rootKeys)
	if anchorKey == nil {
		return finding.Finding{
			Kind:     "dns-dnssec",
			Severity: finding.SeverityMedium,
			What:     "dnssec unvalidated",
			Because:  "the served root DNSKEY set does not contain the key the configured trust anchor commits to, so the chain cannot start",
			Detail:   fmt.Sprintf("anchor_keytag=%d", anchor.KeyTag),
		}
	}
	if err := verifyRRset(root.records, root.sigs, rootKeys); err != nil {
		return finding.Finding{
			Kind:     "dns-dnssec",
			Severity: finding.SeverityHigh,
			What:     "dnssec bogus",
			Because:  "the root DNSKEY set does not verify against its own RRSIG, so nothing can be trusted from this resolver",
			Detail:   "zone=.\nerror=" + err.Error(),
		}
	}

	validated := []string{"."}
	parentKeys := rootKeys
	for _, zone := range zoneSuffixes(host) {
		ds := fetchSigned(ctx, zone, dns.TypeDS, timeout)
		if len(ds.records) == 0 {
			// No DS: this name is not a signed delegation. Everything above it
			// was validated, everything at or below is insecure by definition.
			return finding.Finding{
				Kind:     "dns-dnssec",
				Severity: finding.SeverityInfo,
				What:     "dnssec insecure",
				Because: fmt.Sprintf("%s publishes no DS record, so validating resolvers treat it and everything below it as unsigned",
					dns.Fqdn(zone)),
				Detail: fmt.Sprintf("validated=%s\nunsigned_from=%s", strings.Join(validated, ","), dns.Fqdn(zone)),
			}
		}
		if err := verifyRRset(ds.records, ds.sigs, parentKeys); err != nil {
			return finding.Finding{
				Kind:     "dns-dnssec",
				Severity: finding.SeverityHigh,
				What:     "dnssec bogus",
				Because: fmt.Sprintf("the DS record at %s does not verify against the key set of its parent zone, so the delegation cannot be trusted",
					dns.Fqdn(zone)),
				Detail: fmt.Sprintf("zone=%s\nparent=%s\nerror=%v", dns.Fqdn(zone), strings.Join(validated, ","), err),
			}
		}

		child := fetchSigned(ctx, zone, dns.TypeDNSKEY, timeout)
		childKeys := asDNSKEYs(child.records)
		if child.err != nil || len(childKeys) == 0 {
			return finding.Finding{
				Kind:     "dns-dnssec",
				Severity: finding.SeverityHigh,
				What:     "dnssec bogus",
				Because: fmt.Sprintf("%s has a DS record at its parent but serves no DNSKEY, so the delegation cannot be validated",
					dns.Fqdn(zone)),
				Detail: fmt.Sprintf("zone=%s\nvalidated=%s\nerror=%v", dns.Fqdn(zone), strings.Join(validated, ","), child.err),
			}
		}
		if matched := keysMatchingDS(ds.records, childKeys); matched == nil {
			return finding.Finding{
				Kind:     "dns-dnssec",
				Severity: finding.SeverityHigh,
				What:     "dnssec bogus", Because: fmt.Sprintf("no DNSKEY served by %s produces the digest published in its parent's DS record", dns.Fqdn(zone)),
				Detail: fmt.Sprintf("zone=%s\nvalidated=%s", dns.Fqdn(zone), strings.Join(validated, ",")),
			}
		}
		if err := verifyRRset(child.records, child.sigs, childKeys); err != nil {
			return finding.Finding{
				Kind:     "dns-dnssec",
				Severity: finding.SeverityHigh,
				What:     "dnssec bogus",
				Because:  fmt.Sprintf("the DNSKEY set of %s does not verify against its own RRSIG", dns.Fqdn(zone)),
				Detail:   fmt.Sprintf("zone=%s\nerror=%v", dns.Fqdn(zone), err.Error()),
			}
		}
		validated = append(validated, dns.Fqdn(zone))
		parentKeys = childKeys
	}

	return finding.Finding{
		Kind:     "dns-dnssec",
		Severity: finding.SeverityInfo,
		What:     "dnssec validated",
		Because: fmt.Sprintf("every delegation from the root anchor down to %s chained: the DS digest at each level matched a served DNSKEY and each key set carried a verifying RRSIG",
			validated[len(validated)-1]),
		Detail: "validated=" + strings.Join(validated, ",\nvalidated="),
	}
}

// asDNSKEYs filters answers down to DNSKEY records.
func asDNSKEYs(rrs []dns.RR) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, rr := range rrs {
		if k, ok := rr.(*dns.DNSKEY); ok {
			out = append(out, k)
		}
	}
	return out
}

// describeErr renders a possibly-nil error for the finding detail.
func describeErr(err error) string {
	if err == nil {
		return "no records returned"
	}
	return err.Error()
}
