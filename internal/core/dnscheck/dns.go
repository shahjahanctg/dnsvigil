package dnscheck

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/soc-tool/internal/core/finding"
	"github.com/soc-tool/internal/core/target"
)

// Context must be compatible with the TLS context so the engine can share one struct.
// We copy the relevant fields rather than type-aliasing the whole struct.
type Context struct {
	Host           string
	Port           int
	Proxy          string
	CustomResolver string
	// SecondResolver enables resolver-divergence comparison (FR-D11).
	SecondResolver string
	Timeout        time.Duration
	Logger         func(...any)
}

// Result is the full DNS check result for one target.
type Result struct {
	Target   target.Target
	Findings []finding.Finding
	Error    error
}

// Run performs the DNS checks for a target.
func Run(ctx Context, t target.Target) Result {
	if t.Port == 0 {
		t.Port = 443
	}

	timeout := 5 * time.Second
	var f []finding.Finding

	// A
	if ip, err := LookupA(ctx, t.Host, timeout); err == nil {
		f = append(f, finding.Finding{
			Kind:     "dns-a",
			Severity: finding.SeverityInfo,
			What:     "a=" + ip.String(),
			Because:  "an A record exists for " + t.Host,
		})
	} else {
		f = append(f, finding.Finding{
			Kind:     "dns-a",
			Severity: finding.SeverityMedium,
			What:     "no A record",
			Because:  "no A record was found for " + t.Host,
			Detail:   err.Error(),
		})
	}

	// AAAA
	if ips, err := LookupAAAA(ctx, t.Host, timeout); err == nil && len(ips) > 0 {
		f = append(f, finding.Finding{
			Kind:     "dns-aaaa",
			Severity: finding.SeverityInfo,
			What:     "aaaa=" + ips[0].String(),
			Because:  "an AAAA record exists for " + t.Host,
		})
	} else {
		f = append(f, finding.Finding{
			Kind:     "dns-aaaa",
			Severity: finding.SeverityInfo,
			What:     "no AAAA record",
			Because:  "no AAAA record was found (normal for many sites)",
		})
	}

	// CAA
	if cas, err := LookupCAA(ctx, t.Host, timeout); err == nil && len(cas) > 0 {
		f = append(f, finding.Finding{
			Kind:     "dns-caa",
			Severity: finding.SeverityInfo,
			What:     "caa=" + cas[0].Value,
			Because:  "a CAA record exists for " + t.Host,
		})
	} else {
		f = append(f, finding.Finding{
			Kind:     "dns-caa",
			Severity: finding.SeverityMedium,
			What:     "no CAA record",
			Because:  "no CAA record was found for " + t.Host,
			Detail:   err.Error(),
		})
	}

	// Core record set (FR-D1): CNAME, MX, TXT, NS, SOA are T1 queries.
	// Missing records are recorded as absent (INFO); these are facts, not
	// faults, for the apex of a website.
	f = append(f, coreRecordFindings(ctx, t.Host, timeout)...)

	// Mail hygiene (FR-D4/D5): SPF and DMARC presence/policy checks.
	f = append(f, spfFinding(ctx, t.Host, timeout))
	f = append(f, dmarcFinding(ctx, t.Host, timeout))

	// Tier 2: DNSSEC status (FR-D3), dangling CNAME (FR-D9), wildcard
	// (FR-D10), resolver divergence (FR-D11 when a second resolver is set).
	f = append(f, dnssecStatusFinding(ctx, t.Host, timeout))
	if d := danglingCNAMEFinding(ctx, t.Host, timeout); d.Kind != "" {
		f = append(f, d)
	}
	f = append(f, wildcardDetectionFinding(ctx, t.Host, timeout))
	if d := resolverDivergenceFinding(ctx, t.Host, timeout); d.Kind != "" {
		f = append(f, d)
	}

	return Result{Target: t, Findings: f}
}

// coreRecordFindings queries CNAME, MX, TXT, NS, and SOA and records what
// exists (FR-D1). Values are INFO facts; only lookup transport errors no op.
func coreRecordFindings(ctx Context, host string, timeout time.Duration) []finding.Finding {
	var f []finding.Finding
	add := func(kind, name string, ok bool, what, because string, detail string) {
		if ok {
			f = append(f, finding.Finding{Kind: kind, Severity: finding.SeverityInfo, What: what, Because: because, Detail: detail})
		} else {
			f = append(f, finding.Finding{Kind: kind, Severity: finding.SeverityInfo, What: "no " + name, Because: "no " + name + " record exists for " + host + " (normal when not applicable)"})
		}
	}

	if cn, err := LookupCNAME(ctx, host, timeout); err == nil && cn != "" {
		add("dns-cname", "CNAME", true, "cname="+cn, "a CNAME record exists for "+host, "target="+cn)
	} else {
		add("dns-cname", "CNAME", false, "", "", "")
	}

	if mxs, err := LookupMX(ctx, host, timeout); err == nil && len(mxs) > 0 {
		var names []string
		for _, mx := range mxs {
			names = append(names, fmt.Sprintf("%d %s", mx.Preference, mx.Mx))
		}
		add("dns-mx", "MX", true, "mx="+strings.Join(names, ", "), "MX records exist for "+host, strings.Join(names, "\n"))
	} else {
		add("dns-mx", "MX", false, "", "", "")
	}

	if txts, err := LookupTXT(ctx, host, timeout); err == nil && len(txts) > 0 {
		add("dns-txt", "TXT", true, "txt="+strings.Join(txts, " | "), "TXT records exist for "+host, strings.Join(txts, "\n"))
	} else {
		add("dns-txt", "TXT", false, "", "", "")
	}

	if nss, err := LookupNS(ctx, host, timeout); err == nil && len(nss) > 0 {
		add("dns-ns", "NS", true, "ns="+strings.Join(nss, ", "), "NS records define the nameservers delegated for "+host, "nameservers="+strings.Join(nss, "\n"))
	} else {
		add("dns-ns", "NS", false, "", "", "")
	}

	if soa, err := LookupSOA(ctx, host, timeout); err == nil && soa != nil {
		add("dns-soa", "SOA", true, "soa="+soa.Ns, "an SOA record exists for "+host, soa.String())
	} else {
		add("dns-soa", "SOA", false, "", "", "")
	}
	return f
}

// spfFinding checks SPF presence and basic policy per FR-D4.
func spfFinding(ctx Context, host string, timeout time.Duration) finding.Finding {
	txts, err := LookupTXT(ctx, host, timeout)
	if err != nil {
		return finding.Finding{
			Kind:     "dns-spf",
			Severity: finding.SeverityMedium,
			What:     "no SPF record",
			Because:  "no SPF record was found for " + host + ", so sending servers are not authorised",
		}
	}
	for _, txt := range txts {
		t := strings.TrimSpace(txt)
		lower := strings.ToLower(t)
		switch {
		case strings.HasPrefix(lower, "v=spf1"):
			if strings.Contains(lower, "+all") || strings.Contains(lower, "?all") {
				return finding.Finding{
					Kind:     "dns-spf",
					Severity: finding.SeverityHigh,
					What:     "permissive SPF policy",
					Because:  "the SPF record ends in a catch-all mechanism, so any server may send mail as " + host,
					Detail:   txt,
				}
			}
			return finding.Finding{
				Kind:     "dns-spf",
				Severity: finding.SeverityInfo,
				What:     "spf present",
				Because:  "an SPF record authorises which servers may send mail for " + host,
				Detail:   txt,
			}
		}
	}
	return finding.Finding{
		Kind:     "dns-spf",
		Severity: finding.SeverityMedium,
		What:     "no SPF record",
		Because:  "no SPF record was found for " + host + ", so sending servers are not authorised",
	}
}

// dmarcFinding checks DMARC presence and policy per FR-D5.
func dmarcFinding(ctx Context, host string, timeout time.Duration) finding.Finding {
	domain := "_dmarc." + host
	txts, err := LookupTXT(ctx, domain, timeout)
	if err != nil {
		return finding.Finding{
			Kind:     "dns-dmarc",
			Severity: finding.SeverityMedium,
			What:     "no DMARC record",
			Because:  "no DMARC policy was found for " + host + ", so receivers decide how to handle spoofed mail",
		}
	}
	for _, txt := range txts {
		t := strings.TrimSpace(txt)
		lower := strings.ToLower(t)
		if !strings.HasPrefix(lower, "v=dmarc1") {
			continue
		}
		if strings.Contains(lower, "p=none") {
			return finding.Finding{
				Kind:     "dns-dmarc",
				Severity: finding.SeverityMedium,
				What:     "weak DMARC policy (p=none)",
				Because:  "the DMARC policy is p=none, which asks receivers not to act on failures",
				Detail:   t,
			}
		}
		return finding.Finding{
			Kind:     "dns-dmarc",
			Severity: finding.SeverityInfo,
			What:     "dmarc present",
			Because:  "a DMARC policy tells receivers how to handle mail that fails alignment for " + host,
			Detail:   t,
		}
	}
	return finding.Finding{
		Kind:     "dns-dmarc",
		Severity: finding.SeverityMedium,
		What:     "no DMARC record",
		Because:  "no DMARC policy was found for " + host + ", so receivers decide how to handle spoofed mail",
	}
}

// LookupA returns the first A record.
func LookupA(ctx Context, name string, timeout time.Duration) (net.IP, error) {
	c := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeA)

	resolvers := ctx.resolverList()
	for _, r := range resolvers {
		in, _, err := c.Exchange(msg, r)
		if err != nil {
			continue
		}
		for _, rr := range in.Answer {
			if a, ok := rr.(*dns.A); ok {
				return a.A, nil
			}
		}
	}
	return nil, fmt.Errorf("no A record for %s", name)
}

// LookupAAAA returns all AAAA records.
func LookupAAAA(ctx Context, name string, timeout time.Duration) ([]net.IP, error) {
	c := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)

	resolvers := ctx.resolverList()
	for _, r := range resolvers {
		in, _, err := c.Exchange(msg, r)
		if err != nil {
			continue
		}
		var ips []net.IP
		for _, rr := range in.Answer {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				ips = append(ips, aaaa.AAAA)
			}
		}
		if len(ips) > 0 {
			return ips, nil
		}
	}
	return nil, fmt.Errorf("no AAAA record for %s", name)
}

// LookupCAA returns all CAA records.
func LookupCAA(ctx Context, name string, timeout time.Duration) ([]dns.CAA, error) {
	c := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeCAA)

	resolvers := ctx.resolverList()
	for _, r := range resolvers {
		in, _, err := c.Exchange(msg, r)
		if err != nil {
			continue
		}
		var cas []dns.CAA
		for _, rr := range in.Answer {
			if caa, ok := rr.(*dns.CAA); ok {
				cas = append(cas, *caa)
			}
		}
		if len(cas) > 0 {
			return cas, nil
		}
	}
	return nil, fmt.Errorf("no CAA record for %s", name)
}

// LookupCNAME returns the CNAME target, or "" when the name is not an alias.
func LookupCNAME(ctx Context, name string, timeout time.Duration) (string, error) {
	c := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeCNAME)

	for _, r := range ctx.resolverList() {
		in, _, err := c.Exchange(msg, r)
		if err != nil {
			continue
		}
		for _, rr := range in.Answer {
			if cn, ok := rr.(*dns.CNAME); ok {
				return cn.Target, nil
			}
		}
	}
	return "", fmt.Errorf("no CNAME record for %s", name)
}

// LookupMX returns all MX records.
func LookupMX(ctx Context, name string, timeout time.Duration) ([]*dns.MX, error) {
	c := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeMX)

	for _, r := range ctx.resolverList() {
		in, _, err := c.Exchange(msg, r)
		if err != nil {
			continue
		}
		var mxs []*dns.MX
		for _, rr := range in.Answer {
			if mx, ok := rr.(*dns.MX); ok {
				mxs = append(mxs, mx)
			}
		}
		if len(mxs) > 0 {
			return mxs, nil
		}
	}
	return nil, fmt.Errorf("no MX record for %s", name)
}

// LookupTXT returns all TXT record strings.
func LookupTXT(ctx Context, name string, timeout time.Duration) ([]string, error) {
	c := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeTXT)

	for _, r := range ctx.resolverList() {
		in, _, err := c.Exchange(msg, r)
		if err != nil {
			continue
		}
		var out []string
		for _, rr := range in.Answer {
			if txt, ok := rr.(*dns.TXT); ok {
				out = append(out, txt.Txt...)
			}
		}
		// TXT answers may split one record into several strings; the
		// resolver merges each TXT RRset entry already.
		if len(out) > 0 {
			return out, nil
		}
	}
	return nil, fmt.Errorf("no TXT record for %s", name)
}

// LookupNS returns all NS record hostnames.
func LookupNS(ctx Context, name string, timeout time.Duration) ([]string, error) {
	c := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeNS)

	for _, r := range ctx.resolverList() {
		in, _, err := c.Exchange(msg, r)
		if err != nil {
			continue
		}
		var nss []string
		for _, rr := range in.Answer {
			if ns, ok := rr.(*dns.NS); ok {
				nss = append(nss, ns.Ns)
			}
		}
		if len(nss) > 0 {
			return nss, nil
		}
	}
	return nil, fmt.Errorf("no NS record for %s", name)
}

// LookupSOA returns the SOA record for the zone.
func LookupSOA(ctx Context, name string, timeout time.Duration) (*dns.SOA, error) {
	c := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeSOA)

	for _, r := range ctx.resolverList() {
		in, _, err := c.Exchange(msg, r)
		if err != nil {
			continue
		}
		for _, rr := range in.Answer {
			if soa, ok := rr.(*dns.SOA); ok {
				return soa, nil
			}
		}
	}
	return nil, fmt.Errorf("no SOA record for %s", name)
}

// resolverList returns the resolvers to use, honoring ctx.CustomResolver (FR-D12).
func (ctx Context) resolverList() []string {
	if ctx.CustomResolver != "" {
		return []string{ctx.CustomResolver}
	}
	return []string{"1.1.1.1:53", "8.8.8.8:53"}
}
