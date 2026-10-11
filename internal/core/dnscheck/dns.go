package dnscheck

import (
	"fmt"
	"net"
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

	return Result{Target: t, Findings: f}
}

// LookupA returns the first A record.
func LookupA(ctx Context, name string, timeout time.Duration) (net.IP, error) {
	c := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeA)

	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
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

	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
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

	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
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
