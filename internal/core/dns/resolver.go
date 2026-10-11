// Package dns is the shared Go DNS client for the network inspection module.
// It provides convenient lookup helpers over the stable miekg/dns client.
//
// It is a duplicate of the internals that dnscheck previously held, but
// dnscheck was left with the older, duplicated implementation (imports
// fmt/net/strings) and could not compile. dnscheck keeps its own
// dnscheck.Context + Run so the engine's struct is not changed.
package dns

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Context carries DNS lookup configuration.
type Context struct {
	CustomResolver string
	Timeout        time.Duration
}

// Lookup performs a DNS query and returns answers.
func Lookup(ctx Context, name string, qtype uint16) ([]dns.RR, error) {
	client := &dns.Client{Timeout: ctx.Timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)

	var lastErr error
	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
	if ctx.CustomResolver != "" {
		resolvers = []string{ctx.CustomResolver}
	}

	for _, r := range resolvers {
		in, _, err := client.Exchange(msg, r)
		if err != nil {
			lastErr = err
			continue
		}
		var ans []dns.RR
		for _, rr := range in.Answer {
			if rr != nil {
				ans = append(ans, rr)
			}
		}
		return ans, nil
	}
	return nil, fmt.Errorf("dns lookup failed: %w", lastErr)
}

// LookupA returns the first A record.
func LookupA(ctx Context, name string) (net.IP, error) {
	rrs, err := Lookup(ctx, name, dns.TypeA)
	if err != nil {
		return nil, err
	}
	for _, r := range rrs {
		if a, ok := r.(*dns.A); ok {
			return a.A, nil
		}
	}
	return nil, fmt.Errorf("no A record for %s", name)
}

// LookupMX returns the first MX record.
func LookupMX(ctx Context, name string) (dns.MX, error) {
	rrs, err := Lookup(ctx, name, dns.TypeMX)
	if err != nil {
		return dns.MX{}, err
	}
	for _, r := range rrs {
		if mx, ok := r.(*dns.MX); ok && len(mx.Mx) > 0 {
			return *mx, nil
		}
	}
	return dns.MX{}, fmt.Errorf("no MX record for %s", name)
}

// LookupTXT returns all TXT records joined.
func LookupTXT(ctx Context, name string) ([]string, error) {
	rrs, err := Lookup(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rrs {
		if txt, ok := r.(*dns.TXT); ok {
			out = append(out, strings.Join(txt.Txt, " "))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no TXT record for %s", name)
	}
	return out, nil
}

// LookupNS returns all NS records.
func LookupNS(ctx Context, name string) ([]string, error) {
	rrs, err := Lookup(ctx, name, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rrs {
		if ns, ok := r.(*dns.NS); ok {
			out = append(out, ns.Ns)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no NS record for %s", name)
	}
	return out, nil
}

// LookupSOA returns the first SOA record.
func LookupSOA(ctx Context, name string) (*dns.SOA, error) {
	rrs, err := Lookup(ctx, name, dns.TypeSOA)
	if err != nil {
		return nil, err
	}
	for _, r := range rrs {
		if soa, ok := r.(*dns.SOA); ok {
			return soa, nil
		}
	}
	return nil, fmt.Errorf("no SOA record for %s", name)
}

// LookupCAA returns all CAA records.
func LookupCAA(ctx Context, name string) ([]dns.CAA, error) {
	rrs, err := Lookup(ctx, name, dns.TypeCAA)
	if err != nil {
		return nil, err
	}
	var out []dns.CAA
	for _, r := range rrs {
		if caa, ok := r.(*dns.CAA); ok {
			out = append(out, *caa)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no CAA record for %s", name)
	}
	return out, nil
}

// LookupSRV returns the first SRV record.
func LookupSRV(ctx Context, name string) (*dns.SRV, error) {
	rrs, err := Lookup(ctx, name, dns.TypeSRV)
	if err != nil {
		return nil, err
	}
	for _, r := range rrs {
		if srv, ok := r.(*dns.SRV); ok {
			return srv, nil
		}
	}
	return nil, fmt.Errorf("no SRV record for %s", name)
}

// LookupPTR returns the first PTR record.
func LookupPTR(ctx Context, name string) (string, error) {
	rrs, err := Lookup(ctx, name, dns.TypePTR)
	if err != nil {
		return "", err
	}
	for _, r := range rrs {
		if ptr, ok := r.(*dns.PTR); ok {
			return ptr.Ptr, nil
		}
	}
	return "", fmt.Errorf("no PTR record for %s", name)
}

// LookupCNAMERecord returns the first CNAME record.
func LookupCNAMERecord(ctx Context, name string) (string, error) {
	rrs, err := Lookup(ctx, name, dns.TypeCNAME)
	if err != nil {
		return "", err
	}
	for _, r := range rrs {
		if cname, ok := r.(*dns.CNAME); ok {
			return cname.Target, nil
		}
	}
	return "", fmt.Errorf("no CNAME record for %s", name)
}
