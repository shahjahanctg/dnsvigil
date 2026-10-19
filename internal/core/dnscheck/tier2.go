package dnscheck

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dnsvigil/dnsvigil/internal/core/finding"
	"github.com/miekg/dns"
)

// Lookup is a local raw lookup over the shared client behaviour so tier-2
// checks do not need the legacy duplicate package.
func Lookup(ctx Context, name string, qtype uint16) ([]dns.RR, error) {
	c := &dns.Client{Timeout: 3 * time.Second}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	for _, r := range ctx.resolverList() {
		in, _, err := c.Exchange(msg, r)
		if err != nil {
			continue
		}
		if len(in.Answer) > 0 {
			return in.Answer, nil
		}
	}
	return nil, fmt.Errorf("no answers for type %d on %s", qtype, name)
}

// danglingCNAMEFinding is FR-D9: a CNAME pointing at a name without any
// address records is a takeover risk and must be Critical.
func danglingCNAMEFinding(ctx Context, host string, timeout time.Duration) finding.Finding {
	target, err := LookupCNAME(ctx, host, timeout)
	if err != nil || target == "" || strings.EqualFold(target, host) {
		return finding.Finding{} // not an alias; nothing to check
	}
	hasA, errA := LookupA(ctx, strings.TrimSuffix(target, "."), timeout)
	hasAAAA, errAAAA := LookupAAAA(ctx, strings.TrimSuffix(target, "."), timeout)
	if errA == nil && hasA != nil || errAAAA == nil && len(hasAAAA) > 0 {
		return finding.Finding{}
	}
	return finding.Finding{
		Kind:     "dns-dangling-cname",
		Severity: finding.SeverityCritical,
		What:     "dangling cname",
		Because: fmt.Sprintf("the CNAME for %s points at %s, which has no A or AAAA record, so the name can be claimed by a third party",
			host, target),
		Detail: "target=" + target,
	}
}

// wildcardDetectionFinding is FR-D10: a random subdomain that resolves means
// a wildcard record answers for unrelated names.
func wildcardDetectionFinding(ctx Context, host string, timeout time.Duration) finding.Finding {
	probe := "wildcard-probe-" + strconv.FormatInt(time.Now().UnixNano(), 36) + "." + host
	if ip, err := LookupA(ctx, probe, timeout); err == nil && ip != nil {
		return finding.Finding{
			Kind:     "dns-wildcard",
			Severity: finding.SeverityMedium,
			What:     "wildcard dns",
			Because: fmt.Sprintf("the random subdomain %s resolved, so a wildcard record answers for unrelated names and non-existent hosts stay resolvable",
				probe),
			Detail: "probe=" + probe + "\na=" + ip.String(),
		}
	}
	return finding.Finding{
		Kind:     "dns-wildcard",
		Severity: finding.SeverityInfo,
		What:     "no wildcard",
		Because:  "a random non-existent subdomain did not resolve, so wildcard records are not hiding NXDOMAIN answers",
	}
}

// resolverDivergenceFinding is FR-D11: when a second resolver is configured,
// A answers are compared; divergence is reported rather than silently
// following whichever responded first.
func resolverDivergenceFinding(ctx Context, host string, timeout time.Duration) finding.Finding {
	if ctx.SecondResolver == "" {
		return finding.Finding{}
	}
	primary := Context{CustomResolver: firstResolver(ctx), Timeout: timeout}
	second := Context{CustomResolver: ctx.SecondResolver, Timeout: timeout}

	ipA, errA := LookupA(primary, host, timeout)
	ipB, errB := LookupA(second, host, timeout)
	if errA != nil && errB != nil {
		return finding.Finding{}
	}
	if (errA != nil) != (errB != nil) {
		return finding.Finding{
			Kind:     "dns-resolver-divergence",
			Severity: finding.SeverityMedium,
			What:     "resolver divergence",
			Because:  fmt.Sprintf("the two configured resolvers disagree on whether %s has an A record", host),
			Detail: fmt.Sprintf("%s: %v\n%s: %v",
				firstResolver(ctx), errA, ctx.SecondResolver, errB),
		}
	}
	if !ipA.Equal(ipB) {
		return finding.Finding{
			Kind:     "dns-resolver-divergence",
			Severity: finding.SeverityMedium,
			What:     "resolver divergence",
			Because: fmt.Sprintf("the two configured resolvers answered with different IPs for %s; one of them may be stale or serving a different view",
				host),
			Detail: fmt.Sprintf("%s: %s\n%s: %s",
				firstResolver(ctx), ipA, ctx.SecondResolver, ipB),
		}
	}
	return finding.Finding{
		Kind:     "dns-resolver-divergence",
		Severity: finding.SeverityInfo,
		What:     "resolvers agree",
		Because:  "both configured resolvers answered with the same A record for " + host,
	}
}

// firstResolver returns the primary resolver used by resolverList.
func firstResolver(ctx Context) string {
	list := ctx.resolverList()
	if len(list) == 0 {
		return ""
	}
	return list[0]
}
