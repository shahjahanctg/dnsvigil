package dnscheck

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/soc-tool/internal/core/finding"
)

// queryMsg sends one query and returns the whole reply. recurse=false sets
// RD=0, which is how a delegation is probed for lameness (FR-D23).
func queryMsg(ctx Context, name string, qtype uint16, recurse bool, timeout time.Duration) (*dns.Msg, error) {
	c := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = recurse
	var lastErr error
	for _, r := range ctx.resolverList() {
		in, _, err := c.Exchange(msg, r)
		if err != nil {
			lastErr = err
			continue
		}
		return in, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no resolver answered for %s", name)
	}
	return nil, lastErr
}

// lookupDO asks for DNSSEC records with the EDNS0 DO bit set. Without it a
// validating resolver strips the RRSIGs, which would make a correctly signed
// zone look unsigned.
func lookupDO(ctx Context, name string, qtype uint16, timeout time.Duration) ([]dns.RR, error) {
	c := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.SetEdns0(4096, true)
	var lastErr error
	for _, r := range ctx.resolverList() {
		in, _, err := c.Exchange(msg, r)
		if err != nil {
			lastErr = err
			continue
		}
		if len(in.Answer) > 0 {
			return in.Answer, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no answers for type %d on %s", qtype, name)
	}
	return nil, lastErr
}

// srvPrefixes are the service locations most worth reporting (FR-D2).
var srvPrefixes = []string{
	"_https._tcp",
	"_imaps._tcp",
	"_submission._tcp",
	"_sip._tcp",
	"_sip._tls",
	"_xmpp-server._tcp",
	"_autodiscover._tcp",
	"_caldavs._tcp",
	"_carddavs._tcp",
}

// srvFindings reports the SRV records that exist for well-known services.
func srvFindings(ctx Context, host string, timeout time.Duration) []finding.Finding {
	var found []string
	for _, prefix := range srvPrefixes {
		name := prefix + "." + host
		rrs, err := Lookup(ctx, name, dns.TypeSRV)
		if err != nil {
			continue
		}
		for _, rr := range rrs {
			if s, ok := rr.(*dns.SRV); ok {
				found = append(found, fmt.Sprintf("%s -> %s:%d", name, s.Target, s.Port))
			}
		}
	}
	sort.Strings(found)
	if len(found) == 0 {
		return []finding.Finding{{
			Kind:     "dns-srv",
			Severity: finding.SeverityInfo,
			What:     "no srv records",
			Because:  "none of the well-known service prefixes hold an SRV record for " + host,
		}}
	}
	return []finding.Finding{{
		Kind:     "dns-srv",
		Severity: finding.SeverityInfo,
		What:     fmt.Sprintf("srv=%d", len(found)),
		Because:  "well-known service prefixes publish SRV records for " + host,
		Detail:   strings.Join(found, "\n"),
	}}
}

// ptrFindings reports reverse DNS for the host's A record (FR-D2) and whether
// the name it returns resolves back to the same address (FR-D19).
func ptrFindings(ctx Context, host string, timeout time.Duration) []finding.Finding {
	ip, err := LookupA(ctx, host, timeout)
	if err != nil || ip == nil {
		return []finding.Finding{{
			Kind:     "dns-ptr",
			Severity: finding.SeverityInfo,
			What:     "no reverse lookup",
			Because:  "no A record was available for " + host + ", so there is no address to look up in reverse",
		}}
	}
	rev, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return nil
	}
	ptrRRs, err := Lookup(ctx, strings.TrimSuffix(rev, "."), dns.TypePTR)
	if err != nil || len(ptrRRs) == 0 {
		return []finding.Finding{{
			Kind:     "dns-ptr",
			Severity: finding.SeverityInfo,
			What:     "no ptr record",
			Because:  fmt.Sprintf("%s has no PTR record, which is normal for web hosts and relevant mainly for mail servers", ip),
			Detail:   "reverse=" + rev,
		}}
	}
	ptr, ok := ptrRRs[0].(*dns.PTR)
	if !ok {
		return nil
	}
	name := strings.TrimSuffix(ptr.Ptr, ".")
	out := []finding.Finding{{
		Kind:     "dns-ptr",
		Severity: finding.SeverityInfo,
		What:     "ptr=" + name,
		Because:  fmt.Sprintf("%s reverse-resolves to %s", ip, name),
		Detail:   fmt.Sprintf("reverse=%s\nptr=%s", rev, name),
	}}

	fwd, err := LookupA(ctx, name, timeout)
	if err != nil || fwd == nil {
		out = append(out, finding.Finding{
			Kind:     "dns-fcrdns",
			Severity: finding.SeverityMedium,
			What:     "reverse dns mismatch",
			Because: fmt.Sprintf("the PTR for %s is %q, but %q has no A record pointing back, so the name is not forward-confirmed",
				ip, name, name),
			Detail: fmt.Sprintf("reverse=%s\nptr=%s\na=%s", rev, name, ip),
		})
		return out
	}
	if !fwd.Equal(ip) {
		out = append(out, finding.Finding{
			Kind:     "dns-fcrdns",
			Severity: finding.SeverityMedium,
			What:     "reverse dns mismatch",
			Because: fmt.Sprintf("the PTR for %s is %q, which resolves to %s instead — mail receivers treat that as a spoofing signal",
				ip, name, fwd),
			Detail: fmt.Sprintf("reverse=%s\nptr=%s\nptr_a=%s\na=%s", rev, name, fwd, ip),
		})
		return out
	}
	out = append(out, finding.Finding{
		Kind:     "dns-fcrdns",
		Severity: finding.SeverityInfo,
		What:     "forward-confirmed",
		Because:  fmt.Sprintf("%q resolves back to %s, so the reverse name is forward-confirmed", name, ip),
		Detail:   fmt.Sprintf("reverse=%s\nptr=%s\na=%s", rev, name, ip),
	})
	return out
}

// mtaStsFinding reports MTA-STS policy publication (FR-D7).
func mtaStsFinding(ctx Context, host string, timeout time.Duration) finding.Finding {
	return policyTxtFinding(ctx, "_mta-sts."+host, "dns-mta-sts", "v=STSv1",
		"MTA-STS tells senders to require TLS when delivering mail to this domain", host, timeout)
}

// tlsRptFinding reports TLS-RPT publication (FR-D7).
func tlsRptFinding(ctx Context, host string, timeout time.Duration) finding.Finding {
	return policyTxtFinding(ctx, "_smtp._tls."+host, "dns-tls-rpt", "v=TLSRPTv1",
		"TLS-RPT asks receivers to report TLS delivery failures for this domain", host, timeout)
}

// policyTxtFinding looks for a version-tagged TXT policy record.
func policyTxtFinding(ctx Context, name, kind, marker, purpose, host string, timeout time.Duration) finding.Finding {
	rrs, err := Lookup(ctx, name, dns.TypeTXT)
	if err == nil {
		for _, r := range rrs {
			t, ok := r.(*dns.TXT)
			if !ok {
				continue
			}
			joined := strings.Join(t.Txt, "")
			if strings.HasPrefix(strings.TrimSpace(joined), marker) {
				return finding.Finding{
					Kind:     kind,
					Severity: finding.SeverityInfo,
					What:     "published",
					Because:  purpose,
					Detail:   fmt.Sprintf("name=%s\nvalue=%s", name, joined),
				}
			}
		}
	}
	return finding.Finding{
		Kind:     kind,
		Severity: finding.SeverityMedium,
		What:     "not published",
		Because: fmt.Sprintf("%s publishes no %s record, so %s", host, marker,
			strings.TrimSuffix(strings.ToLower(purpose), " this domain")),
		Detail: "name=" + name,
	}
}

// tlsaFindings reports TLSA records for the service port (FR-D8).
func tlsaFindings(ctx Context, host string, port int, timeout time.Duration) []finding.Finding {
	if port == 0 {
		port = 443
	}
	name := fmt.Sprintf("_%d._tcp.%s", port, host)
	rrs, err := Lookup(ctx, name, dns.TypeTLSA)
	if err != nil || len(rrs) == 0 {
		return []finding.Finding{{
			Kind:     "dns-tlsa",
			Severity: finding.SeverityInfo,
			What:     "no tlsa records",
			Because: fmt.Sprintf("%s publishes no TLSA record, so certificate pinning is not defined in DNS for port %d",
				name, port),
			Detail: "name=" + name,
		}}
	}
	var lines []string
	for _, rr := range rrs {
		if t, ok := rr.(*dns.TLSA); ok {
			lines = append(lines, fmt.Sprintf("%s usage=%d selector=%d matching=%d data=%s",
				name, t.Usage, t.Selector, t.MatchingType, t.Certificate))
		}
	}
	return []finding.Finding{{
		Kind:     "dns-tlsa",
		Severity: finding.SeverityInfo,
		What:     fmt.Sprintf("tlsa=%d", len(lines)),
		Because:  "TLSA records pin this service's certificate in DNS (DANE)",
		Detail:   strings.Join(lines, "\n"),
	}}
}

// dkimSelectors are the labels most commonly used for DKIM keys (FR-D6).
var dkimSelectors = []string{"default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2", "mandrill", "sendgrid"}

// dkimPublishedKey reads the p= value out of a DKIM TXT record. An empty
// value is DKIM's published "revoked" marker, so it must not be counted as a
// usable key.
func dkimPublishedKey(record string) (string, bool) {
	lower := strings.ToLower(record)
	idx := strings.Index(lower, "p=")
	if idx < 0 {
		return "", false
	}
	value := strings.TrimSpace(record[idx+2:])
	if i := strings.IndexAny(value, " \t;"); i >= 0 {
		value = strings.TrimSpace(value[:i])
	}
	return value, value != ""
}

// dkimFinding probes common DKIM selectors for a published key.
func dkimFinding(ctx Context, host string, timeout time.Duration) finding.Finding {
	var found, revoked []string
	for _, sel := range dkimSelectors {
		name := sel + "._domainkey." + host
		rrs, err := Lookup(ctx, name, dns.TypeTXT)
		if err != nil {
			continue
		}
		for _, rr := range rrs {
			t, ok := rr.(*dns.TXT)
			if !ok {
				continue
			}
			joined := strings.Join(t.Txt, "")
			if key, ok := dkimPublishedKey(joined); ok {
				found = append(found, fmt.Sprintf("%s: %s", name, truncate(joined, 72)))
				_ = key
			} else if strings.Contains(strings.ToLower(joined), "v=dkim1") {
				// v=DKIM1 with an empty p= is the published revocation marker.
				revoked = append(revoked, name)
			}
			break
		}
	}
	sort.Strings(found)
	sort.Strings(revoked)
	switch {
	case len(found) > 0:
		return finding.Finding{
			Kind:     "dns-dkim",
			Severity: finding.SeverityInfo,
			What:     fmt.Sprintf("dkim_keys=%d", len(found)),
			Because:  "published DKIM keys with key material were found at common selector names",
			Detail:   strings.Join(found, "\n"),
		}
	case len(revoked) > 0:
		return finding.Finding{
			Kind:     "dns-dkim",
			Severity: finding.SeverityInfo,
			What:     "dkim key revoked",
			Because: fmt.Sprintf("%d selector(s) publish a DKIM record with an empty public key, which is the marker for a withdrawn key",
				len(revoked)),
			Detail: strings.Join(revoked, "\n"),
		}
	}
	return finding.Finding{
		Kind:     "dns-dkim",
		Severity: finding.SeverityInfo,
		What:     "no dkim key found",
		Because: fmt.Sprintf("none of the %d common DKIM selectors published usable key material for %s (a custom selector name would not be found)",
			len(dkimSelectors), host),
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// cnameChainFinding is FR-D21: follow the CNAME chain and detect loops. The
// chain is resolved here rather than relying on the resolver, so the loop is
// reported instead of being swallowed into SERVFAIL.
func cnameChainFinding(ctx Context, host string, timeout time.Duration) finding.Finding {
	const maxHops = 12
	seen := map[string]bool{strings.ToLower(host): true}
	current := host
	var chain []string
	for i := 0; i < maxHops; i++ {
		target, err := LookupCNAME(ctx, current, timeout)
		if err != nil || target == "" || strings.EqualFold(target, current) {
			break
		}
		next := strings.TrimSuffix(target, ".")
		chain = append(chain, fmt.Sprintf("%s -> %s", current, next))
		if seen[strings.ToLower(next)] {
			return finding.Finding{
				Kind:     "dns-cname-loop",
				Severity: finding.SeverityHigh,
				What:     "cname loop",
				Because:  fmt.Sprintf("the CNAME chain for %s returns to a name it already visited, which breaks resolution", host),
				Detail:   strings.Join(chain, "\n"),
			}
		}
		seen[strings.ToLower(next)] = true
		current = next
	}
	if len(chain) > 0 {
		return finding.Finding{
			Kind:     "dns-cname-chain",
			Severity: finding.SeverityInfo,
			What:     fmt.Sprintf("cname_hops=%d", len(chain)),
			Because:  "the name is an alias, resolved here one hop at a time so the chain is visible in the evidence",
			Detail:   strings.Join(chain, "\n"),
		}
	}
	return finding.Finding{}
}

// ttlFinding is FR-D22: report the TTLs that matter for caching decisions.
func ttlFinding(ctx Context, host string, timeout time.Duration) finding.Finding {
	var lines []string
	if in, err := queryMsg(ctx, host, dns.TypeA, true, timeout); err == nil {
		for _, rr := range in.Answer {
			lines = append(lines, fmt.Sprintf("A %s ttl=%d", rr.Header().Name, rr.Header().Ttl))
		}
	}
	if in, err := queryMsg(ctx, host, dns.TypeSOA, true, timeout); err == nil {
		for _, rr := range in.Answer {
			lines = append(lines, fmt.Sprintf("SOA %s ttl=%d", rr.Header().Name, rr.Header().Ttl))
		}
	}
	if in, err := queryMsg(ctx, host, dns.TypeNS, true, timeout); err == nil {
		for _, rr := range in.Answer {
			lines = append(lines, fmt.Sprintf("NS %s ttl=%d", rr.Header().Name, rr.Header().Ttl))
		}
	}
	if len(lines) == 0 {
		return finding.Finding{}
	}
	low := false
	for _, l := range lines {
		if strings.Contains(l, "ttl=0") {
			low = true
		}
	}
	sev := finding.SeverityInfo
	what := fmt.Sprintf("ttls=%d", len(lines))
	because := "record TTLs decide how long stale answers can persist after a change"
	if low {
		sev = finding.SeverityLow
		what = "ttl of zero"
		because = "at least one record has a TTL of zero, so every resolver must re-query it on each request"
	}
	return finding.Finding{Kind: "dns-ttl", Severity: sev, What: what, Because: because, Detail: strings.Join(lines, "\n")}
}

// lameDelegationFinding is FR-D23: every authoritative server named in NS
// must answer authoritatively for the zone.
func lameDelegationFinding(ctx Context, host string, timeout time.Duration) finding.Finding {
	nsRRs, err := Lookup(ctx, host, dns.TypeNS)
	if err != nil || len(nsRRs) == 0 {
		return finding.Finding{}
	}
	var names []string
	for _, rr := range nsRRs {
		if ns, ok := rr.(*dns.NS); ok {
			names = append(names, strings.TrimSuffix(ns.Ns, "."))
		}
	}
	sort.Strings(names)
	var lame, proxied, checked []string
	for _, nsName := range names {
		ips, err := LookupA(ctx, nsName, timeout)
		if err != nil || ips == nil {
			lame = append(lame, nsName+" (does not resolve)")
			continue
		}
		in, err := queryMsgTo(ctx, ips.String(), host, dns.TypeSOA, timeout)
		if err != nil {
			lame = append(lame, fmt.Sprintf("%s (no response from %s)", nsName, ips))
			continue
		}
		switch classifyDelegationReply(in) {
		case delegationAuthoritative:
			checked = append(checked, nsName)
		case delegationProxied:
			// A reply with recursion available (or validated data) did not
			// come from the authoritative server itself: a local forwarder,
			// VPN split DNS, or an intercepting resolver answered instead.
			// Calling that a lame delegation would be a false positive.
			proxied = append(proxied, fmt.Sprintf("%s (%s) answered with ra=%t ad=%t, so a recursive resolver replied instead of the authoritative server",
				nsName, ips, in.RecursionAvailable, in.AuthenticatedData))
		default:
			lame = append(lame, fmt.Sprintf("%s (%s answered without authority for %s)", nsName, ips, host))
		}
	}
	if len(lame) > 0 {
		return finding.Finding{
			Kind:     "dns-lame-delegation",
			Severity: finding.SeverityMedium,
			What:     fmt.Sprintf("lame_delegation=%d", len(lame)),
			Because: fmt.Sprintf("of %d nameservers delegated for %s, these do not answer authoritatively, so resolution can fail or fall back to another server",
				len(names), host),
			Detail: strings.Join(lame, "\n"),
		}
	}
	if len(proxied) > 0 {
		return finding.Finding{
			Kind:     "dns-lame-delegation",
			Severity: finding.SeverityLow,
			What:     "delegation not verifiable",
			Because:  "the delegation query was answered by a recursive resolver rather than the authoritative server named in NS, so lameness cannot be judged from this network",
			Detail:   strings.Join(proxied, "\n"),
		}
	}
	return finding.Finding{
		Kind:     "dns-lame-delegation",
		Severity: finding.SeverityInfo,
		What:     fmt.Sprintf("nameservers_authoritative=%d", len(checked)),
		Because:  "every nameserver delegated for " + host + " answers authoritatively for the zone",
		Detail:   strings.Join(checked, "\n"),
	}
}

// delegationVerdict is what a delegation probe learned about one server.
type delegationVerdict int

const (
	// delegationAuthoritative: the server itself answered for the zone.
	delegationAuthoritative delegationVerdict = iota
	// delegationLame: the server answered without authority for its own zone.
	delegationLame
	// delegationProxied: a recursive resolver answered instead of the server
	// that was probed, so lameness cannot be judged from here.
	delegationProxied
)

// classifyDelegationReply decides what a non-recursive SOA probe means.
func classifyDelegationReply(in *dns.Msg) delegationVerdict {
	if in == nil {
		return delegationLame
	}
	if in.Authoritative && len(in.Answer) > 0 {
		return delegationAuthoritative
	}
	if in.RecursionAvailable || in.AuthenticatedData {
		return delegationProxied
	}
	return delegationLame
}

// queryMsgTo sends a query directly to one server (used by delegation checks).
func queryMsgTo(ctx Context, server, name string, qtype uint16, timeout time.Duration) (*dns.Msg, error) {
	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		port := ctx.DelegationPort
		if port == 0 {
			port = 53
		}
		addr = net.JoinHostPort(server, strconv.Itoa(port))
	}
	c := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = false // ask the server as an authority, not as a forwarder
	in, _, err := c.Exchange(msg, addr)
	if err != nil {
		return nil, err
	}
	return in, nil
}

// dohProviders maps the operator's choice to an RFC 8484 JSON endpoint.
var dohProviders = map[string]string{
	"cloudflare": "https://cloudflare-dns.com/dns-query",
	"google":     "https://dns.google/resolve",
	"quad9":      "https://dns.quad9.net:5053/dns-query",
}

// dohEndpoint resolves the DoH provider selection (FR-D13). An empty value is
// the default; an https URL is used as given; anything else is an error, so a
// typo cannot silently fall back to a provider the operator did not choose.
func dohEndpoint(provider string) (string, error) {
	p := strings.TrimSpace(strings.ToLower(provider))
	if p == "" {
		return dohProviders["cloudflare"], nil
	}
	if url, ok := dohProviders[p]; ok {
		return url, nil
	}
	if strings.HasPrefix(p, "https://") {
		return provider, nil
	}
	return "", fmt.Errorf("%q is not a known provider (%s) or an https URL", provider, strings.Join(dohProviderNames(), ", "))
}

func dohProviderNames() []string {
	names := make([]string, 0, len(dohProviders))
	for name := range dohProviders {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// dohFinding is FR-D13: resolve over DNS-over-HTTPS and compare with the
// resolver used for the rest of the run.
func dohFinding(ctx Context, host string, timeout time.Duration) []finding.Finding {
	if !ctx.UseDoH {
		return nil
	}
	endpoint, err := dohEndpoint(ctx.DoHProvider)
	if err != nil {
		return []finding.Finding{{
			Kind:     "dns-doh",
			Severity: finding.SeverityLow,
			What:     "doh provider unusable",
			Because:  "the configured DNS-over-HTTPS provider could not be resolved to an endpoint, so no comparison was made",
			Detail:   err.Error(),
		}}
	}
	dohIP, err := dohLookupA(endpoint, host, timeout)
	if err != nil {
		return []finding.Finding{{
			Kind:     "dns-doh",
			Severity: finding.SeverityLow,
			What:     "doh query failed",
			Because:  "the DNS-over-HTTPS lookup did not return an answer, so no comparison was possible",
			Detail:   err.Error() + "\ndoh=" + endpoint,
		}}
	}
	udpIP, err := LookupA(ctx, host, timeout)
	if err != nil || udpIP == nil {
		return []finding.Finding{{
			Kind:     "dns-doh",
			Severity: finding.SeverityInfo,
			What:     "doh_a=" + dohIP.String(),
			Because:  "resolved over DNS-over-HTTPS; the local resolver returned no A record to compare against",
			Detail:   "doh=" + endpoint,
		}}
	}
	if !dohIP.Equal(udpIP) {
		return []finding.Finding{{
			Kind:     "dns-doh",
			Severity: finding.SeverityMedium,
			What:     "doh divergence",
			Because: fmt.Sprintf("DNS-over-HTTPS answered %s while the configured resolver answered %s for %s",
				dohIP, udpIP, host),
			Detail: "doh=" + endpoint,
		}}
	}
	return []finding.Finding{{
		Kind:     "dns-doh",
		Severity: finding.SeverityInfo,
		What:     "doh_a=" + dohIP.String(),
		Because:  "DNS-over-HTTPS and the configured resolver agree on the A record",
		Detail:   "doh=" + endpoint,
	}}
}

// dohLookupA performs an RFC 8484 JSON DNS-over-HTTPS query against endpoint.
func dohLookupA(endpoint, host string, timeout time.Duration) (net.IP, error) {
	client := &http.Client{Timeout: maxDuration(timeout, 3*time.Second)}
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}
	req, err := http.NewRequest(http.MethodGet,
		endpoint+sep+"name="+host+"&type=A", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/dns-json")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh server returned status %d", res.StatusCode)
	}
	var body struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return nil, err
	}
	for _, a := range body.Answer {
		if a.Type != int(dns.TypeA) {
			continue
		}
		if ip := net.ParseIP(a.Data); ip != nil {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("no A answer for %s over doh", host)
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// discoveryWordlist is the built-in name list used by FR-D14. It stays short
// so an opt-in run remains bounded.
var discoveryWordlist = []string{
	"www", "mail", "webmail", "smtp", "mx", "imap", "pop", "ftp", "api", "app",
	"admin", "portal", "vpn", "remote", "dev", "test", "stage", "staging",
	"prod", "demo", "blog", "shop", "store", "support", "help", "docs",
	"status", "monitor", "git", "ci", "jenkins", "cdn", "static", "assets",
	"media", "images", "db", "sql", "backup", "intranet", "internal",
}

// loadWordlist reads an operator-supplied name list (FR-D14): one name or
// label per line, with blank lines and # comments ignored. An empty path means
// "use the built-in list".
func loadWordlist(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		names = append(names, line)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("wordlist %s contains no names", path)
	}
	return names, nil
}

// discoveryFindings is FR-D14/FR-D15: names found from a wordlist and, when
// enabled, from Certificate Transparency logs. Only names under the
// operator-supplied domain are queried (FR-S8).
func discoveryFindings(ctx Context, host string, timeout time.Duration) []finding.Finding {
	if !ctx.DiscoverWordlist && !ctx.DiscoverCT {
		return nil
	}
	found := map[string]bool{}
	var mu sync.Mutex

	if ctx.DiscoverWordlist {
		labels := discoveryWordlist
		if ctx.WordlistPath != "" {
			loaded, err := loadWordlist(ctx.WordlistPath)
			if err != nil {
				return []finding.Finding{{
					Kind:     "dns-subdomain",
					Severity: finding.SeverityLow,
					What:     "wordlist unreadable",
					Because:  "the operator-supplied wordlist could not be read, so no names were probed from it",
					Detail:   err.Error(),
				}}
			}
			labels = loaded
		}
		workers := 8
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		for _, label := range labels {
			// A line containing a dot is a complete name; otherwise it is a
			// label under the target domain.
			name := label
			if !strings.Contains(label, ".") {
				name = label + "." + host
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(name string) {
				defer wg.Done()
				defer func() { <-sem }()
				if ip, err := LookupA(ctx, name, timeout); err == nil && ip != nil {
					mu.Lock()
					found[name] = true
					mu.Unlock()
				}
			}(name)
		}
		wg.Wait()
	}

	var ctErr string
	if ctx.DiscoverCT {
		names, err := ctLogNames(host)
		if err != nil {
			ctErr = err.Error()
		} else {
			for _, n := range names {
				if strings.HasSuffix(n, "."+host) {
					mu.Lock()
					found[n] = true
					mu.Unlock()
				}
			}
		}
	}

	var list []string
	for n := range found {
		list = append(list, n)
	}
	sort.Strings(list)

	detail := strings.Join(list, "\n")
	if len(list) > 40 {
		detail = strings.Join(list[:40], "\n") + fmt.Sprintf("\n… and %d more", len(list)-40)
	}
	if ctErr != "" {
		detail += "\nct_log_error=" + ctErr
	}
	sources := strings.Join(discoverySources(ctx), "+")
	if len(list) == 0 {
		return []finding.Finding{{
			Kind:     "dns-subdomain",
			Severity: finding.SeverityInfo,
			What:     "no subdomains found",
			Because:  "the enabled discovery sources (" + sources + ") found no additional names for " + host,
			Detail:   detail,
		}}
	}
	return []finding.Finding{{
		Kind:     "dns-subdomain",
		Severity: finding.SeverityInfo,
		What:     fmt.Sprintf("subdomains=%d", len(list)),
		Because: fmt.Sprintf("discovery sources (%s) found %d additional names, which widens the audit surface beyond the names typed in",
			sources, len(list)),
		Detail: detail,
	}}
}

func discoverySources(ctx Context) []string {
	var s []string
	if ctx.DiscoverWordlist {
		s = append(s, "wordlist")
	}
	if ctx.DiscoverCT {
		s = append(s, "ct-log")
	}
	return s
}

// ctLogNames asks crt.sh for names that appear in Certificate Transparency
// logs for a domain (FR-D15).
func ctLogNames(host string) ([]string, error) {
	url := "https://crt.sh/?q=%25." + host + "&output=json"
	return ctLogQuery(url, ctLogAttempts, time.Sleep)
}

// ctLogAttempts is how many times a rate-limited CT query is retried.
const ctLogAttempts = 3

// ctLogQuery fetches and parses a CT-log JSON response, retrying when the log
// rate-limits us. crt.sh answers 429 readily, and losing discovery to one
// throttled request would report an empty result that is not true. The sleep
// function is injected so tests can run without waiting.
func ctLogQuery(url string, attempts int, sleep func(time.Duration)) ([]string, error) {
	if attempts < 1 {
		attempts = 1
	}
	client := &http.Client{Timeout: 20 * time.Second}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			sleep(time.Duration(1<<uint(attempt-1)) * time.Second)
		}
		res, err := client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		if res.StatusCode != http.StatusOK {
			retryable := res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500
			lastErr = fmt.Errorf("ct log returned status %d", res.StatusCode)
			res.Body.Close()
			if retryable {
				continue
			}
			return nil, lastErr
		}
		names, err := parseCTNames(res.Body)
		res.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return names, nil
	}
	return nil, lastErr
}

// parseCTNames extracts the unique names from a crt.sh JSON response,
// stripping wildcard prefixes.
func parseCTNames(body io.Reader) ([]string, error) {
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(body).Decode(&entries); err != nil {
		return nil, err
	}
	unique := map[string]bool{}
	for _, e := range entries {
		for _, line := range strings.Split(e.NameValue, "\n") {
			name := strings.TrimSpace(strings.ToLower(line))
			name = strings.TrimPrefix(name, "*.")
			if name == "" {
				continue
			}
			unique[name] = true
		}
	}
	var out []string
	for n := range unique {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// zoneTransferFindings is FR-D16: an AXFR attempt against each authoritative
// server, reported as a leak when it succeeds.
func zoneTransferFindings(ctx Context, host string, timeout time.Duration) []finding.Finding {
	if !ctx.ZoneTransfer {
		return nil
	}
	nsRRs, err := Lookup(ctx, host, dns.TypeNS)
	if err != nil || len(nsRRs) == 0 {
		return []finding.Finding{{
			Kind:     "dns-zone-transfer",
			Severity: finding.SeverityInfo,
			What:     "no nameserver to try",
			Because:  "no NS records were available, so no zone transfer could be attempted",
		}}
	}
	var leaked, refused []string
	for _, rr := range nsRRs {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		name := strings.TrimSuffix(ns.Ns, ".")
		ip, err := LookupA(ctx, name, timeout)
		if err != nil || ip == nil {
			continue
		}
		records, err := tryAXFR(host, net.JoinHostPort(ip.String(), "53"), timeout)
		if err != nil {
			refused = append(refused, fmt.Sprintf("%s (%s): %v", name, ip, err))
			continue
		}
		if records > 0 {
			leaked = append(leaked, fmt.Sprintf("%s (%s): %d records", name, ip, records))
		}
	}
	if len(leaked) > 0 {
		return []finding.Finding{{
			Kind:     "dns-zone-transfer",
			Severity: finding.SeverityCritical,
			What:     "zone transfer allowed",
			Because:  "an unauthorised zone transfer returned records, exposing every name in the zone",
			Detail:   strings.Join(leaked, "\n"),
		}}
	}
	return []finding.Finding{{
		Kind:     "dns-zone-transfer",
		Severity: finding.SeverityInfo,
		What:     "zone transfer refused",
		Because:  "every nameserver refused the zone transfer, which is the expected configuration",
		Detail:   strings.Join(refused, "\n"),
	}}
}

// tryAXFR performs one AXFR and returns how many records came back.
func tryAXFR(zone, server string, timeout time.Duration) (int, error) {
	tr := &dns.Transfer{DialTimeout: timeout, ReadTimeout: timeout}
	msg := new(dns.Msg)
	msg.SetAxfr(dns.Fqdn(zone))
	ch, err := tr.In(msg, server)
	if err != nil {
		return 0, err
	}
	count := 0
	for env := range ch {
		if env.Error != nil {
			if count > 0 {
				return count, nil
			}
			return 0, env.Error
		}
		count += len(env.RR)
	}
	return count, nil
}
