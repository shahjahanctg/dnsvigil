package dnscheck

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dnsvigil/dnsvigil/internal/core/finding"
	"github.com/dnsvigil/dnsvigil/internal/core/target"
	"github.com/miekg/dns"
)

// dnsFixture is an in-process UDP DNS server for offline tests (FR-D12).
type dnsFixture struct {
	server *dns.Server
	addr   string
}

func newDNSFixture(t *testing.T, anchor string) *dnsFixture {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	addr := pc.LocalAddr().String()
	pc.Close() // dns.Serve takes over the socket; re-listen below

	serveMux := dns.NewServeMux()
	serveMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch {
		case q.Qtype == dns.TypeA && q.Name == dns.Fqdn("example.test"):
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 10),
			})
		case q.Qtype == dns.TypeAAAA && q.Name == dns.Fqdn("example.test"):
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.IPv6loopback,
			})
		case q.Qtype == dns.TypeMX && q.Name == dns.Fqdn("mail.example.test"):
			m.Answer = append(m.Answer, &dns.MX{
				Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60},
				Mx:         "mx1.example.test.",
				Preference: 10,
			})
		case q.Qtype == dns.TypeSRV && q.Name == dns.Fqdn("_xmpp._tcp.example.test"):
			m.Answer = append(m.Answer, &dns.SRV{
				Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 60},
				Target:   "xmpp.example.test.",
				Port:     5222,
				Priority: 0,
				Weight:   0,
			})
		case q.Qtype == dns.TypeTXT && q.Name == dns.Fqdn("log.example.test"):
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"v=spf1 include:_spf.example.test ~all"},
			})
		case q.Qtype == dns.TypeNS && q.Name == dns.Fqdn("ns.example.test"):
			m.Answer = append(m.Answer, &dns.NS{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
				Ns:  "ns1.example.test.",
			})
		case q.Qtype == dns.TypeSOA && q.Name == dns.Fqdn("example.test"):
			m.Answer = append(m.Answer, &dns.SOA{
				Hdr:     dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
				Ns:      "ns1.example.test.",
				Mbox:    "hostmaster.example.test.",
				Serial:  2026010101,
				Refresh: 3600,
				Retry:   600,
				Expire:  604800,
				Minttl:  3600,
			})
		case q.Qtype == dns.TypePTR && q.Name == dns.Fqdn("1.0.0.127.in-addr.arpa"):
			m.Answer = append(m.Answer, &dns.PTR{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
				Ptr: "localhost",
			})
		case q.Qtype == dns.TypeCAA && q.Name == dns.Fqdn("example.test"):
			m.Answer = append(m.Answer, &dns.CAA{
				Hdr:   dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 60},
				Value: anchor,
				Tag:   "issue",
			})
		case q.Qtype == dns.TypeMX && q.Name == dns.Fqdn("example.test"):
			m.Answer = append(m.Answer, &dns.MX{
				Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60},
				Mx:         "mail.example.test.",
				Preference: 10,
			})
		case q.Qtype == dns.TypeNS && q.Name == dns.Fqdn("example.test"):
			m.Answer = append(m.Answer, &dns.NS{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
				Ns:  "ns1.example.test.",
			})
		case q.Qtype == dns.TypeSOA && q.Name == dns.Fqdn("example.test"):
			m.Answer = append(m.Answer, &dns.SOA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
				Ns:   "ns1.example.test.",
				Mbox: "hostmaster.example.test.",
			})
		case q.Qtype == dns.TypeCNAME && q.Name == dns.Fqdn("alias.example.test"):
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "example.test.",
			})
		case q.Qtype == dns.TypeTXT && q.Name == dns.Fqdn("example.test"):
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"v=spf1 include:_spf.example.test ~all"},
			})
		case q.Qtype == dns.TypeTXT && q.Name == dns.Fqdn("_dmarc.example.test"):
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"v=DMARC1; p=reject; rua=mailto:dmarc@example.test"},
			})
		case q.Qtype == dns.TypeTXT && q.Name == dns.Fqdn("_dmarc.permissive.test"):
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"v=DMARC1; p=none"},
			})
		case q.Qtype == dns.TypeTXT && q.Name == dns.Fqdn("permissive.test"):
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"v=spf1 include:_spf.example.test +all"},
			})
		case q.Qtype == dns.TypeDNSKEY && q.Name == dns.Fqdn("example.test"):
			m.Answer = append(m.Answer, &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: q.Name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 60},
				Algorithm: dns.ECDSAP256SHA256,
				Protocol:  3,
			})
		case q.Qtype == dns.TypeCNAME && q.Name == dns.Fqdn("dana.example.test"):
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "dead.example.test.",
			})
		case q.Qtype == dns.TypeA && strings.HasPrefix(q.Name, "wildcard-probe-") && strings.HasSuffix(q.Name, ".wild.test."):
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 99),
			})
		case q.Qtype == dns.TypeTXT && q.Name == dns.Fqdn("txtonly.test"):
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"plain text without spf"},
			})
		}
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{PacketConn: pc, Handler: serveMux}
	// Re-open the socket for the server.
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("re-listen udp: %v", err)
	}
	server.PacketConn = conn
	go server.ActivateAndServe()
	t.Cleanup(func() { _ = server.Shutdown() })
	return &dnsFixture{server: server, addr: addr}
}

func TestRunHonorsCustomResolver(t *testing.T) {
	fx := newDNSFixture(t, "letsencrypt.org")
	ctx := Context{
		CustomResolver: fx.addr,
		Timeout:        2 * time.Second,
		Logger:         func(...any) {},
	}

	res := Run(ctx, target.Target{Host: "example.test", Port: 443})
	if res.Error != nil {
		t.Fatalf("Run returned error: %v", res.Error)
	}

	var foundA, foundAAAA, foundCAA bool
	for _, f := range res.Findings {
		switch f.Kind {
		case "dns-a":
			foundA = true
			if f.Severity != finding.SeverityInfo || f.What != "a=192.0.2.10" {
				t.Errorf("dns-a finding = %+v", f)
			}
		case "dns-aaaa":
			foundAAAA = true
			if f.Severity != finding.SeverityInfo {
				t.Errorf("dns-aaaa finding severity: %+v", f)
			}
		case "dns-caa":
			foundCAA = true
			if f.Severity != finding.SeverityInfo || f.What != "caa=letsencrypt.org" {
				t.Errorf("dns-caa finding = %+v", f)
			}
		}
	}
	if !foundA || !foundAAAA || !foundCAA {
		t.Errorf("missing findings: foundA=%v foundAAAA=%v foundCAA=%v; all=%+v", foundA, foundAAAA, foundCAA, res.Findings)
	}
}

func TestRunMissingRecordsProduceFindings(t *testing.T) {
	// The fixture answers nothing for unknown.test; all three lookups miss.
	fx := newDNSFixture(t, "does.not.matter")
	ctx := Context{CustomResolver: fx.addr, Timeout: 2 * time.Second}

	res := Run(ctx, target.Target{Host: "unknown.test", Port: 443})
	if res.Error != nil {
		t.Fatalf("Run returned error: %v", res.Error)
	}

	// A and CAA missing must be flagged MEDIUM; AAAA missing stays INFO (normal).
	sevByKind := map[string]finding.Severity{}
	for _, f := range res.Findings {
		sevByKind[f.Kind] = f.Severity
	}
	if sevByKind["dns-a"] != finding.SeverityMedium {
		t.Errorf("missing A should be MEDIUM, got %v", sevByKind["dns-a"])
	}
	if sevByKind["dns-aaaa"] != finding.SeverityInfo {
		t.Errorf("missing AAAA should be INFO (normal), got %v", sevByKind["dns-aaaa"])
	}
	if sevByKind["dns-caa"] != finding.SeverityMedium {
		t.Errorf("missing CAA should be MEDIUM, got %v", sevByKind["dns-caa"])
	}
}

func TestLookupAWithCustomResolver(t *testing.T) {
	fx := newDNSFixture(t, "x")
	ctx := Context{CustomResolver: fx.addr, Timeout: 2 * time.Second}

	ip, err := LookupA(ctx, "example.test", 2*time.Second)
	if err != nil {
		t.Fatalf("LookupA: %v", err)
	}
	if want := net.IPv4(192, 0, 2, 10); !ip.Equal(want) {
		t.Errorf("LookupA = %v, want %v", ip, want)
	}

	if _, err := LookupA(ctx, "unknown.test", 2*time.Second); err == nil {
		t.Error("LookupA(unknown.test) should fail with an error")
	}
}

func TestLookupAAAAAndCAA(t *testing.T) {
	fx := newDNSFixture(t, "myca.example")
	ctx := Context{CustomResolver: fx.addr, Timeout: 2 * time.Second}

	ips, err := LookupAAAA(ctx, "example.test", 2*time.Second)
	if err != nil || len(ips) != 1 {
		t.Fatalf("LookupAAAA: %v, %d ips", err, len(ips))
	}
	if got := ips[0].String(); got != "::1" {
		t.Errorf("LookupAAAA = %q, want %q", got, "::1")
	}

	cas, err := LookupCAA(ctx, "example.test", 2*time.Second)
	if err != nil || len(cas) != 1 {
		t.Fatalf("LookupCAA: %v, %d records", err, len(cas))
	}
	if cas[0].Value != "myca.example" || cas[0].Tag != "issue" {
		t.Errorf("LookupCAA = %+v, want issue=myca.example", cas[0])
	}
}

func TestRunQueriesCoreRecordSet(t *testing.T) {
	// FR-D1: A, AAAA, CNAME, MX, TXT, NS, SOA (CAA) are all queried; the
	// fixture serves MX/TXT/NS/SOA for example.test, and no CNAME.
	fx := newDNSFixture(t, "anchor")
	ctx := Context{CustomResolver: fx.addr, Timeout: 2 * time.Second}

	res := Run(ctx, target.Target{Host: "example.test", Port: 443})
	if res.Error != nil {
		t.Fatalf("Run returned error: %v", res.Error)
	}

	want := []string{"dns-mx", "dns-txt", "dns-ns", "dns-soa", "dns-cname"}
	kinds := map[string]bool{}
	for _, f := range res.Findings {
		kinds[f.Kind] = true
	}
	for _, k := range want {
		if !kinds[k] {
			t.Errorf("missing FR-D1 finding kind %q; got %+v", k, res.Findings)
		}
	}

	// MX/TXT/NS/SOA facts exist → INFO; CNAME absent → INFO (normal for an apex).
	for _, f := range res.Findings {
		switch f.Kind {
		case "dns-mx", "dns-txt", "dns-ns", "dns-soa",
			"dns-cname":
			if f.Severity != finding.SeverityInfo {
				t.Errorf("%s severity = %v, want INFO", f.Kind, f.Severity)
			}
		case "dns-spf":
			if f.Severity != finding.SeverityInfo || f.What != "spf present" {
				t.Errorf("spf finding = %+v", f)
			}
		case "dns-dmarc":
			if f.Severity != finding.SeverityInfo || f.What != "dmarc present" {
				t.Errorf("dmarc finding = %+v", f)
			}
		}
	}
	if !strings.Contains(res.Findings[0].What, "a=") && !kinds["dns-a"] {
		t.Error("A-record finding lost after FR-D1 additions")
	}
}

func TestSPFAndDMARCWeakPoliciesFlagged(t *testing.T) {
	// FR-D4: permissive SPF flagged. FR-D5: p=none flagged as weak.
	fx := newDNSFixture(t, "anchor")
	ctx := Context{CustomResolver: fx.addr, Timeout: 2 * time.Second}

	res := Run(ctx, target.Target{Host: "permissive.test", Port: 443})
	sevByWhat := map[string]finding.Finding{}
	for _, f := range res.Findings {
		sevByWhat[f.What] = f
	}

	permissive, ok := sevByWhat["permissive SPF policy"]
	if !ok {
		t.Fatalf("permissive SPF not flagged; got %+v", res.Findings)
	}
	if permissive.Severity != finding.SeverityHigh {
		t.Errorf("permissive SPF severity = %v, want High", permissive.Severity)
	}

	weak, ok := sevByWhat["weak DMARC policy (p=none)"]
	if !ok {
		t.Fatalf("weak DMARC not flagged; got %+v", res.Findings)
	}
	if weak.Severity != finding.SeverityMedium {
		t.Errorf("weak DMARC severity = %v, want Medium", weak.Severity)
	}
}

func TestMissingMailHygieneIsFlagged(t *testing.T) {
	// FR-D4/D5: missing SPF/DMARC are always results, never silent skips.
	fx := newDNSFixture(t, "anchor")
	ctx := Context{CustomResolver: fx.addr, Timeout: 2 * time.Second}

	res := Run(ctx, target.Target{Host: "unknown.test", Port: 443})
	kinds := map[string]finding.Finding{}
	for _, f := range res.Findings {
		kinds[f.What] = f
	}
	spf, ok := kinds["no SPF record"]
	if !ok {
		t.Fatalf("missing SPF not recorded; got %+v", res.Findings)
	}
	if spf.Severity != finding.SeverityMedium {
		t.Errorf("missing SPF severity = %v, want Medium", spf.Severity)
	}
	if _, ok := kinds["no DMARC record"]; !ok {
		t.Errorf("missing DMARC not recorded: %+v", res.Findings)
	}
}

func TestLookupMXTXTNSSOACNAME(t *testing.T) {
	fx := newDNSFixture(t, "anchor")
	ctx := Context{CustomResolver: fx.addr}

	mxs, err := LookupMX(ctx, "example.test", 2*time.Second)
	if err != nil || len(mxs) != 1 || mxs[0].Mx != "mail.example.test." {
		t.Errorf("LookupMX = %v, %v", mxs, err)
	}

	txts, err := LookupTXT(ctx, "example.test", 2*time.Second)
	if err != nil || len(txts) != 1 || !strings.HasPrefix(txts[0], "v=spf1") {
		t.Errorf("LookupTXT = %v, %v", txts, err)
	}

	nss, err := LookupNS(ctx, "example.test", 2*time.Second)
	if err != nil || len(nss) != 1 || nss[0] != "ns1.example.test." {
		t.Errorf("LookupNS = %v, %v", nss, err)
	}

	soa, err := LookupSOA(ctx, "example.test", 2*time.Second)
	if err != nil || soa.Ns != "ns1.example.test." {
		t.Errorf("LookupSOA = %v, %v", soa, err)
	}

	cn, err := LookupCNAME(ctx, "alias.example.test", 2*time.Second)
	if err != nil || cn != "example.test." {
		t.Errorf("LookupCNAME = %q, %v", cn, err)
	}
}

func TestTier2WildcardDivergenceDangling(t *testing.T) {
	fx := newDNSFixture(t, "anchor")
	// FR-D10: the fixture answers A for wildcard-probe-* names under wild.test.
	probeHost := "wild.test"
	ctx := Context{CustomResolver: fx.addr, Timeout: 2 * time.Second}

	wf := wildcardDetectionFinding(ctx, probeHost, 2*time.Second)
	if wf.What != "wildcard dns" || wf.Severity != finding.SeverityMedium {
		t.Errorf("wildcard detection = %+v", wf)
	}

	clean := wildcardDetectionFinding(ctx, "example.test", 2*time.Second)
	if clean.What != "no wildcard" {
		t.Errorf("ordinary host should not be flagged wildcard: %+v", clean)
	}

	// FR-D9: alias.example.test → example.test (has an A) is fine;
	// dana.example.test → dead.example.test (no records) is Critical.
	if d := danglingCNAMEFinding(ctx, "alias.example.test", 2*time.Second); d.Kind != "" {
		t.Errorf("healthy CNAME must produce no finding: %+v", d)
	}
	d := danglingCNAMEFinding(ctx, "dana.example.test", 2*time.Second)
	if d.Kind != "dns-dangling-cname" || d.Severity != finding.SeverityCritical {
		t.Errorf("dangling CNAME = %+v", d)
	}

	// FR-D3: this fixture serves no root DNSKEY, so a validator cannot start a
	// chain and must say so instead of guessing. The validated, insecure and
	// bogus paths are exercised against a synthetic hierarchy in
	// dnssec_chain_test.go.
	noRoot := dnssecChainFinding(ctx, "example.test", 2*time.Second)
	if noRoot.Kind != "dns-dnssec" || noRoot.What != "dnssec unavailable" {
		t.Errorf("without root data the chain must be reported unavailable: %+v", noRoot)
	}
	if noRoot.Severity != finding.SeverityLow || noRoot.Detail == "" {
		t.Errorf("an unavailable chain must be Low with the cause recorded: %+v", noRoot)
	}
}

func TestRunDivergenceViaSecondResolver(t *testing.T) {
	// FR-D11: agreement and divergence between two configured resolvers.
	a := newDNSFixture(t, "anchor")

	// Second resolver: same fixture first (agree), then a tiny inline UDP
	// server answering a different IP (diverge).
	secondary := func(ip net.IP) string {
		pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
		addr := pc.LocalAddr().String()
		pc.Close()
		mux := dns.NewServeMux()
		mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip,
			})
			_ = w.WriteMsg(m)
		})
		conn, _ := net.ListenPacket("udp", addr)
		srv := &dns.Server{PacketConn: conn, Handler: mux}
		go srv.ActivateAndServe()
		t.Cleanup(func() { _ = srv.Shutdown() })
		return addr
	}

	agree := Context{CustomResolver: a.addr, Timeout: 1 * time.Second, SecondResolver: a.addr}
	if d := resolverDivergenceFinding(agree, "example.test", time.Second); d.What != "resolvers agree" {
		t.Errorf("same fixture twice should agree: %+v", d)
	}

	dvg := Context{CustomResolver: a.addr, Timeout: 1 * time.Second, SecondResolver: secondary(net.IPv4(192, 0, 2, 77))}
	d := resolverDivergenceFinding(dvg, "example.test", time.Second)
	if d.What != "resolver divergence" || d.Severity != finding.SeverityMedium {
		t.Errorf("divergent resolvers must be flagged Medium: %+v", d)
	}

	noSecond := Context{CustomResolver: a.addr, Timeout: 1 * time.Second}
	if d := resolverDivergenceFinding(noSecond, "example.test", time.Second); d.Kind != "" {
		t.Errorf("no second resolver must produce no divergence finding: %+v", d)
	}
}

func TestResolverList(t *testing.T) {
	if got := (Context{CustomResolver: "127.0.0.1:5353"}).resolverList(); len(got) != 1 || got[0] != "127.0.0.1:5353" {
		t.Errorf("resolverList with custom = %v", got)
	}
	def := (Context{}).resolverList()
	if len(def) != 2 {
		t.Errorf("resolverList default should have 2 resolvers, got %v", def)
	}
}
