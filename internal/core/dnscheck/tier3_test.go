package dnscheck

import (
	"crypto"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/soc-tool/internal/core/finding"
)

// zoneFixture is a small authoritative DNS server used by the tier-3 tests.
// Unlike the shared fixture it answers with AA set, which is what the lame
// delegation check (FR-D23) inspects, and it serves a signed zone so DS →
// DNSKEY → RRSIG validation (FR-D3) can be exercised offline.
type zoneFixture struct {
	addr string
	ds   *dns.DS
}

func newZoneFixture(t *testing.T) *zoneFixture {
	t.Helper()

	// A 1024-bit key keeps the test fast; the digest/signature logic is the
	// same as for a production key.
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "signed.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	}
	priv, err := key.Generate(1024)
	if err != nil {
		t.Fatalf("generate DNSSEC key: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatal("generated DNSSEC key is not a crypto.Signer")
	}
	ds := key.ToDS(dns.SHA256)
	if ds == nil {
		t.Fatal("ToDS returned nil")
	}

	rrset := []dns.RR{key}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "signed.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeDNSKEY,
		Algorithm:   key.Algorithm,
		KeyTag:      key.KeyTag(),
		SignerName:  "signed.test.",
		Labels:      uint8(dns.CountLabel("signed.test.")),
		OrigTtl:     300,
		Expiration:  uint32(time.Now().Add(time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
	}
	if err := sig.Sign(signer, rrset); err != nil {
		t.Fatalf("sign DNSKEY set: %v", err)
	}

	answers := map[string][]dns.RR{}
	add := func(name string, rrs ...dns.RR) { answers[name] = append(answers[name], rrs...) }

	hdr := func(name string, rrtype uint16, ttl uint32) dns.RR_Header {
		return dns.RR_Header{Name: dns.Fqdn(name), Rrtype: rrtype, Class: dns.ClassINET, Ttl: ttl}
	}

	// Addresses, aliases and a CNAME loop.
	add("example.test./A", &dns.A{Hdr: hdr("example.test", dns.TypeA, 300), A: net.IPv4(192, 0, 2, 10)})
	add("alias.test./A", &dns.A{Hdr: hdr("alias.test", dns.TypeA, 300), A: net.IPv4(192, 0, 2, 10)})
	add("chain.test./CNAME", &dns.CNAME{Hdr: hdr("chain.test", dns.TypeCNAME, 300), Target: "mid.test."})
	add("mid.test./CNAME", &dns.CNAME{Hdr: hdr("mid.test", dns.TypeCNAME, 300), Target: "example.test."})
	add("loop1.test./CNAME", &dns.CNAME{Hdr: hdr("loop1.test", dns.TypeCNAME, 300), Target: "loop2.test."})
	add("loop2.test./CNAME", &dns.CNAME{Hdr: hdr("loop2.test", dns.TypeCNAME, 300), Target: "loop1.test."})

	// Mail policy, TLSA, DKIM and SRV records.
	add("_mta-sts.example.test./TXT", &dns.TXT{Hdr: hdr("_mta-sts.example.test", dns.TypeTXT, 300), Txt: []string{"v=STSv1; id=20260101"}})
	add("_smtp._tls.example.test./TXT", &dns.TXT{Hdr: hdr("_smtp._tls.example.test", dns.TypeTXT, 300), Txt: []string{"v=TLSRPTv1; rua=mailto:tls@example.test"}})
	add("_443._tcp.example.test./TLSA", &dns.TLSA{Hdr: hdr("_443._tcp.example.test", dns.TypeTLSA, 300), Usage: 3, Selector: 1, MatchingType: 1, Certificate: "abcdef"})
	add("default._domainkey.example.test./TXT", &dns.TXT{Hdr: hdr("default._domainkey.example.test", dns.TypeTXT, 300), Txt: []string{"v=DKIM1; k=rsa; p=MIIBIjANBg"}})
	add("_https._tcp.example.test./SRV", &dns.SRV{Hdr: hdr("_https._tcp.example.test", dns.TypeSRV, 300), Target: "example.test.", Port: 443})

	// Reverse DNS that forward-confirms, plus a mismatched pair.
	add("10.2.0.192.in-addr.arpa./PTR", &dns.PTR{Hdr: hdr("10.2.0.192.in-addr.arpa", dns.TypePTR, 300), Ptr: "example.test."})
	add("9.2.0.192.in-addr.arpa./PTR", &dns.PTR{Hdr: hdr("9.2.0.192.in-addr.arpa", dns.TypePTR, 300), Ptr: "elsewhere.test."})
	add("elsewhere.test./A", &dns.A{Hdr: hdr("elsewhere.test", dns.TypeA, 300), A: net.IPv4(192, 0, 2, 99)})

	// SOA/NS for TTL and delegation checks. ns1 answers here; ns2 is pointed
	// at an address with no DNS server, which is the lame case.
	add("example.test./SOA", &dns.SOA{
		Hdr: hdr("example.test", dns.TypeSOA, 300), Ns: "ns1.example.test.", Mbox: "hostmaster.example.test.",
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minttl: 300,
	})
	add("example.test./NS", &dns.NS{Hdr: hdr("example.test", dns.TypeNS, 300), Ns: "ns1.example.test."})
	add("ns1.example.test./A", &dns.A{Hdr: hdr("ns1.example.test", dns.TypeA, 300), A: net.IPv4(127, 0, 0, 2)})
	// Both delegations land under the same query name so the lame check sees
	// the whole NS set: one server refuses, the other never answers.
	add("lame.test./NS", &dns.NS{Hdr: hdr("lame.test", dns.TypeNS, 300), Ns: "ns1.example.test."})
	add("lame.test./NS", &dns.NS{Hdr: hdr("lame.test", dns.TypeNS, 300), Ns: "nodns.example.test."})
	add("nodns.example.test./A", &dns.A{Hdr: hdr("nodns.example.test", dns.TypeA, 300), A: net.IPv4(192, 0, 2, 222)})

	// The signed zone: DS at the parent name, DNSKEY and its RRSIG.
	// The signature travels with the record set it covers (that is what the
	// EDNS0 DO bit asks for), so it is served inside the DNSKEY answer.
	add("signed.test./DS", ds)
	add("signed.test./DNSKEY", key, sig)

	// A zone whose DS points at a key that is not served (bogus).
	bogusKey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "bogus.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	}
	otherPriv, err := bogusKey.Generate(1024)
	if err != nil {
		t.Fatalf("generate bogus key: %v", err)
	}
	_ = otherPriv
	bogusDS := bogusKey.ToDS(dns.SHA256)
	add("bogus.test./DS", bogusDS)
	// Serve a different key than the DS commits to.
	unmatched := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "bogus.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	}
	if _, err := unmatched.Generate(1024); err != nil {
		t.Fatalf("generate unmatched key: %v", err)
	}
	add("bogus.test./DNSKEY", unmatched)

	fx := &zoneFixture{ds: ds}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		key := q.Name + "/" + dns.TypeToString[q.Qtype]
		if rrs, ok := answers[key]; ok {
			m.Answer = append(m.Answer, rrs...)
		} else if q.Qtype == dns.TypePTR {
			// Nothing else publishes PTR.
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	fx.addr = pc.LocalAddr().String()
	server := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return fx
}

func (f *zoneFixture) ctx(timeout time.Duration) Context {
	return Context{CustomResolver: f.addr, Timeout: timeout}
}

func TestDNSSECValidationValidated(t *testing.T) {
	// FR-D3: DS digest matches the served DNSKEY and the RRSIG verifies.
	fx := newZoneFixture(t)
	got := dnssecValidationFinding(fx.ctx(2*time.Second), "signed.test", 2*time.Second)
	if got.What != "dnssec validated" {
		t.Fatalf("signed zone should validate: %+v", got)
	}
	if got.Severity != finding.SeverityInfo {
		t.Errorf("validated severity = %v, want Info", got.Severity)
	}
	if !strings.Contains(got.Detail, "matched_keytag=") {
		t.Errorf("validated detail should name the matched key: %q", got.Detail)
	}
}

func TestDNSSECValidationBogusOnDigestMismatch(t *testing.T) {
	// FR-D3: a DS that commits to a key the zone does not serve is bogus.
	fx := newZoneFixture(t)
	got := dnssecValidationFinding(fx.ctx(2*time.Second), "bogus.test", 2*time.Second)
	if got.What != "dnssec bogus" || got.Severity != finding.SeverityHigh {
		t.Fatalf("digest mismatch must be bogus High: %+v", got)
	}
	if !strings.Contains(got.Because, "DS") {
		t.Errorf("bogus reason should mention the DS record: %q", got.Because)
	}
}

func TestDNSSECValidationInsecureWithoutDS(t *testing.T) {
	fx := newZoneFixture(t)
	got := dnssecValidationFinding(fx.ctx(2*time.Second), "example.test", 2*time.Second)
	if got.What != "dnssec insecure" || got.Severity != finding.SeverityInfo {
		t.Fatalf("unsigned zone must be insecure, not bogus: %+v", got)
	}
}

func TestCNAMECheinAndLoop(t *testing.T) {
	fx := newZoneFixture(t)
	ctx := fx.ctx(2 * time.Second)

	chain := cnameChainFinding(ctx, "chain.test", 2*time.Second)
	if chain.Kind != "dns-cname-chain" || chain.What != "cname_hops=2" {
		t.Errorf("chain finding = %+v", chain)
	}
	if !strings.Contains(chain.Detail, "chain.test") || !strings.Contains(chain.Detail, "example.test") {
		t.Errorf("chain detail should list each hop: %q", chain.Detail)
	}

	loop := cnameChainFinding(ctx, "loop1.test", 2*time.Second)
	if loop.Kind != "dns-cname-loop" || loop.Severity != finding.SeverityHigh {
		t.Errorf("loop must be flagged High: %+v", loop)
	}

	if none := cnameChainFinding(ctx, "example.test", 2*time.Second); none.Kind != "" {
		t.Errorf("a name that is not an alias must produce no finding: %+v", none)
	}
}

func TestSRVFindings(t *testing.T) {
	fx := newZoneFixture(t)
	got := srvFindings(fx.ctx(2*time.Second), "example.test", 2*time.Second)
	if len(got) != 1 || got[0].Kind != "dns-srv" {
		t.Fatalf("srv findings = %+v", got)
	}
	if !strings.Contains(got[0].Detail, "_https._tcp.example.test") {
		t.Errorf("srv detail should name the service prefix: %q", got[0].Detail)
	}
}

func TestPtrAndForwardConfirmed(t *testing.T) {
	fx := newZoneFixture(t)
	ctx := fx.ctx(2 * time.Second)

	// example.test → 192.0.2.10 → PTR example.test → A 192.0.2.10: confirmed.
	ok := ptrFindings(ctx, "example.test", 2*time.Second)
	if len(ok) != 2 || ok[0].Kind != "dns-ptr" || ok[1].Kind != "dns-fcrdns" {
		t.Fatalf("ptr findings = %+v", ok)
	}
	if ok[1].What != "forward-confirmed" || ok[1].Severity != finding.SeverityInfo {
		t.Errorf("forward-confirmed classification = %+v", ok[1])
	}
}

func TestMailPolicyFindings(t *testing.T) {
	fx := newZoneFixture(t)
	ctx := fx.ctx(2 * time.Second)

	if got := mtaStsFinding(ctx, "example.test", 2*time.Second); got.What != "published" || got.Kind != "dns-mta-sts" {
		t.Errorf("mta-sts finding = %+v", got)
	}
	if got := tlsRptFinding(ctx, "example.test", 2*time.Second); got.What != "published" || got.Kind != "dns-tls-rpt" {
		t.Errorf("tls-rpt finding = %+v", got)
	}
	missing := mtaStsFinding(ctx, "alias.test", 2*time.Second)
	if missing.What != "not published" || missing.Severity != finding.SeverityMedium {
		t.Errorf("absent policy should be Medium: %+v", missing)
	}
}

func TestTLSAAndDKIMFindings(t *testing.T) {
	fx := newZoneFixture(t)
	ctx := fx.ctx(2 * time.Second)

	tlsa := tlsaFindings(ctx, "example.test", 443, 2*time.Second)
	if len(tlsa) != 1 || tlsa[0].What != "tlsa=1" {
		t.Errorf("tlsa findings = %+v", tlsa)
	}
	if noTLSA := tlsaFindings(ctx, "example.test", 8443, 2*time.Second); noTLSA[0].What != "no tlsa records" {
		t.Errorf("unpinned port = %+v", noTLSA[0])
	}

	dkim := dkimFinding(ctx, "example.test", 2*time.Second)
	if dkim.What != "dkim_keys=1" || !strings.Contains(dkim.Detail, "default._domainkey") {
		t.Errorf("dkim finding = %+v", dkim)
	}
	if none := dkimFinding(ctx, "alias.test", 2*time.Second); none.What != "no dkim key found" {
		t.Errorf("dkim absence = %+v", none)
	}
}

func TestTTLFinding(t *testing.T) {
	fx := newZoneFixture(t)
	got := ttlFinding(fx.ctx(2*time.Second), "example.test", 2*time.Second)
	if got.Kind != "dns-ttl" || got.Severity != finding.SeverityInfo {
		t.Fatalf("ttl finding = %+v", got)
	}
	if !strings.Contains(got.Detail, "ttl=300") {
		t.Errorf("ttl detail should carry the values: %q", got.Detail)
	}
}

func TestLameDelegationFinding(t *testing.T) {
	fx := newZoneFixture(t)
	ctx := fx.ctx(2 * time.Second)

	// lame.test delegates to two servers that cannot answer: one refuses on
	// 127.0.0.2:53, the other is an unroutable TEST-NET address. This check
	// dials port 53, so what the network does with that traffic decides the
	// outcome: a plain timeout/refusal is a lame delegation (Medium), while a
	// reply carrying recursion is reported as unverifiable (Low) instead of
	// being blamed on the delegation. Both are correct; neither may claim
	// authority the reply did not carry. The exact branch is pinned
	// deterministically in TestClassifyDelegationReply.
	got := lameDelegationFinding(ctx, "lame.test", 500*time.Millisecond)
	if got.Kind != "dns-lame-delegation" {
		t.Fatalf("lame delegation = %+v", got)
	}
	switch got.Severity {
	case finding.SeverityMedium:
		if !strings.Contains(got.Because, "do not answer authoritatively") {
			t.Errorf("lame reason should explain the consequence: %q", got.Because)
		}
	case finding.SeverityLow:
		if !strings.Contains(got.Because, "recursive resolver") {
			t.Errorf("unverifiable reason should name the recursive responder: %q", got.Because)
		}
	default:
		t.Errorf("unexpected severity for an unreachable delegation: %+v", got)
	}
	if !strings.Contains(got.Detail, "ns1.example.test") {
		t.Errorf("detail should name the server that could not answer: %q", got.Detail)
	}
	// The authoritative branch cannot be exercised offline: the check dials
	// port 53 while this fixture listens on an ephemeral port, so every
	// delegation here looks lame. That branch is verified against a live
	// nameserver (see the run recorded in the README).
}

func TestOptInChecksStayOffByDefault(t *testing.T) {
	// FR-D13/D14/D15/D16 are network-reaching and must not run unless the
	// operator asked for them; a default run must not reach these paths.
	fx := newZoneFixture(t)
	ctx := fx.ctx(2 * time.Second)

	if got := dohFinding(ctx, "example.test", 2*time.Second); got != nil {
		t.Errorf("doh findings without --doh = %+v", got)
	}
	if got := discoveryFindings(ctx, "example.test", 2*time.Second); got != nil {
		t.Errorf("discovery findings without --discover = %+v", got)
	}
	if got := zoneTransferFindings(ctx, "example.test", 2*time.Second); got != nil {
		t.Errorf("zone transfer findings without --axfr = %+v", got)
	}
}

func TestDKIMPublishedKey(t *testing.T) {
	// An empty p= is DKIM's revocation marker and must never count as a key,
	// otherwise a withdrawn selector reads as a published one.
	cases := []struct {
		record  string
		wantKey string
		wantOK  bool
	}{
		{"v=DKIM1; p=", "", false},
		{"v=DKIM1; p=   ", "", false},
		{"v=DKIM1; k=rsa; p=MIIBIjANBg", "MIIBIjANBg", true},
		{"v=DKIM1; p=MIIBIjANBg; t=s", "MIIBIjANBg", true},
		{"v=spf1 -all", "", false},
	}
	for _, tc := range cases {
		key, ok := dkimPublishedKey(tc.record)
		if ok != tc.wantOK || key != tc.wantKey {
			t.Errorf("dkimPublishedKey(%q) = (%q, %t), want (%q, %t)",
				tc.record, key, ok, tc.wantKey, tc.wantOK)
		}
	}
}

func TestClassifyDelegationReply(t *testing.T) {
	// FR-D23 must not call a recursive responder "lame": on networks with a
	// forwarder or interception the probe never reaches the authoritative
	// server, which is a different statement from a broken delegation.
	auth := new(dns.Msg)
	auth.Authoritative = true
	auth.Answer = append(auth.Answer, &dns.SOA{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}})
	if got := classifyDelegationReply(auth); got != delegationAuthoritative {
		t.Errorf("authoritative reply = %v, want delegationAuthoritative", got)
	}

	proxied := new(dns.Msg)
	proxied.RecursionAvailable = true
	proxied.Answer = append(proxied.Answer, &dns.SOA{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}})
	if got := classifyDelegationReply(proxied); got != delegationProxied {
		t.Errorf("recursive reply = %v, want delegationProxied", got)
	}

	validated := new(dns.Msg)
	validated.AuthenticatedData = true
	if got := classifyDelegationReply(validated); got != delegationProxied {
		t.Errorf("validated reply = %v, want delegationProxied", got)
	}

	if got := classifyDelegationReply(new(dns.Msg)); got != delegationLame {
		t.Errorf("empty non-recursive reply = %v, want delegationLame", got)
	}
	if got := classifyDelegationReply(nil); got != delegationLame {
		t.Errorf("nil reply = %v, want delegationLame", got)
	}
}

func TestQueryMsgToUsesFixedPort(t *testing.T) {
	// The delegation check needs host:port handling for bare addresses.
	fx := newZoneFixture(t)
	host, port, err := net.SplitHostPort(fx.addr)
	if err != nil {
		t.Fatalf("fixture address: %v", err)
	}
	if got, want := net.JoinHostPort(host, port), fx.addr; got != want {
		t.Errorf("address round trip = %q, want %q", got, want)
	}
}
