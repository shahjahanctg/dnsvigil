package dnscheck

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/soc-tool/internal/core/finding"
	"github.com/soc-tool/internal/core/target"
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
				Mx:         "mx1.example.test",
				Preference: 10,
			})
		case q.Qtype == dns.TypeSRV && q.Name == dns.Fqdn("_xmpp._tcp.example.test"):
			m.Answer = append(m.Answer, &dns.SRV{
				Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 60},
				Target:   "xmpp.example.test",
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
				Ns:  "ns1.example.test",
			})
		case q.Qtype == dns.TypeSOA && q.Name == dns.Fqdn("example.test"):
			m.Answer = append(m.Answer, &dns.SOA{
				Hdr:     dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
				Ns:      "ns1.example.test",
				Mbox:    "hostmaster.example.test",
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

func TestResolverList(t *testing.T) {
	if got := (Context{CustomResolver: "127.0.0.1:5353"}).resolverList(); len(got) != 1 || got[0] != "127.0.0.1:5353" {
		t.Errorf("resolverList with custom = %v", got)
	}
	def := (Context{}).resolverList()
	if len(def) != 2 {
		t.Errorf("resolverList default should have 2 resolvers, got %v", def)
	}
}
