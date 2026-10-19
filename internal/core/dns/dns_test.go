package dns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fixture is a minimal in-process UDP DNS server for offline tests.
func newFixture(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()

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
		case q.Qtype == dns.TypeMX && q.Name == dns.Fqdn("example.test"):
			m.Answer = append(m.Answer, &dns.MX{
				Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60},
				Mx:         "mail.example.test.",
				Preference: 10,
			})
		case q.Qtype == dns.TypeTXT && q.Name == dns.Fqdn("example.test"):
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"v=spf1 ~all"},
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
		case q.Qtype == dns.TypeCAA && q.Name == dns.Fqdn("example.test"):
			m.Answer = append(m.Answer, &dns.CAA{
				Hdr:   dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 60},
				Value: "myca.example",
				Tag:   "issue",
			})
		case q.Qtype == dns.TypeSRV && q.Name == dns.Fqdn("_svc.example.test"):
			m.Answer = append(m.Answer, &dns.SRV{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 60},
				Target: "host.example.test.",
				Port:   5222,
			})
		case q.Qtype == dns.TypePTR && q.Name == dns.Fqdn("1.0.0.127.in-addr.arpa"):
			m.Answer = append(m.Answer, &dns.PTR{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
				Ptr: "localhost.",
			})
		case q.Qtype == dns.TypeCNAME && q.Name == dns.Fqdn("alias.example.test"):
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "example.test.",
			})
		case q.Qtype == dns.TypeA && q.Name == dns.Fqdn("multi.example.test"):
			m.Answer = append(m.Answer,
				&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)},
				&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 2)},
			)
		}
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{PacketConn: pc, Handler: serveMux}
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("re-listen udp: %v", err)
	}
	server.PacketConn = conn
	go server.ActivateAndServe()
	t.Cleanup(func() { _ = server.Shutdown() })
	return addr
}

func TestLookupA(t *testing.T) {
	ctx := Context{CustomResolver: newFixture(t), Timeout: 2 * time.Second}

	ip, err := LookupA(ctx, "example.test")
	if err != nil || !ip.Equal(net.IPv4(192, 0, 2, 10)) {
		t.Errorf("LookupA = %v, %v", ip, err)
	}
	if _, err := LookupA(ctx, "missing.test"); err == nil {
		t.Error("LookupA(missing.test) should error")
	}
}

func TestLookupMXAndTXT(t *testing.T) {
	ctx := Context{CustomResolver: newFixture(t), Timeout: 2 * time.Second}

	mx, err := LookupMX(ctx, "example.test")
	if err != nil || mx.Mx != "mail.example.test." || mx.Preference != 10 {
		t.Errorf("LookupMX = %+v, %v", mx, err)
	}

	txts, err := LookupTXT(ctx, "example.test")
	if err != nil || len(txts) != 1 || txts[0] != "v=spf1 ~all" {
		t.Errorf("LookupTXT = %v, %v", txts, err)
	}
}

func TestLookupNSSOACAA(t *testing.T) {
	ctx := Context{CustomResolver: newFixture(t), Timeout: 2 * time.Second}

	nss, err := LookupNS(ctx, "example.test")
	if err != nil || len(nss) != 1 || nss[0] != "ns1.example.test." {
		t.Errorf("LookupNS = %v, %v", nss, err)
	}

	soa, err := LookupSOA(ctx, "example.test")
	if err != nil || soa.Ns != "ns1.example.test." {
		t.Errorf("LookupSOA = %+v, %v", soa, err)
	}

	cas, err := LookupCAA(ctx, "example.test")
	if err != nil || len(cas) != 1 || cas[0].Value != "myca.example" {
		t.Errorf("LookupCAA = %+v, %v", cas, err)
	}
}

func TestLookupSRVPTRCNAME(t *testing.T) {
	ctx := Context{CustomResolver: newFixture(t), Timeout: 2 * time.Second}

	srv, err := LookupSRV(ctx, "_svc.example.test")
	if err != nil || srv.Target != "host.example.test." || srv.Port != 5222 {
		t.Errorf("LookupSRV = %+v, %v", srv, err)
	}

	ptr, err := LookupPTR(ctx, "1.0.0.127.in-addr.arpa")
	if err != nil || ptr != "localhost." {
		t.Errorf("LookupPTR = %q, %v", ptr, err)
	}

	cn, err := LookupCNAMERecord(ctx, "alias.example.test")
	if err != nil || cn != "example.test." {
		t.Errorf("LookupCNAMERecord = %q, %v", cn, err)
	}
}

func TestLookupRawReturnsAllAnswers(t *testing.T) {
	ctx := Context{CustomResolver: newFixture(t), Timeout: 2 * time.Second}

	rrs, err := Lookup(ctx, "multi.example.test", dns.TypeA)
	if err != nil || len(rrs) != 2 {
		t.Errorf("Lookup multi = %d answers, %v", len(rrs), err)
	}
}
