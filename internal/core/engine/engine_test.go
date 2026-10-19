package engine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/soc-tool/internal/core/dnscheck"
	"github.com/soc-tool/internal/core/finding"
	"github.com/soc-tool/internal/core/target"
	"github.com/soc-tool/internal/core/tlscheck"
)

// dnsFixture is a minimal in-process UDP DNS server for offline engine tests.
// It answers A (127.0.0.1) and CAA for any queried name.
type dnsFixture struct {
	addr string
}

func newEngineDNSFixture(t *testing.T) *dnsFixture {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	addr := pc.LocalAddr().String()

	serveMux := dns.NewServeMux()
	serveMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(127, 0, 0, 1),
			})
		case dns.TypeCAA:
			m.Answer = append(m.Answer, &dns.CAA{
				Hdr:   dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 60},
				Value: "myca.example",
				Tag:   "issue",
			})
		}
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{PacketConn: pc, Handler: serveMux}
	go server.ActivateAndServe()
	t.Cleanup(func() { _ = server.Shutdown() })
	return &dnsFixture{addr: addr}
}

// tlsServer is an in-process TLS server for offline engine tests.
type tlsServer struct {
	ln net.Listener
}

func newTLSServer(t *testing.T, cert tls.Certificate) *tlsServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	srv := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// The connection handshake completes on first read; then drop.
				_, _ = io.Copy(io.Discard, c)
				_ = c.Close()
			}(c)
		}
	}()
	return &tlsServer{ln: ln}
}

func (s *tlsServer) port() int {
	return s.ln.Addr().(*net.TCPAddr).Port
}

// mustTestCert builds a self-signed server certificate covering 127.0.0.1
// (via IP SAN, so x509 hostname verification over the IP literal succeeds).
// It returns both the server certificate and a trust pool containing it.
func mustTestCert(t *testing.T, notBefore, notAfter time.Time) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1", Organization: []string{"soc-tool engine test"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return cert, pool
}

// TestRunIncludesDNSAndTLSFindings is the end-to-end happy path: in-process
// DNS server plus a TLS server with a trusted, valid certificate. It proves
// engine.Run no longer ignores TLSContext.
func TestRunIncludesDNSAndTLSFindings(t *testing.T) {
	fx := newEngineDNSFixture(t)
	cert, pool := mustTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv := newTLSServer(t, cert)

	res := Run(Context{
		DNSContext: dnscheck.Context{CustomResolver: fx.addr, Timeout: 2 * time.Second},
		TLSContext: tlscheck.Context{RootCAs: pool},
	}, target.Target{Host: "127.0.0.1", Port: srv.port()})

	if res.Error != nil {
		t.Fatalf("Run returned error: %v", res.Error)
	}

	kinds := map[string]bool{}
	for _, f := range res.Findings {
		kinds[f.Kind] = true
	}
	for _, k := range []string{"dns-a", "dns-caa", "tls-identity", "tls-validity", "tls-hostname", "tls-chain"} {
		if !kinds[k] {
			t.Errorf("expected finding kind %q in merged results; got %+v", k, res.Findings)
		}
	}
}

func TestRunFlagExpiredCertAsFinding(t *testing.T) {
	// FR-C6: trust failures are certificate findings, not dead errors.
	fx := newEngineDNSFixture(t)
	cert, pool := mustTestCert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	srv := newTLSServer(t, cert)

	res := Run(Context{
		DNSContext: dnscheck.Context{CustomResolver: fx.addr, Timeout: 2 * time.Second},
		TLSContext: tlscheck.Context{RootCAs: pool},
	}, target.Target{Host: "127.0.0.1", Port: srv.port()})

	if res.Error != nil {
		t.Fatalf("a trust failure must surface as a finding, not an error: %v", res.Error)
	}
	var expired *finding.Finding
	for i := range res.Findings {
		if res.Findings[i].Kind == "tls-expiry" && res.Findings[i].What == "expired" {
			expired = &res.Findings[i]
		}
	}
	if expired == nil {
		t.Fatalf("expired certificate must produce a tls-expiry finding; got %+v", res.Findings)
	}
	if expired.Severity != finding.SeverityCritical {
		t.Errorf("expired-cert severity = %v, want Critical", expired.Severity)
	}
}

func TestRunFlagUntrustedChainAsFinding(t *testing.T) {
	// FR-C6: self-signed / untrusted chains are flagged findings.
	fx := newEngineDNSFixture(t)
	cert, _ := mustTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv := newTLSServer(t, cert)

	// Fresh, empty pool: the self-signed server cert is not trusted.
	res := Run(Context{
		DNSContext: dnscheck.Context{CustomResolver: fx.addr, Timeout: 2 * time.Second},
		TLSContext: tlscheck.Context{RootCAs: x509.NewCertPool()},
	}, target.Target{Host: "127.0.0.1", Port: srv.port()})

	if res.Error != nil {
		t.Fatalf("trust failure must surface as a finding, not an error: %v", res.Error)
	}
	var untrusted *finding.Finding
	for i := range res.Findings {
		if res.Findings[i].Kind == "tls-chain" && res.Findings[i].What == "untrusted chain" {
			untrusted = &res.Findings[i]
		}
	}
	if untrusted == nil {
		t.Fatalf("self-signed chain must produce an untrusted-chain finding; got %+v", res.Findings)
	}
	if untrusted.Severity != finding.SeverityCritical {
		t.Errorf("untrusted-chain severity = %v, want Critical", untrusted.Severity)
	}
}

func TestRunWarnDaysOverride(t *testing.T) {
	// FR-C4: a configurable warning threshold changes the finding.
	fx := newEngineDNSFixture(t)
	cert, pool := mustTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(20*24*time.Hour))
	srv := newTLSServer(t, cert)

	// At the default 30-day threshold, 20 days left is inside the window;
	// at a 10-day threshold it is not.
	res := Run(Context{
		DNSContext: dnscheck.Context{CustomResolver: fx.addr, Timeout: 2 * time.Second},
		TLSContext: tlscheck.Context{RootCAs: pool, ExpiryWarnDays: 10},
	}, target.Target{Host: "127.0.0.1", Port: srv.port()})

	for _, f := range res.Findings {
		if f.Kind == "tls-expiry" && f.Severity == finding.SeverityHigh {
			t.Errorf("20 days left must not be HIGH at a 10-day threshold: %+v", f)
		}
	}
}

func TestRunUnreachableTargetProducesTLSConnectFinding(t *testing.T) {
	fx := newEngineDNSFixture(t)

	// Reserve a port, then release it so nothing listens there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	res := Run(Context{
		DNSContext: dnscheck.Context{CustomResolver: fx.addr, Timeout: 2 * time.Second},
	}, target.Target{Host: "127.0.0.1", Port: port})

	var tlsConnect *finding.Finding
	for i := range res.Findings {
		if res.Findings[i].Kind == "tls-connect" {
			tlsConnect = &res.Findings[i]
		}
	}
	if tlsConnect == nil {
		t.Fatalf("expected a tls-connect finding for an unreachable target; got %+v", res.Findings)
	}
	if tlsConnect.Severity != finding.SeverityMedium {
		t.Errorf("tls-connect severity = %v, want Medium", tlsConnect.Severity)
	}
	if tlsConnect.Because == "" {
		t.Error("tls-connect finding must carry a plain-language reason (FR-S7)")
	}
}
