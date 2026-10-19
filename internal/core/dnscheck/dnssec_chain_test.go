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

// chainFixture serves a synthetic DNSSEC hierarchy: the root, a signed TLD and
// a signed second level, so chain building can be tested without the internet.
type chainFixture struct {
	addr string
	// anchor is the DS the validator must start from (the root key's DS).
	anchor *dns.DS
	// brokenDS makes the TLD's DS signature unverifiable.
	brokenDS bool
	// unsignedTLD makes the TLD delegation unsigned (no DS at "test").
	unsignedTLD bool
}

func newChainFixture(t *testing.T) *chainFixture {
	t.Helper()

	type zone struct {
		name string
		key  *dns.DNSKEY
		priv crypto.Signer
		sig  *dns.RRSIG
	}
	build := func(name string, flags uint16) zone {
		key := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
			Flags:     flags,
			Protocol:  3,
			Algorithm: dns.RSASHA256,
		}
		priv, err := key.Generate(1024)
		if err != nil {
			t.Fatalf("generate key for %s: %v", name, err)
		}
		signer, ok := priv.(crypto.Signer)
		if !ok {
			t.Fatalf("key for %s is not a signer", name)
		}
		sig := &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
			TypeCovered: dns.TypeDNSKEY,
			Algorithm:   key.Algorithm,
			KeyTag:      key.KeyTag(),
			SignerName:  name,
			Labels:      uint8(dns.CountLabel(name)),
			OrigTtl:     300,
			Expiration:  uint32(time.Now().Add(time.Hour).Unix()),
			Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		}
		if err := sig.Sign(signer, []dns.RR{key}); err != nil {
			t.Fatalf("sign %s DNSKEY: %v", name, err)
		}
		return zone{name: name, key: key, priv: signer, sig: sig}
	}

	root := build(".", 257)
	tld := build("test.", 257)
	second := build("signed.test.", 257)

	answers := map[string][]dns.RR{}
	add := func(name string, rrs ...dns.RR) { answers[name] = append(answers[name], rrs...) }

	add("./DNSKEY", root.key, root.sig)
	add("test./DNSKEY", tld.key, tld.sig)
	add("signed.test./DNSKEY", second.key, second.sig)

	// The root signs the TLD's DS; the TLD signs the second level's DS.
	tldDS := tld.key.ToDS(dns.SHA256)
	secondDS := second.key.ToDS(dns.SHA256)

	// Sign the DS RRsets with the respective zone keys.
	sign := func(zoneKey *dns.DNSKEY, priv crypto.Signer, signerName string, rrset []dns.RR) *dns.RRSIG {
		sig := &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: rrset[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
			TypeCovered: dns.TypeDS,
			Algorithm:   zoneKey.Algorithm,
			KeyTag:      zoneKey.KeyTag(),
			SignerName:  signerName,
			Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
			OrigTtl:     300,
			Expiration:  uint32(time.Now().Add(time.Hour).Unix()),
			Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		}
		if err := sig.Sign(priv, rrset); err != nil {
			t.Fatalf("sign DS for %s: %v", rrset[0].Header().Name, err)
		}
		return sig
	}

	fx := &chainFixture{anchor: root.key.ToDS(dns.SHA256)}
	add("test./DS", tldDS, sign(root.key, root.priv, ".", []dns.RR{tldDS}))
	add("signed.test./DS", secondDS, sign(tld.key, tld.priv, "test.", []dns.RR{secondDS}))

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		key := q.Name + "/" + dns.TypeToString[q.Qtype]
		if fx.brokenDS && q.Name == "test." && q.Qtype == dns.TypeDS {
			// A signed parent that publishes an unsigned DS: present but
			// unverifiable, which is bogus rather than insecure.
			for _, rr := range answers["test./DS"] {
				if rr.Header().Rrtype == dns.TypeDS {
					m.Answer = append(m.Answer, rr)
				}
			}
			_ = w.WriteMsg(m)
			return
		}
		if fx.unsignedTLD && q.Name == "test." && q.Qtype == dns.TypeDS {
			_ = w.WriteMsg(m) // NOERROR, no DS
			return
		}
		if rrs, ok := answers[key]; ok {
			m.Answer = append(m.Answer, rrs...)
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

func TestDNSSECChainValidatesToRootAnchor(t *testing.T) {
	// FR-D3 done properly: DS digests and RRSIGs are checked level by level
	// from the root anchor down to the target zone.
	fx := newChainFixture(t)
	restore := setRootTrustAnchor(fx.anchor)
	defer restore()

	got := dnssecChainFinding(Context{CustomResolver: fx.addr, Timeout: 2 * time.Second}, "signed.test", 2*time.Second)
	if got.What != "dnssec validated" {
		t.Fatalf("signed hierarchy should validate: %+v", got)
	}
	if got.Severity != finding.SeverityInfo {
		t.Errorf("validated chain severity = %v, want Info", got.Severity)
	}
	for _, zone := range []string{".", "test.", "signed.test."} {
		if !strings.Contains(got.Detail, "validated="+zone) {
			t.Errorf("detail should list the validated level %s: %q", zone, got.Detail)
		}
	}
}

func TestDNSSECChainStopsAtAnUnsignedDelegation(t *testing.T) {
	// An unsigned delegation is insecure, not bogus: validation ends there and
	// the result says so rather than claiming the whole path.
	fx := newChainFixture(t)
	fx.unsignedTLD = true
	restore := setRootTrustAnchor(fx.anchor)
	defer restore()

	got := dnssecChainFinding(Context{CustomResolver: fx.addr, Timeout: 2 * time.Second}, "signed.test", 2*time.Second)
	if got.What != "dnssec insecure" {
		t.Fatalf("unsigned delegation should be insecure: %+v", got)
	}
	if !strings.Contains(got.Because, "test.") {
		t.Errorf("reason should name the unsigned delegation: %q", got.Because)
	}
	if !strings.Contains(got.Detail, "validated=.") {
		t.Errorf("the root must be reported as validated: %q", got.Detail)
	}
}

func TestDNSSECChainReportsBogusOnBrokenSignature(t *testing.T) {
	// A DS that cannot be verified against the parent's key set is bogus and
	// must be High, naming the level that failed.
	fx := newChainFixture(t)
	fx.brokenDS = true
	restore := setRootTrustAnchor(fx.anchor)
	defer restore()

	got := dnssecChainFinding(Context{CustomResolver: fx.addr, Timeout: 2 * time.Second}, "signed.test", 2*time.Second)
	if got.What != "dnssec bogus" || got.Severity != finding.SeverityHigh {
		t.Fatalf("unverifiable DS must be bogus High: %+v", got)
	}
	if !strings.Contains(got.Detail, "test.") {
		t.Errorf("bogus detail should name the failing level: %q", got.Detail)
	}
}

func TestDNSSECChainDefaultsToRealRootAnchor(t *testing.T) {
	// The shipped anchor must be the published root KSK-2017 DS.
	anchor := rootTrustAnchor()
	if anchor == nil {
		t.Fatal("no default trust anchor configured")
	}
	if anchor.KeyTag != 20326 || anchor.Algorithm != dns.RSASHA256 || anchor.DigestType != dns.SHA256 {
		t.Errorf("unexpected default anchor: tag=%d alg=%d digest=%d", anchor.KeyTag, anchor.Algorithm, anchor.DigestType)
	}
	if !strings.EqualFold(anchor.Digest, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D") {
		t.Errorf("anchor digest = %s, want the IANA root KSK-2017 digest", anchor.Digest)
	}
}
