package listener

import (
	"context"
	"log/slog"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/danielguillaumont/snare/internal/token"
)

// DNS is an authoritative server for one zone. Any query whose name contains a valid token
// is recorded. Every in-zone name gets the same bland answer with TTL 0, so resolvers
// don't cache it and each new lookup reaches us.
//
// Note: the source IP of a DNS hit is the *resolver's* address, not the toucher's.
type DNS struct {
	Zone     string // e.g. "cb.example.com." (trailing dot optional)
	AnswerIP net.IP // address returned for A queries
	Signer   *token.Signer
	Recorder Recorder
	Log      *slog.Logger
}

func (d *DNS) zone() string { return dns.Fqdn(strings.ToLower(d.Zone)) }

func (d *DNS) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	zone := d.zone()

	if len(req.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	if !dns.IsSubDomain(zone, name) {
		m.Rcode = dns.RcodeRefused
		m.Authoritative = false
		_ = w.WriteMsg(m)
		return
	}

	if m, ok := d.Signer.Match(name); ok {
		src := ""
		if host, _, err := net.SplitHostPort(w.RemoteAddr().String()); err == nil {
			src = host
		}
		detail := name + " " + dns.TypeToString[q.Qtype] + " (source is the resolver)"
		if err := d.Recorder.Hit(context.Background(), m, "dns", src, detail); err != nil {
			d.Log.Error("record dns hit", "err", err)
		}
	}

	hdr := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: q.Name, Rrtype: t, Class: dns.ClassINET, Ttl: 0}
	}
	switch q.Qtype {
	case dns.TypeA, dns.TypeANY:
		if ip4 := d.AnswerIP.To4(); ip4 != nil {
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr(dns.TypeA), A: ip4})
		}
	case dns.TypeSOA:
		if name == zone {
			m.Answer = append(m.Answer, d.soa())
		}
	default:
		// NOERROR with no data, plus SOA for negative caching semantics.
		m.Ns = append(m.Ns, d.soa())
	}
	_ = w.WriteMsg(m)
}

func (d *DNS) soa() dns.RR {
	z := d.zone()
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: z, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 0},
		Ns:      "ns1." + z,
		Mbox:    "hostmaster." + z,
		Serial:  2026112501,
		Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 0,
	}
}
