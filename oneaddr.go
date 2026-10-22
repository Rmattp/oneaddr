// Package oneaddr provides a CoreDNS plugin that keeps one address per owner name.
package oneaddr

import (
	"strings"

	"github.com/miekg/dns"
)

type dedupKey struct {
	name   string
	rrtype uint16
	class  uint16
}

func makeDedupKey(rec dns.RR) dedupKey {
	hdr := rec.Header()
	return dedupKey{
		name:   strings.ToLower(hdr.Name),
		rrtype: hdr.Rrtype,
		class:  hdr.Class,
	}
}

// OneAddrResponseWriter filters duplicate A and AAAA records from responses.
type OneAddrResponseWriter struct {
	dns.ResponseWriter
}

// WriteMsg implements the dns.ResponseWriter interface.
func (r *OneAddrResponseWriter) WriteMsg(res *dns.Msg) error {
	if res.Rcode != dns.RcodeSuccess || len(res.Question) == 0 {
		return r.ResponseWriter.WriteMsg(res)
	}

	if qtype := res.Question[0].Qtype; qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return r.ResponseWriter.WriteMsg(res)
	}

	res.Answer = trimRecords(res.Answer)
	res.Extra = trimRecords(res.Extra)

	return r.ResponseWriter.WriteMsg(res)
}

func trimRecords(in []dns.RR) []dns.RR {
	seen := make(map[dedupKey]struct{}, len(in))
	out := make([]dns.RR, 0, len(in))
	for _, rec := range in {
		if rrtype := rec.Header().Rrtype; rrtype == dns.TypeA || rrtype == dns.TypeAAAA {
			key := makeDedupKey(rec)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
		}
		out = append(out, rec)
	}

	return out
}

// Write implements the dns.ResponseWriter interface.
func (r *OneAddrResponseWriter) Write(buf []byte) (int, error) {
	// Should we pack and unpack here to fiddle with the packet... Not likely.
	log.Warning("oneaddr plugin called with Write: truncated records")
	return r.ResponseWriter.Write(buf)
}
