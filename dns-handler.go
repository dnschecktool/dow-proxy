package main

import (
	"github.com/miekg/dns"
)

func acceptDNS(dh dns.Header) dns.MsgAcceptAction {
	if isResponse := dh.Bits&(1<<15) != 0; isResponse {
		return dns.MsgIgnore
	}
	if opcode := int(dh.Bits>>11) & 0xF; opcode != dns.OpcodeQuery {
		return dns.MsgRejectNotImplemented
	}
	if dh.Qdcount != 1 {
		return dns.MsgReject
	}
	if dh.Ancount != 0 {
		return dns.MsgReject
	}
	if dh.Nscount != 0 {
		return dns.MsgReject
	}
	if dh.Arcount > 1 {
		return dns.MsgReject
	}
	return dns.MsgAccept
}

func handleDNS(drw dns.ResponseWriter, dr *dns.Msg) {
	opt := dr.IsEdns0()

	// the only extra record allowed is the OPT
	if opt == nil && len(dr.Extra) != 0 {
		drw.WriteMsg(new(dns.Msg).SetRcode(dr, dns.RcodeFormatError))
		return
	}

	if opt != nil && opt.Version() != 0 {
		drw.WriteMsg(new(dns.Msg).SetRcode(dr, dns.RcodeBadVers).SetEdns0(uint16(UDPBufferSize), false))
		return
	}

	var udpSize int
	if opt != nil {
		udpSize = int(opt.UDPSize())
	}

	resp := Upstream.Forward(dr)
	if resp == nil {
		return
	}

	if drw.RemoteAddr().Network() == "udp" {
		if udpSize < 512 {
			udpSize = 512
		} else if udpSize > int(UDPBufferSize) {
			udpSize = int(UDPBufferSize)
		}
		resp.Truncate(udpSize)
	}

	drw.WriteMsg(resp)
}
