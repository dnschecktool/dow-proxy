package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"

	"github.com/miekg/dns"
)

type DNSForwarder struct {
	Addr      string
	TLSConfig *tls.Config
}

func (d *DNSForwarder) Address() string {
	if d.TLSConfig != nil {
		return "tls://" + d.Addr
	}
	return d.Addr
}

func (d *DNSForwarder) Forward(req *dns.Msg) *dns.Msg {
	reqOpt := req.IsEdns0()

	if reqOpt == nil {
		req.SetEdns0(uint16(UDPBufferSize), false)
	} else {
		reqOpt.SetUDPSize(uint16(UDPBufferSize))
	}

	client := &dns.Client{Timeout: Timeout}
	if d.TLSConfig != nil {
		client.Net = "tcp-tls"
		client.TLSConfig = d.TLSConfig
		if BootstrapServer != "" {
			client.Dialer = &net.Dialer{
				Timeout: Timeout,
				Resolver: &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
						var d net.Dialer
						return d.DialContext(ctx, network, BootstrapServer)
					},
				},
			}
		}
	}

	resp, _, err := client.Exchange(req, d.Addr)

	if err == nil && resp.Truncated && d.TLSConfig == nil {
		client.Net = "tcp"
		resp, _, err = client.Exchange(req, d.Addr)
	}

	if err != nil {
		if Verbose {
			log.Printf("[DNS] Exchange error: %v", err)
		}
		errResp := new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
		if reqOpt != nil {
			errRespOpt := errResp.SetEdns0(uint16(UDPBufferSize), reqOpt.Do()).IsEdns0()
			errRespOpt.Option = append(errRespOpt.Option, &dns.EDNS0_EDE{
				InfoCode:  dns.ExtendedErrorCodeOther,
				ExtraText: "No response from upstream: " + err.Error(),
			})
		}
		return errResp
	}

	respOpt := resp.IsEdns0()
	if respOpt != nil {
		if reqOpt == nil {
			// remove OPT from response since the original request did not have one
			for i := len(resp.Extra) - 1; i >= 0; i-- {
				if resp.Extra[i].Header().Rrtype == dns.TypeOPT {
					resp.Extra = append(resp.Extra[:i], resp.Extra[i+1:]...)
					break
				}
			}
		} else if uint16(UDPBufferSize) < respOpt.UDPSize() {
			respOpt.SetUDPSize(uint16(UDPBufferSize))
		}
	}

	return resp
}

func (d *DNSForwarder) Close() {}
