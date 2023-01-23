package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"sync"

	"github.com/miekg/dns"
)

type DNSForwarder struct {
	Addr        string
	TLSConfig   *tls.Config
	TLSConnPool []*dns.Conn
	Mutex       sync.Mutex
	Closed      bool
}

func (d *DNSForwarder) Address() string {
	if d.TLSConfig != nil {
		return "tls://" + d.Addr
	}
	return d.Addr
}

func (d *DNSForwarder) Forward(req *dns.Msg) *dns.Msg {
	if d.Closed {
		return nil
	}

	reqOpt := req.IsEdns0()
	if reqOpt == nil {
		req.SetEdns0(uint16(UDPBufferSize), false)
	} else {
		reqOpt.SetUDPSize(uint16(UDPBufferSize))
	}

	var resp *dns.Msg
	var err error
	client := &dns.Client{Timeout: Timeout}

	if d.TLSConfig == nil {
		resp, _, err = client.Exchange(req, d.Addr)
		if err == nil && resp.Truncated {
			client.Net = "tcp"
			resp, _, err = client.Exchange(req, d.Addr)
		}
	} else {
		var conn *dns.Conn
		d.Mutex.Lock()
		if l := len(d.TLSConnPool); l != 0 {
			conn = d.TLSConnPool[l-1]
			d.TLSConnPool = d.TLSConnPool[:l-1]
		}
		d.Mutex.Unlock()

		if conn != nil {
			resp, _, err = client.ExchangeWithConn(req, conn)
			if err != nil {
				conn.Close()
				conn = nil
			}
		}

		if conn == nil {
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
			conn, err = client.Dial(d.Addr)
			if err == nil {
				resp, _, err = client.ExchangeWithConn(req, conn)
				if err != nil {
					conn.Close()
				}
			}
		}

		if err == nil {
			d.Mutex.Lock()
			d.TLSConnPool = append(d.TLSConnPool, conn)
			d.Mutex.Unlock()
		}
	}

	if err != nil {
		if Verbose {
			log.Printf("[DNSForwarder] Exchange error: %v", err)
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

func (d *DNSForwarder) Close() {
	d.Mutex.Lock()
	d.Closed = true
	for _, conn := range d.TLSConnPool {
		conn.Close()
	}
	d.TLSConnPool = nil
	d.Mutex.Unlock()
}
