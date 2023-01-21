package main

import (
	"net/url"

	"github.com/miekg/dns"
)

type Forwarder interface {
	Address() string
	Forward(*dns.Msg) *dns.Msg
	Close()
}

func NewForwarder(s string) Forwarder {
	if hostPort := getHostPort(s, 53, true, true); hostPort != "" {
		return &DNSForwarder{Addr: hostPort}
	}
	if url, err := url.Parse(s); err == nil {
		if url.String() == "tls://"+url.Host {
			return &DNSForwarder{
				Addr:      getHostPort(url.Host, 853, true, false),
				TLSConfig: getClientTLSConfig(),
			}
		}
		if url.Scheme == "ws" {
			url.Host = getHostPort(url.Host, 80, true, false)
			return NewWebSocketForwarder(url.String(), nil)
		}
		if url.Scheme == "wss" {
			url.Host = getHostPort(url.Host, 443, true, false)
			return NewWebSocketForwarder(url.String(), getClientTLSConfig())
		}
	}
	return nil
}
