package main

import (
	"crypto/tls"
	"net"
	"net/netip"
	"strconv"
)

func getClientTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		InsecureSkipVerify: Insecure,
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
	}
}

func getHostPort(s string, defaultPort int, requireHost bool, ipOnly bool) string {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host = s
		port = strconv.Itoa(defaultPort)
	}
	if requireHost && host == "" {
		return ""
	}
	s = net.JoinHostPort(host, port)
	if ipOnly && host != "" {
		if _, err := netip.ParseAddrPort(s); err != nil {
			return ""
		}
	}
	return s
}
