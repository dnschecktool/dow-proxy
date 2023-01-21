package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

var (
	Verbose              bool
	ListenAddr           string
	UpstreamAddr         string
	Upstream             Forwarder
	Insecure             bool
	Server               bool
	TLSCertFile          string
	TLSKeyFile           string
	UDPBufferSize        uint
	WSBufferSize         uint
	MaxWebSockets        uint
	RequestsPerWebSocket uint
	Timeout              time.Duration
	WebSocketReadLimit   int64 = 4096
)

func main() {
	flag.BoolVar(&Verbose, "verbose", false, "Verbose output")
	flag.StringVar(&ListenAddr, "listen", "", "Listening `[IP]:port`. IP is optional, leave empty to listen on all interfaces. (default \":53\", \":80\", or \":443\" depending on server and TLS options)")
	flag.StringVar(&UpstreamAddr, "upstream", "", "Upstream DNS `server` IP address or URL")
	flag.BoolVar(&Insecure, "insecure", false, "Skip server certificate verification for upstream encrypted connections")
	flag.BoolVar(&Server, "server", false, "Listen for WebSocket connections instead of plaintext DNS. Unless a TLS certificate and key are provided, the WebSocket connections will be unencrypted.")
	flag.StringVar(&TLSCertFile, "tls-cert", "", "TLS certificate `file` path for encrypting WebSocket connections in server mode")
	flag.StringVar(&TLSKeyFile, "tls-key", "", "TLS private key `file` path for encrypting WebSocket connections in server mode")
	flag.UintVar(&UDPBufferSize, "udp-buffer", 1232, "EDNS UDP buffer size in `bytes`")
	flag.UintVar(&WSBufferSize, "ws-buffer", 512, "WebSocket read and write buffer size in `bytes`")
	flag.UintVar(&MaxWebSockets, "max-ws", 50, "Maximum `number` of WebSockets to serve simultaneously")
	flag.UintVar(&RequestsPerWebSocket, "requests-per-ws", 50, "Maximum `number` of open DNS requests per WebSocket. Additional requests will be refused.")
	flag.DurationVar(&Timeout, "timeout", 5*time.Second, "Maximum allowed time `duration` to wait for network activities")
	flag.Parse()

	if UDPBufferSize < 512 || UDPBufferSize > 4096 {
		fmt.Fprintf(flag.CommandLine.Output(), "invalid value \"%d\" for flag -udp-buffer: valid range is 512 to 4096\n", UDPBufferSize)
		flag.Usage()
		os.Exit(2)
	}

	if Timeout < time.Second {
		fmt.Fprintf(flag.CommandLine.Output(), "invalid value %q for flag -timeout: minimum is 1s\n", Timeout.String())
		flag.Usage()
		os.Exit(2)
	}

	var defaultListenPort int
	if Server {
		if TLSCertFile == "" || TLSKeyFile == "" {
			defaultListenPort = 80
		} else {
			defaultListenPort = 443
		}
	} else {
		defaultListenPort = 53
	}

	if addr := getHostPort(ListenAddr, defaultListenPort, false, true); addr == "" {
		fmt.Fprintf(flag.CommandLine.Output(), "invalid value %q for flag -listen: invalid address\n", ListenAddr)
		flag.Usage()
		os.Exit(2)
	} else {
		ListenAddr = addr
	}

	if UpstreamAddr == "" {
		fmt.Fprintln(flag.CommandLine.Output(), "flag required: -upstream")
		flag.Usage()
		os.Exit(2)
	}

	Upstream = NewForwarder(UpstreamAddr)
	if Upstream == nil {
		fmt.Fprintf(flag.CommandLine.Output(), "invalid value %q for flag -upstream: invalid address\n", UpstreamAddr)
		flag.Usage()
		os.Exit(2)
	}
	defer Upstream.Close()

	if Verbose {
		log.Printf(
			"upstream=%v, insecure=%v, udp-buffer=%v, ws-buffer=%v, max-ws=%v, requests-per-ws=%v, timeout=%v",
			Upstream.Address(),
			Insecure,
			UDPBufferSize,
			WSBufferSize,
			MaxWebSockets,
			RequestsPerWebSocket,
			Timeout.String(),
		)
	}

	if Server {
		http.Handle("/", newWebSocketHandler())

		if TLSCertFile == "" || TLSKeyFile == "" {
			go func() {
				log.Printf("Starting WebSocket listener on ws://%v", ListenAddr)
				srv := &http.Server{
					Addr:         ListenAddr,
					ReadTimeout:  Timeout,
					WriteTimeout: Timeout,
				}
				log.Fatal(srv.ListenAndServe())
			}()
		} else {
			go func() {
				log.Printf("Starting WebSocket listener on wss://%v", ListenAddr)
				srv := &http.Server{
					Addr:         ListenAddr,
					ReadTimeout:  Timeout,
					WriteTimeout: Timeout,
					TLSConfig: &tls.Config{
						MinVersion: tls.VersionTLS13,
					},
				}
				log.Fatal(srv.ListenAndServeTLS(TLSCertFile, TLSKeyFile))
			}()
		}

	} else {
		dns.HandleFunc(".", handleDNS)

		go func() {
			log.Printf("Starting DNS (udp) listener on %v", ListenAddr)
			srv := &dns.Server{
				Addr:          ListenAddr,
				Net:           "udp",
				ReadTimeout:   Timeout,
				WriteTimeout:  Timeout,
				MsgAcceptFunc: acceptDNS,
			}
			log.Fatal(srv.ListenAndServe())
		}()

		go func() {
			log.Printf("Starting DNS (tcp) listener on %v", ListenAddr)
			srv := &dns.Server{
				Addr:          ListenAddr,
				Net:           "tcp",
				ReadTimeout:   Timeout,
				WriteTimeout:  Timeout,
				MsgAcceptFunc: acceptDNS,
			}
			log.Fatal(srv.ListenAndServe())
		}()
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	log.Printf("Signal %v received, stopping", sig)
}
