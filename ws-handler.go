package main

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/miekg/dns"
)

type WebSocketHandler struct {
	Upgrader  *websocket.Upgrader
	Semaphore chan bool
}

func newWebSocketHandler() *WebSocketHandler {
	return &WebSocketHandler{
		Upgrader: &websocket.Upgrader{
			HandshakeTimeout: Timeout,
			ReadBufferSize:   int(WSBufferSize),
			WriteBufferSize:  int(WSBufferSize),
			CheckOrigin:      func(_ *http.Request) bool { return true },
		},
		Semaphore: make(chan bool, MaxWebSockets),
	}
}

func (h *WebSocketHandler) ServeHTTP(hrw http.ResponseWriter, hr *http.Request) {
	var remote string
	if TLSCertFile == "" || TLSKeyFile == "" {
		remote = hr.Header.Get("X-Real-IP")
	}
	if remote == "" {
		remote = hr.RemoteAddr
	}

	if !websocket.IsWebSocketUpgrade(hr) {
		http.Error(hrw, "Bad Request: Not a WebSocket upgrade", http.StatusBadRequest)
		return
	}

	select {
	case h.Semaphore <- true:
		defer func() { <-h.Semaphore }()

	default:
		if Verbose {
			log.Printf("[WebSocket] Denied for %v (Maximum WebSockets reached)", remote)
		}
		http.Error(hrw, "Service Unavailable: Too busy, try again later", http.StatusServiceUnavailable)
		return
	}

	conn, err := h.Upgrader.Upgrade(hrw, hr, nil)
	if err != nil {
		if Verbose {
			log.Printf("[WebSocket] Upgrade error for %v: %v", remote, err)
		}
		return
	}
	conn.SetReadLimit(WebSocketReadLimit)

	if Verbose {
		log.Printf("[WebSocket] Accepted connection from %v", remote)
	}

	var routines sync.WaitGroup
	dnsResponses := make(chan *dns.Msg) // not buffered

	routines.Add(1)
	go func() {
		if Verbose {
			log.Printf("[WebSocket] Starting write loop for %v", remote)
		}
		defer func() {
			if Verbose {
				log.Printf("[WebSocket] Exiting write loop for %v", remote)
			}
			routines.Done()
		}()
		for dnsResp := range dnsResponses {
			dnsRespBytes, err := dnsResp.Pack()
			if err != nil {
				log.Printf("[WebSocket] Pack error for %v (query %v): %v", remote, dnsResp.Id, err)
				continue
			}
			err = conn.WriteMessage(websocket.BinaryMessage, dnsRespBytes)
			if err != nil {
				if Verbose {
					log.Printf("[WebSocket] WriteMessage error for %v (query %v): %v", remote, dnsResp.Id, err)
				}
			}
		}
	}()

	requestsSemaphore := make(chan bool, RequestsPerWebSocket)
	for {
		messageType, messageBytes, err := conn.ReadMessage()
		if err != nil {
			if Verbose {
				log.Printf("[WebSocket] ReadMessage error for %v: %v", remote, err)
			}
			break
		}

		var dnsReq *dns.Msg
		if messageType == websocket.BinaryMessage {
			dnsReq = new(dns.Msg)
			err = dnsReq.Unpack(messageBytes)
			if err != nil {
				dnsReq = nil
			}
		}
		if dnsReq == nil {
			if Verbose {
				log.Printf("[WebSocket] Invalid message received from %v, closing", remote)
			}
			messageBytes = websocket.FormatCloseMessage(websocket.CloseUnsupportedData, "")
			err = conn.WriteControl(websocket.CloseMessage, messageBytes, time.Now().Add(Timeout))
			if err != nil {
				if Verbose {
					log.Printf("[WebSocket] WriteControl error for %v: %v", remote, err)
				}
			}
			break
		}

		// validation similar to acceptDNS()
		if dnsReq.Response {
			continue
		}
		if dnsReq.Opcode != dns.OpcodeQuery {
			dnsResponses <- new(dns.Msg).SetRcode(dnsReq, dns.RcodeNotImplemented)
			continue
		}
		if len(dnsReq.Question) != 1 || len(dnsReq.Answer) != 0 || len(dnsReq.Ns) != 0 || len(dnsReq.Extra) > 1 {
			dnsResponses <- new(dns.Msg).SetRcode(dnsReq, dns.RcodeFormatError)
			continue
		}
		if len(dnsReq.Extra) != 0 {
			if opt := dnsReq.IsEdns0(); opt == nil {
				dnsResponses <- new(dns.Msg).SetRcode(dnsReq, dns.RcodeFormatError)
				continue
			} else if opt.Version() != 0 {
				dnsResponses <- new(dns.Msg).SetRcode(dnsReq, dns.RcodeBadVers).SetEdns0(uint16(UDPBufferSize), false)
				continue
			}
		}

		select {
		case requestsSemaphore <- true:
			routines.Add(1)
			go func() {
				defer func() {
					<-requestsSemaphore
					routines.Done()
				}()
				dnsResp := Upstream.Forward(dnsReq)
				if dnsResp != nil {
					dnsResponses <- dnsResp
				}
			}()

		default:
			if Verbose {
				log.Printf("[WebSocket] Maximum open requests reached for %v, refusing query %v", remote, dnsReq.Id)
			}
			dnsResp := new(dns.Msg).SetRcode(dnsReq, dns.RcodeRefused)
			if dnsReqOpt := dnsReq.IsEdns0(); dnsReqOpt != nil {
				dnsRespOpt := dnsResp.SetEdns0(uint16(UDPBufferSize), dnsReqOpt.Do()).IsEdns0()
				dnsRespOpt.Option = append(dnsRespOpt.Option, &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeOther,
					ExtraText: "Too busy, try again later",
				})
			}
			dnsResponses <- dnsResp
		}
	}

	conn.Close()
	close(dnsResponses)
	routines.Wait()

	if Verbose {
		log.Printf("[WebSocket] Finished for %v", remote)
	}
}
