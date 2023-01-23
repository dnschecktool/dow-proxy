package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/miekg/dns"
)

type WebSocketForwarder struct {
	Addr      string
	TLSConfig *tls.Config
	Semaphore chan bool
	Waiting   map[uint16]chan *dns.Msg
	Mutex     sync.Mutex
	Routines  sync.WaitGroup
	Conn      *websocket.Conn
	Closed    bool
}

func NewWebSocketForwarder(addr string, tlsConfig *tls.Config) *WebSocketForwarder {
	return &WebSocketForwarder{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Semaphore: make(chan bool, RequestsPerWebSocket),
		Waiting:   make(map[uint16]chan *dns.Msg, RequestsPerWebSocket),
	}
}

func (ws *WebSocketForwarder) Address() string {
	return ws.Addr
}

func (ws *WebSocketForwarder) Forward(req *dns.Msg) *dns.Msg {
	if ws.Closed {
		return nil
	}

	select {
	case ws.Semaphore <- true:
		defer func() { <-ws.Semaphore }()

	default:
		if Verbose {
			log.Printf("[WebSocketForwarder] Maximum open requests reached, refusing query %v", req.Id)
		}
		resp := new(dns.Msg).SetRcode(req, dns.RcodeRefused)
		if reqOpt := req.IsEdns0(); reqOpt != nil {
			respOpt := resp.SetEdns0(uint16(UDPBufferSize), reqOpt.Do()).IsEdns0()
			respOpt.Option = append(respOpt.Option, &dns.EDNS0_EDE{
				InfoCode:  dns.ExtendedErrorCodeOther,
				ExtraText: "Too busy, try again later",
			})
		}
		return resp
	}

	originalId := req.Id
	ws.Mutex.Lock()

	// make sure we have a unique id
	for {
		req.Id = dns.Id()
		if _, found := ws.Waiting[req.Id]; !found {
			break
		}
	}

	reqBytes, err := req.Pack()
	if err != nil {
		log.Printf("[WebSocketForwarder] Pack error for query %v: %v", req.Id, err)
		ws.Mutex.Unlock()
		resp := new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
		resp.Id = originalId
		return resp
	}

	respChan := make(chan *dns.Msg, 1)
	ws.Waiting[req.Id] = respChan

	if ws.Conn != nil {
		err = ws.Conn.WriteMessage(websocket.BinaryMessage, reqBytes)
		if err != nil {
			if Verbose {
				log.Printf("[WebSocketForwarder] WriteMessage error, will reopen and try again: %v", err)
			}
			ws.Conn.Close()
			ws.Conn = nil
		}
	}

	if ws.Conn == nil {
		if Verbose {
			log.Printf("[WebSocketForwarder] Opening WebSocket connection to %v", ws.Addr)
		}
		err = ws.open()
		if err != nil {
			if Verbose {
				log.Printf("[WebSocketForwarder] Open error: %v", err)
			}
		} else {
			err = ws.Conn.WriteMessage(websocket.BinaryMessage, reqBytes)
			if err != nil {
				if Verbose {
					log.Printf("[WebSocketForwarder] WriteMessage error, giving up: %v", err)
				}
				ws.Conn.Close()
				ws.Conn = nil
			}
		}
		if err != nil {
			delete(ws.Waiting, req.Id)
			ws.Mutex.Unlock()
			resp := new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
			resp.Id = originalId
			if reqOpt := req.IsEdns0(); reqOpt != nil {
				respOpt := resp.SetEdns0(uint16(UDPBufferSize), reqOpt.Do()).IsEdns0()
				respOpt.Option = append(respOpt.Option, &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeOther,
					ExtraText: "No response from upstream: " + err.Error(),
				})
			}
			return resp
		}
	}

	ws.Mutex.Unlock()

	select {
	case resp := <-respChan:
		if resp != nil {
			resp.Id = originalId
		}
		return resp

	case <-time.After(Timeout):
		if Verbose {
			log.Printf("[WebSocketForwarder] Timeout reached while waiting for response for query %v (%v)", req.Id, originalId)
		}
		ws.Mutex.Lock()
		delete(ws.Waiting, req.Id)
		ws.Mutex.Unlock()
		resp := new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
		resp.Id = originalId
		if reqOpt := req.IsEdns0(); reqOpt != nil {
			respOpt := resp.SetEdns0(uint16(UDPBufferSize), reqOpt.Do()).IsEdns0()
			respOpt.Option = append(respOpt.Option, &dns.EDNS0_EDE{
				InfoCode:  dns.ExtendedErrorCodeOther,
				ExtraText: "No response from upstream: timeout",
			})
		}
		return resp
	}
}

func (ws *WebSocketForwarder) Close() {
	ws.Mutex.Lock()
	ws.Closed = true
	if ws.Conn != nil {
		if Verbose {
			log.Print("[WebSocketForwarder] Sending close message")
		}
		message := websocket.FormatCloseMessage(websocket.CloseGoingAway, "")
		err := ws.Conn.WriteControl(websocket.CloseMessage, message, time.Now().Add(Timeout))
		if err != nil {
			if Verbose {
				log.Printf("[WebSocketForwarder] WriteControl error: %v", err)
			}
		}
		ws.Conn.Close()
		ws.Conn = nil
	}
	ws.Mutex.Unlock()
	ws.Routines.Wait()
}

func (ws *WebSocketForwarder) open() error {
	dialer := &websocket.Dialer{
		TLSClientConfig:  ws.TLSConfig,
		HandshakeTimeout: Timeout,
		ReadBufferSize:   int(WSBufferSize),
		WriteBufferSize:  int(WSBufferSize),
	}

	if BootstrapServer != "" {
		netDialer := &net.Dialer{
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, network, BootstrapServer)
				},
			},
		}
		dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return netDialer.DialContext(ctx, network, addr)
		}
	}

	conn, _, err := dialer.Dial(ws.Addr, nil)
	if err != nil {
		return err
	}
	ws.Conn = conn

	ws.Routines.Add(1)
	go func() {
		if Verbose {
			log.Print("[WebSocketForwarder] Starting read loop")
		}
		defer func() {
			if Verbose {
				log.Print("[WebSocketForwarder] Exiting read loop")
			}
			conn.Close()
			ws.Routines.Done()
		}()
		for {
			messageType, respBytes, err := conn.ReadMessage()
			if err != nil {
				if Verbose {
					log.Printf("[WebSocketForwarder] ReadMessage error: %v", err)
				}
				break
			}
			if messageType == websocket.BinaryMessage {
				resp := new(dns.Msg)
				err = resp.Unpack(respBytes)
				if err != nil {
					if Verbose {
						log.Printf("[WebSocketForwarder] Unpack error (invalid message): %v", err)
					}
					continue
				}
				ws.Mutex.Lock()
				respChan, found := ws.Waiting[resp.Id]
				if found {
					delete(ws.Waiting, resp.Id)
				}
				ws.Mutex.Unlock()
				if !found {
					if Verbose {
						log.Printf("[WebSocketForwarder] Received response for stale query %v", resp.Id)
					}
					continue
				}
				respChan <- resp
			}
		}
	}()

	return nil
}
