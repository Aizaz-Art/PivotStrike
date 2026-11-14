package server

import (
	"crypto/tls"
	"log"
	"net"
)

// Listen accepts TLS connections on laddr forever, handing each one to
// mgr.Accept at depth 0 (a fresh, first-hop agent). It never returns
// unless the listener itself is closed or fails unrecoverably — a single
// bad/aborted handshake from one agent must never take down the ability
// to accept the next one, which is why accept errors are logged and
// looped past rather than returned.
func Listen(laddr string, cert tls.Certificate, mgr *SessionManager) error {
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.NoClientCert,
	}
	ln, err := tls.Listen("tcp", laddr, tlsCfg)
	if err != nil {
		return err
	}
	log.Printf("listening for agents on %s", laddr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("listener error (retrying): %v", err)
				if ne, ok := err.(net.Error); ok && !ne.Temporary() {
					return
				}
				continue
			}
			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("recovered panic handling new agent connection from %s: %v", conn.RemoteAddr(), r)
					}
				}()
				mgr.Accept(conn, 0, "")
			}()
		}
	}()
	return nil
}
