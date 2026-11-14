package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"pivot-tool/internal/common"
)

// SOCKS5Server provides a standard SOCKS5 proxy (RFC 1928) that routes
// connections through the pivot tunnel. This is the fallback for tools
// that CANNOT use a TUN interface — e.g. a browser configured to use a
// SOCKS proxy, or any tool that supports SOCKS but would need proxychains
// to use a raw route.
//
// The TUN interface is still the primary, preferred path (it supports SYN
// scans, raw sockets, ICMP, everything), but having a SOCKS5 fallback
// means the operator is never stuck.
type SOCKS5Server struct {
	mgr      *SessionManager
	listener net.Listener
	addr     string
}

func NewSOCKS5Server(mgr *SessionManager) *SOCKS5Server {
	return &SOCKS5Server{mgr: mgr}
}

func (s *SOCKS5Server) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = ln
	s.addr = addr
	log.Printf("SOCKS5 proxy listening on %s", addr)
	go s.acceptLoop()
	return nil
}

func (s *SOCKS5Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *SOCKS5Server) handleConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("recovered panic in SOCKS5 handler: %v", r)
		}
		conn.Close()
	}()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 1. Greeting: client sends version + auth methods
	buf := make([]byte, 258)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 { // SOCKS5
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return
	}

	// 2. We accept "no auth" (0x00)
	conn.Write([]byte{0x05, 0x00})

	// 3. Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	cmd := buf[1]
	atyp := buf[3]

	var dstAddr string
	switch atyp {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		dstAddr = net.IP(buf[:4]).String()
	case 0x03: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		domLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domLen]); err != nil {
			return
		}
		dstAddr = string(buf[:domLen])
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		dstAddr = net.IP(buf[:16]).String()
	default:
		s.sendReply(conn, 0x08) // address type not supported
		return
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	dstPort := binary.BigEndian.Uint16(buf[:2])
	target := net.JoinHostPort(dstAddr, strconv.Itoa(int(dstPort)))

	if cmd != 0x01 { // only CONNECT supported
		s.sendReply(conn, 0x07) // command not supported
		return
	}

	// 4. Route through the pivot tunnel
	ip := net.ParseIP(dstAddr)
	if ip == nil {
		// Domain name — try to resolve through a connected agent
		// For now, fall back to local resolution
		resolved, err := net.ResolveIPAddr("ip", dstAddr)
		if err != nil {
			s.sendReply(conn, 0x04) // host unreachable
			return
		}
		ip = resolved.IP
	}

	sess := s.mgr.Routes.Lookup(ip)
	if sess == nil {
		s.sendReply(conn, 0x03) // network unreachable
		return
	}

	remote, err := sess.OpenDataStream(common.StreamHeader{Kind: "connect", Network: "tcp", Addr: target})
	if err != nil {
		s.sendReply(conn, 0x01) // general failure
		return
	}

	// Wait for the agent's connect ack
	if !remote.waitConnectAck(8 * time.Second) {
		remote.Close()
		s.sendReply(conn, 0x05) // connection refused
		return
	}

	// Success reply
	conn.SetDeadline(time.Time{}) // clear deadline for the data phase
	s.sendReply(conn, 0x00)

	// Splice
	splice(conn, remote)
}

func (s *SOCKS5Server) sendReply(conn net.Conn, status byte) {
	// Minimal SOCKS5 reply with 0.0.0.0:0 as bound address
	reply := []byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(reply)
}

func (s *SOCKS5Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.addr
}

var _ = fmt.Sprintf // keep fmt available
