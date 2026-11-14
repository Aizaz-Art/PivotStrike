package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/nicocha30/gvisor-ligolo/pkg/buffer"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/adapters/gonet"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/header"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/link/channel"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/network/ipv4"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/network/ipv6"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/stack"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/icmp"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/tcp"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/udp"
	"github.com/nicocha30/gvisor-ligolo/pkg/waiter"
	"pivot-tool/internal/common"
)

// NIC is the only network interface card the virtual stack ever has: the
// one channel endpoint wired to the operator's real TUN device. Every
// pivoted subnet, no matter how many hops away, is reached through this
// single NIC — the stack is told (via promiscuous mode + spoofing, see
// below) to treat literally any destination as "on link" and let our own
// RouteTable decide, per-connection, which agent actually handles it. This
// is the core trick that removes ligolo-ng's "one TUN interface per pivot
// level" requirement.
const nicID tcpip.NICID = 1

// TunStack owns the gVisor userland TCP/IP stack and the raw packet pump
// between it and the real TUN device. It is what makes `nmap -sS` (SYN
// scan) and `-sU` (UDP scan) work transparently through the tunnel: the
// kernel on the operator's box sees a normal routable interface and lets
// nmap craft whatever raw packets it wants; this stack terminates those
// packets in userspace exactly like a tiny router would, and for TCP SYNs
// specifically it completes a real three-way handshake with the stack
// itself (fast, local, no network round trip) the instant a route exists,
// so nmap's SYN/ACK or RST comes back immediately rather than waiting on
// a slow link — which is also why this approach is dramatically faster
// for -sS scans than tunneling each individual nmap probe through a SOCKS
// proxy with proxychains.
type TunStack struct {
	stack *stack.Stack
	ep    *channel.Endpoint
	tun   io.ReadWriteCloser
	mtu   uint32
	mgr   *SessionManager
}

// NewTunStack wires up the stack and starts the two pump goroutines
// (TUN -> stack, stack -> TUN). tun must already be an open, "up" TUN
// device (see tun_linux.go); mtu should match what was configured on the
// interface (1500 is a safe, universal default; lower it if the path to
// the deepest pivot adds encapsulation overhead somewhere, which it does
// not here since everything rides inside the existing yamux/TLS stream).
func NewTunStack(tun io.ReadWriteCloser, mtu uint32, mgr *SessionManager) (*TunStack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})

	ep := channel.New(1024, mtu, "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("creating virtual NIC: %v", err)
	}
	// Promiscuous + spoofing = "accept and originate traffic for any
	// address, not just ones explicitly assigned to this NIC". Without
	// this, we would have to call AddProtocolAddress for every single
	// pivoted host IP before traffic to it would work, which is exactly
	// the kind of manual bookkeeping this tool exists to eliminate.
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("enabling promiscuous mode: %v", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("enabling spoofing: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	ts := &TunStack{stack: s, ep: ep, tun: tun, mtu: mtu, mgr: mgr}

	tcpFwd := tcp.NewForwarder(s, 0, 10000, ts.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, ts.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	go ts.pumpFromTUN()
	go ts.pumpToTUN()

	return ts, nil
}

// pumpFromTUN reads raw IP packets off the real TUN device (written there
// by the host kernel because nmap/the OS routed them at us) and injects
// them into the virtual stack.
func (ts *TunStack) pumpFromTUN() {
	buf := make([]byte, ts.mtu+64)
	for {
		n, err := ts.tun.Read(buf)
		if err != nil {
			log.Printf("TUN read error (interface removed or proxy shutting down): %v", err)
			return
		}
		if n < 1 {
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])

		var proto tcpip.NetworkProtocolNumber
		switch raw[0] >> 4 {
		case 4:
			proto = header.IPv4ProtocolNumber
		case 6:
			proto = header.IPv6ProtocolNumber
		default:
			continue // not IP; a sane TUN device shouldn't hand us this, but don't crash if it does
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
		ts.ep.InjectInbound(proto, pkt)
	}
}

// pumpToTUN does the reverse: packets the stack decided to emit (SYN/ACK,
// RST, ACK, actual payload bytes, ICMP errors, ...) get written back out
// the real TUN device, where the host kernel delivers them to whatever
// local process asked for them (nmap, curl, a browser pointed at a proxy
// SOCKS... whatever the operator is running).
func (ts *TunStack) pumpToTUN() {
	ctx := context.Background()
	for {
		pkt := ts.ep.ReadContext(ctx)
		if pkt.IsNil() {
			return // only happens if ep.Close() was called (shutdown)
		}
		view := pkt.ToView()
		b := view.AsSlice()
		if _, err := ts.tun.Write(b); err != nil {
			log.Printf("TUN write error: %v", err)
		}
		pkt.DecRef()
	}
}

// handleTCP is called by the gVisor stack for every inbound TCP SYN that
// matched our catch-all route. It is the single busiest, most
// failure-sensitive piece of code in the whole tool, so every branch is
// deliberately fail-closed: no route or no healthy agent means an
// immediate, clean reset (sendReset=true) rather than a connection that
// hangs until nmap's own timeout, which is what makes large SYN scans
// through this tunnel finish in seconds instead of minutes.
func (ts *TunStack) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dstIP := net.IP(id.LocalAddress.AsSlice())

	sess := ts.mgr.Routes.Lookup(dstIP)
	if sess == nil {
		r.Complete(true) // RST: "no route", not a silent timeout
		return
	}

	target := net.JoinHostPort(dstIP.String(), fmt.Sprintf("%d", id.LocalPort))
	remote, err := sess.OpenDataStream(common.StreamHeader{Kind: "connect", Network: "tcp", Addr: target})
	if err != nil {
		log.Printf("could not open data stream to agent %s for %s: %v", sess.ID, target, err)
		r.Complete(true)
		return
	}

	// Critical correctness point: do NOT complete the virtual TCP
	// handshake (which sends a SYN/ACK back to whatever is scanning or
	// connecting on the operator's side) until the agent has actually
	// tried to reach the real target and told us whether that
	// succeeded. Completing optimistically here would make every port
	// look "open" to nmap regardless of the real target's state, which
	// defeats the entire point of a SYN scan. The one-byte status ack
	// (0x01 ok / 0x00 failed) is written by the agent in
	// agent.handleDataStream immediately after its net.Dial call
	// returns, so this adds at most one real RTT to the pivot path —
	// not one per probe retransmission, since we also bound the wait.
	if !remote.waitConnectAck(3 * time.Second) {
		r.Complete(true) // RST: target refused/unreachable/timed out from the agent's side
		remote.Close()
		return
	}

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		log.Printf("stack could not complete handshake for %s: %v", target, tcpErr)
		r.Complete(true)
		remote.Close()
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&wq, ep)
	splice(local, remote)
}

func (ts *TunStack) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dstIP := net.IP(id.LocalAddress.AsSlice())

	sess := ts.mgr.Routes.Lookup(dstIP)
	if sess == nil {
		return // UDP has no RST equivalent here; we just drop (nmap will read this as filtered after its own timeout, matching normal UDP-scan behavior against a host with no firewall-reject rule)
	}

	target := net.JoinHostPort(dstIP.String(), fmt.Sprintf("%d", id.LocalPort))
	remote, err := sess.OpenDataStream(common.StreamHeader{Kind: "connect", Network: "udp", Addr: target})
	if err != nil {
		return
	}

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		remote.Close()
		return
	}
	local := gonet.NewUDPConn(ts.stack, &wq, ep)
	splice(local, remote)
}
