package server

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"pivot-tool/internal/common"
)

// AgentSession represents one connected agent (fresh TCP connection OR a
// nested relay stream — identical handling either way, which is exactly
// what makes multi-hop "just work").
type AgentSession struct {
	ID       string // AgentID from Hello, stable across reconnects
	Hello    common.HelloPayload
	ymx      *yamux.Session
	ctrl     *yamux.Stream
	ctrlOut  sync.Mutex // serialize writes to ctrl from multiple goroutines
	lineR    *common.LineReader
	lastSeen atomic.Int64 // unix nano
	closed   atomic.Bool
	mgr      *SessionManager

	// Depth/parent info for display and for refusing accidental routing
	// loops (an agent can never be its own ancestor).
	Depth       int
	ParentID    string
	ConnectedAt time.Time
}

func (s *AgentSession) Closed() bool { return s.closed.Load() }

func (s *AgentSession) touch() { s.lastSeen.Store(time.Now().UnixNano()) }

func (s *AgentSession) LastSeen() time.Time {
	return time.Unix(0, s.lastSeen.Load())
}

// DataStream wraps a yamux stream opened for a "connect" target, adding
// the one-byte connect-ack handshake described in netstack.go's
// handleTCP: the agent writes 0x01/0x00 immediately after its own
// net.Dial attempt returns, and the caller MUST read that byte (via
// waitConnectAck) before trusting the stream is actually wired up to a
// live target.
type DataStream struct {
	*yamux.Stream
}

// waitConnectAck blocks (up to timeout) for the agent's one-byte dial
// result. Returns false on timeout, read error, EOF, or an explicit
// failure byte — all of which mean "do not treat this as a successful
// connection".
func (d DataStream) waitConnectAck(timeout time.Duration) bool {
	_ = d.SetReadDeadline(time.Now().Add(timeout))
	defer d.SetReadDeadline(time.Time{})
	var b [1]byte
	n, err := d.Read(b[:])
	return err == nil && n == 1 && b[0] == 1
}

// OpenDataStream opens a new yamux stream and writes the given header as
// its first line, returning the stream ready for raw byte relay. Used by
// the netstack TCP/UDP forwarders to reach a "connect" target on the agent.
func (s *AgentSession) OpenDataStream(h common.StreamHeader) (DataStream, error) {
	if s.Closed() {
		return DataStream{}, fmt.Errorf("session %s is closed", s.ID)
	}
	st, err := s.ymx.OpenStream()
	if err != nil {
		return DataStream{}, err
	}
	if err := common.WriteHeader(st, h); err != nil {
		st.Close()
		return DataStream{}, err
	}
	return DataStream{st}, nil
}

func (s *AgentSession) sendHeartbeat() {
	s.ctrlOut.Lock()
	defer s.ctrlOut.Unlock()
	_ = common.WriteEnvelope(s.ctrl, common.MsgHeartbeat, common.HeartbeatPayload{UnixNano: time.Now().UnixNano()})
}

// controlLoop reads the control stream until it errors out (peer gone),
// handling Hello refreshes and heartbeat replies. One goroutine per
// session, started by SessionManager.Accept.
func (s *AgentSession) controlLoop() {
	defer s.close()
	for {
		env, err := s.lineR.ReadEnvelope()
		if err != nil {
			log.Printf("[%s] control stream ended: %v", s.ID, err)
			return
		}
		s.touch()
		switch env.Type {
		case common.MsgHeartbeat:
			var hb common.HeartbeatPayload
			_ = common.Unmarshal(env.Payload, &hb)
			if !hb.Echo {
				s.ctrlOut.Lock()
				_ = common.WriteEnvelope(s.ctrl, common.MsgHeartbeat, common.HeartbeatPayload{UnixNano: hb.UnixNano, Echo: true})
				s.ctrlOut.Unlock()
			}
		case common.MsgHello:
			var hp common.HelloPayload
			if err := common.Unmarshal(env.Payload, &hp); err == nil {
				s.Hello = hp
				s.mgr.applyRoutes(s, hp.Routes)
			}
		case common.MsgListenAck:
			var la common.ListenAckPayload
			_ = common.Unmarshal(env.Payload, &la)
			s.mgr.deliverListenAck(la)
		default:
			// Forward-compatible: unknown message types are ignored
			// rather than treated as fatal, so an older server can
			// still talk to a newer agent (and vice versa) as long
			// as the core Hello/Heartbeat/Connect semantics hold.
		}
	}
}

func (s *AgentSession) close() {
	if s.closed.CompareAndSwap(false, true) {
		_ = s.ymx.Close()
		s.mgr.onSessionClosed(s)
	}
}
