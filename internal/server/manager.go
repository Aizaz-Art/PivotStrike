package server

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/yamux"
	"pivot-tool/internal/common"
)

// SessionManager owns every connected AgentSession (top-level and nested,
// indistinguishably) plus the shared RouteTable they publish routes into.
type SessionManager struct {
	Routes *RouteTable
	Token  string // pre-shared join token; empty means "no token required" (operator's explicit choice, e.g. -no-auth)

	mu       sync.RWMutex
	sessions map[string]*AgentSession // keyed by AgentID

	pendingMu sync.Mutex
	pending   map[string]chan common.ListenAckPayload

	OnSessionChange func() // optional UI hook, called after any add/remove
	OnNewRoute      func(cidr string) // optional: wire the OS route table automatically (see cmd/pivot-server), so the operator never types `ip route add` either
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		Routes:   NewRouteTable(),
		sessions: make(map[string]*AgentSession),
		pending:  make(map[string]chan common.ListenAckPayload),
	}
}

// Accept takes a freshly-arrived io.ReadWriteCloser — either a raw TLS
// connection straight off the listener (depth 0), or a "nested" yamux
// stream relayed up through an existing agent (depth > 0) — and runs the
// full session lifecycle on it. This single code path is what lets an
// arbitrarily deep chain of pivots "just work": a triple-pivot's control
// traffic is, from this function's point of view, identical to a
// first-hop agent's control traffic. It happens to be tunneled inside two
// extra layers of yamux-over-TLS, but yamux.Server only needs an
// io.ReadWriteCloser, so that nesting is completely transparent here.
func (m *SessionManager) Accept(conn io.ReadWriteCloser, depth int, parentID string) {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 15 * time.Second
	cfg.ConnectionWriteTimeout = 15 * time.Second
	cfg.LogOutput = io.Discard

	ymx, err := yamux.Server(conn, cfg)
	if err != nil {
		log.Printf("yamux handshake failed (depth=%d parent=%s): %v", depth, parentID, err)
		conn.Close()
		return
	}

	ctrl, err := ymx.AcceptStream()
	if err != nil {
		log.Printf("agent never opened a control stream (depth=%d): %v", depth, err)
		ymx.Close()
		return
	}

	lr := common.NewLineReader(ctrl)
	env, err := lr.ReadEnvelope()
	if err != nil || env.Type != common.MsgHello {
		log.Printf("agent did not send Hello as first message (depth=%d): %v", depth, err)
		ymx.Close()
		return
	}
	var hp common.HelloPayload
	if err := common.Unmarshal(env.Payload, &hp); err != nil {
		log.Printf("malformed Hello (depth=%d): %v", depth, err)
		ymx.Close()
		return
	}
	// The join token is only meaningful for a fresh, depth-0 connection:
	// that is the only point where an arbitrary stranger could complete
	// our self-signed TLS handshake and try to register as an agent. A
	// nested (chained) session's trust is inherited from its parent
	// having already passed this same check — the parent would not be
	// relaying it otherwise — so re-demanding a token the chained agent
	// was never even given would make multi-hop pivoting impossible by
	// design, not by accident.
	if depth == 0 && m.Token != "" && hp.Token != m.Token {
		log.Printf("rejecting agent %s (depth=%d): bad/missing join token", hp.AgentID, depth)
		ymx.Close()
		return
	}
	if hp.AgentID == "" {
		// Defend against a buggy/ancient agent build; never let an
		// empty ID collide with every other empty-ID agent in the map.
		hp.AgentID = uuid.NewString()
	}

	sess := &AgentSession{
		ID:          hp.AgentID,
		Hello:       hp,
		ymx:         ymx,
		ctrl:        ctrl,
		lineR:       lr,
		mgr:         m,
		Depth:       depth,
		ParentID:    parentID,
		ConnectedAt: time.Now(),
	}
	sess.touch()

	m.register(sess)
	m.applyRoutes(sess, hp.Routes)
	log.Printf("[+] agent %s connected (%s@%s, depth=%d, %d route(s))", sess.ID, hp.OS, hp.Hostname, depth, len(hp.Routes))

	go m.heartbeatLoop(sess)
	go m.acceptExtraStreams(sess, depth)

	sess.controlLoop() // blocks until the control stream dies
}

// register swaps in the new session for this AgentID. If an older session
// with the same ID is still (nominally) around — e.g. the agent's TCP
// connection died and it reconnected before the server noticed — the old
// one is closed out from under it. Routes simply get overwritten by
// applyRoutes with the new session pointer, so reconnection is seamless:
// the operator never re-types a route or an autoroute command.
func (m *SessionManager) register(sess *AgentSession) {
	m.mu.Lock()
	old, existed := m.sessions[sess.ID]
	m.sessions[sess.ID] = sess
	m.mu.Unlock()
	if existed && old != sess {
		old.close()
	}
	if m.OnSessionChange != nil {
		m.OnSessionChange()
	}
}

func (m *SessionManager) onSessionClosed(sess *AgentSession) {
	m.mu.Lock()
	if cur, ok := m.sessions[sess.ID]; ok && cur == sess {
		delete(m.sessions, sess.ID)
	}
	m.mu.Unlock()
	m.Routes.RemoveSession(sess)
	log.Printf("[-] agent %s disconnected", sess.ID)
	if m.OnSessionChange != nil {
		m.OnSessionChange()
	}
}

func (m *SessionManager) applyRoutes(sess *AgentSession, routes []common.NetRoute) {
	for _, r := range routes {
		isNew := len(m.Routes.Snapshot()) == 0 || !containsRoute(m.Routes.Snapshot(), r.CIDR)
		if err := m.Routes.Upsert(r.CIDR, sess, r.Metric); err != nil {
			log.Printf("[%s] bad route %q from agent, ignoring: %v", sess.ID, r.CIDR, err)
			continue
		}
		if isNew && m.OnNewRoute != nil {
			m.OnNewRoute(r.CIDR)
		}
	}
}

func containsRoute(list []string, cidr string) bool {
	for _, c := range list {
		if c == cidr {
			return true
		}
	}
	return false
}

// heartbeatLoop pings the agent every 10s and relies on yamux's own
// keepalive (ConnectionWriteTimeout) plus a missed-heartbeat counter to
// detect a dead-but-not-yet-RST'd TCP connection (the classic "cable
// unplugged" / "WAF silently drops idle connections" / "exam VPN blipped"
// failure mode that pure TCP keepalive can take minutes to notice).
func (m *SessionManager) heartbeatLoop(sess *AgentSession) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for !sess.Closed() {
		<-ticker.C
		if time.Since(sess.LastSeen()) > 45*time.Second {
			log.Printf("[%s] missed heartbeats for 45s, tearing down session", sess.ID)
			sess.close()
			return
		}
		sess.sendHeartbeat()
	}
}

// acceptExtraStreams handles every yamux stream the agent opens AFTER the
// initial control stream: nested chained agents, and reverse "listen"
// callback connections.
func (m *SessionManager) acceptExtraStreams(sess *AgentSession, depth int) {
	for {
		st, err := sess.ymx.AcceptStream()
		if err != nil {
			return // session (or its mux) is gone; controlLoop will notice too
		}
		go m.handleExtraStream(sess, st, depth)
	}
}

func (m *SessionManager) handleExtraStream(sess *AgentSession, st *yamux.Stream, depth int) {
	lr := common.NewLineReader(st)
	hdr, err := lr.ReadHeader()
	if err != nil {
		st.Close()
		return
	}
	switch hdr.Kind {
	case "nested":
		// A chained agent: recurse. The PrefixedConn lets us hand the
		// *rest* of the stream (after the header line, which is
		// already consumed by lr's internal buffer) to yamux.Server
		// as if it were a fresh connection.
		m.Accept(common.NewPrefixedConn(st, lr), depth+1, sess.ID)
	case "listen-data":
		m.handleListenData(sess, hdr, lr, st)
	default:
		log.Printf("[%s] unknown extra-stream kind %q, closing", sess.ID, hdr.Kind)
		st.Close()
	}
}

// RequestListen asks sess to bind bindAddr on the pivot and forward
// accepted connections' bytes back to us, splicing them to proxyBack on
// our side. Blocks (with a timeout) for the agent's ack so a CLI caller
// gets an immediate success/failure instead of a silent no-op.
func (m *SessionManager) RequestListen(sess *AgentSession, bindAddr, proxyBack string) (common.ListenAckPayload, error) {
	id := uuid.NewString()
	ch := make(chan common.ListenAckPayload, 1)
	m.pendingMu.Lock()
	m.pending[id] = ch
	m.pendingMu.Unlock()
	defer func() {
		m.pendingMu.Lock()
		delete(m.pending, id)
		m.pendingMu.Unlock()
	}()

	sess.ctrlOut.Lock()
	err := common.WriteEnvelope(sess.ctrl, common.MsgListenReq, common.ListenReqPayload{ID: id, BindAddr: bindAddr, ProxyBack: proxyBack})
	sess.ctrlOut.Unlock()
	if err != nil {
		return common.ListenAckPayload{}, err
	}

	select {
	case ack := <-ch:
		return ack, nil
	case <-time.After(10 * time.Second):
		return common.ListenAckPayload{}, fmt.Errorf("agent %s did not ack listen request within 10s", sess.ID)
	}
}

func (m *SessionManager) deliverListenAck(ack common.ListenAckPayload) {
	m.pendingMu.Lock()
	ch, ok := m.pending[ack.ID]
	m.pendingMu.Unlock()
	if ok {
		ch <- ack
	}
}

func (m *SessionManager) handleListenData(sess *AgentSession, hdr common.StreamHeader, lr *common.LineReader, st *yamux.Stream) {
	back, err := net.DialTimeout("tcp", hdr.Addr, 5*time.Second)
	if err != nil {
		log.Printf("[%s] listen-data: could not reach proxy_back %s: %v", sess.ID, hdr.Addr, err)
		st.Close()
		return
	}
	splice(st, back)
}

// Sessions returns a snapshot list, sorted newest-first, for status
// display.
func (m *SessionManager) Sessions() []*AgentSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*AgentSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}

func (m *SessionManager) Get(id string) (*AgentSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// splice copies bytes both directions until either side closes, then
// makes sure both ends get torn down (half-open leaks are how a long exam
// session slowly runs out of file descriptors).
func splice(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}
