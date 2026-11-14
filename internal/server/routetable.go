package server

import (
	"net"
	"sort"
	"sync"
)

// RouteTable maps destination CIDRs to the AgentSession responsible for
// them, with longest-prefix-match lookup, and is safe for concurrent use.
// This is the piece that lets ONE TUN interface on the proxy serve an
// arbitrary number of agents/hops: ligolo-ng needs a brand new TUN
// interface (and a brand new set of `ip route add` commands) per pivot
// level, because its route table is really just the kernel's own routing
// table pointed at different TUN devices. Here, routing is a software
// decision made per-connection inside our process, so adding the 50th
// pivoted subnet is exactly as cheap as adding the 1st, and never touches
// the host's real routing table at all (nothing to clean up if the process
// is killed -9, nothing for a different tool on the same box to conflict
// with).
type RouteTable struct {
	mu     sync.RWMutex
	routes map[string]*routeEntry // keyed by CIDR string
}

type routeEntry struct {
	network *net.IPNet
	session *AgentSession
	metric  int
}

func NewRouteTable() *RouteTable {
	return &RouteTable{routes: make(map[string]*routeEntry)}
}

// Upsert adds or replaces the route to cidr via session. Called whenever an
// agent sends/updates its Hello with self-reported routes, and on every
// heartbeat refresh, so a route automatically migrates to a reconnected
// session (new AgentSession pointer, same agent_id) without operator
// intervention.
func (rt *RouteTable) Upsert(cidr string, session *AgentSession, metric int) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.routes[ipnet.String()] = &routeEntry{network: ipnet, session: session, metric: metric}
	return nil
}

// RemoveSession deletes every route that pointed at session (called when a
// session disconnects and does NOT come back within the grace period —
// see SessionManager.reaper).
func (rt *RouteTable) RemoveSession(session *AgentSession) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for k, e := range rt.routes {
		if e.session == session {
			delete(rt.routes, k)
		}
	}
}

// Lookup returns the best (longest-prefix, then lowest-metric) matching
// session for ip, or nil if nothing routes there — in which case the
// caller should respond with an ICMP-style "no route" / TCP RST rather
// than hanging, so nmap sees a clean "closed"/"filtered" instead of a
// timeout storm.
func (rt *RouteTable) Lookup(ip net.IP) *AgentSession {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	var best *routeEntry
	var bestPrefix int
	for _, e := range rt.routes {
		if !e.network.Contains(ip) {
			continue
		}
		ones, _ := e.network.Mask.Size()
		if best == nil || ones > bestPrefix || (ones == bestPrefix && e.metric < best.metric) {
			best = e
			bestPrefix = ones
		}
	}
	if best == nil || best.session == nil || best.session.Closed() {
		return nil
	}
	return best.session
}

// Snapshot returns a stable, sorted list of current routes for display
// (status command / web UI), independent of map iteration order.
func (rt *RouteTable) Snapshot() []string {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	out := make([]string, 0, len(rt.routes))
	for k := range rt.routes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
