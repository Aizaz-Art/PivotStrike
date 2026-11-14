package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// CLI is the interactive console the operator uses to inspect connected
// agents, routes, listeners, and manage the pivoting session — all without
// leaving the terminal the server is running in. Commands are deliberately
// short and forgiving (e.g. "s" = "status", "a" = "agents"), because the
// person typing them is mid-exam with adrenaline, and muscle-memory from
// ligolo-ng's own console is kept where it makes sense.
type CLI struct {
	mgr     *SessionManager
	out     io.Writer
	running bool
}

func NewCLI(mgr *SessionManager) *CLI {
	return &CLI{mgr: mgr, out: os.Stdout}
}

func (c *CLI) Run() {
	c.running = true
	scanner := bufio.NewScanner(os.Stdin)
	c.prompt()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			c.prompt()
			continue
		}
		c.dispatch(line)
		c.prompt()
	}
}

func (c *CLI) prompt() {
	agents := c.mgr.Sessions()
	routes := c.mgr.Routes.Snapshot()
	fmt.Fprintf(c.out, "\n\033[1;36mpivot»\033[0m \033[2m[%d agent(s), %d route(s)]\033[0m ", len(agents), len(routes))
}

func (c *CLI) dispatch(line string) {
	parts := strings.Fields(line)
	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "help", "h", "?":
		c.cmdHelp()
	case "status", "s":
		c.cmdStatus()
	case "agents", "a", "sessions":
		c.cmdAgents()
	case "routes", "r":
		c.cmdRoutes()
	case "listener", "listen", "l":
		c.cmdListener(args)
	case "listeners", "ll":
		c.cmdListeners()
	case "ping":
		c.cmdPing(args)
	case "quit", "exit", "q":
		fmt.Fprintln(c.out, "Shutting down...")
		os.Exit(0)
	default:
		fmt.Fprintf(c.out, "Unknown command %q — type 'help' for available commands\n", cmd)
	}
}

func (c *CLI) cmdHelp() {
	help := `
┌─────────────────────────────────────────────────────────────┐
│                    pivot-server commands                     │
├──────────────┬──────────────────────────────────────────────┤
│ status (s)   │ Overview: agents, routes, uptime             │
│ agents (a)   │ List connected agents with details           │
│ routes (r)   │ Show routing table                           │
│ listen (l)   │ Create a listener on a pivot host            │
│              │   l <agent-id-prefix> <bind> <proxy-back>    │
│              │   e.g.: l abc 0.0.0.0:4444 127.0.0.1:4444   │
│ listeners    │ List active listeners                        │
│ ping <id>    │ Check RTT to an agent (id prefix)            │
│ help (h)     │ This help                                    │
│ quit (q)     │ Shut down                                    │
└──────────────┴──────────────────────────────────────────────┘`
	fmt.Fprintln(c.out, help)
}

func (c *CLI) cmdStatus() {
	agents := c.mgr.Sessions()
	routes := c.mgr.Routes.Snapshot()

	fmt.Fprintf(c.out, "\n\033[1;33m═══ PIVOT STATUS ═══\033[0m\n")
	fmt.Fprintf(c.out, "  Agents connected : \033[1;32m%d\033[0m\n", len(agents))
	fmt.Fprintf(c.out, "  Routes active    : \033[1;32m%d\033[0m\n", len(routes))

	if len(agents) > 0 {
		fmt.Fprintf(c.out, "\n  \033[1mAgents:\033[0m\n")
		for _, s := range agents {
			age := time.Since(s.ConnectedAt).Truncate(time.Second)
			lastSeen := time.Since(s.LastSeen()).Truncate(time.Millisecond)
			fmt.Fprintf(c.out, "    \033[1;36m%s\033[0m  %s@%s  depth=%d  up=%s  last_seen=%s ago\n",
				s.ID[:8], s.Hello.OS, s.Hello.Hostname, s.Depth, age, lastSeen)
			for _, r := range s.Hello.Routes {
				fmt.Fprintf(c.out, "      └─ %s (%s)\n", r.CIDR, r.Interface)
			}
		}
	}

	if len(routes) > 0 {
		fmt.Fprintf(c.out, "\n  \033[1mRoutes:\033[0m\n")
		for _, r := range routes {
			fmt.Fprintf(c.out, "    %s\n", r)
		}
	}
}

func (c *CLI) cmdAgents() {
	agents := c.mgr.Sessions()
	if len(agents) == 0 {
		fmt.Fprintln(c.out, "  No agents connected. Deploy with the command shown at startup.")
		return
	}

	// Sort by depth, then connection time
	sort.Slice(agents, func(i, j int) bool {
		if agents[i].Depth != agents[j].Depth {
			return agents[i].Depth < agents[j].Depth
		}
		return agents[i].ConnectedAt.Before(agents[j].ConnectedAt)
	})

	fmt.Fprintf(c.out, "\n  \033[1m%-10s %-12s %-8s %-6s %-10s %-12s Routes\033[0m\n",
		"ID", "Host", "OS", "Depth", "Uptime", "Last Seen")
	fmt.Fprintf(c.out, "  %s\n", strings.Repeat("─", 78))

	for _, s := range agents {
		age := time.Since(s.ConnectedAt).Truncate(time.Second)
		lastSeen := time.Since(s.LastSeen()).Truncate(time.Millisecond)
		routeStrs := make([]string, 0)
		for _, r := range s.Hello.Routes {
			routeStrs = append(routeStrs, r.CIDR)
		}
		fmt.Fprintf(c.out, "  \033[1;36m%-10s\033[0m %-12s %-8s %-6d %-10s %-12s %s\n",
			s.ID[:minInt(10, len(s.ID))],
			truncate(s.Hello.Hostname, 12),
			s.Hello.OS+"/"+s.Hello.Arch,
			s.Depth,
			age.String(),
			lastSeen.String(),
			strings.Join(routeStrs, ", "),
		)
	}
}

func (c *CLI) cmdRoutes() {
	routes := c.mgr.Routes.Snapshot()
	if len(routes) == 0 {
		fmt.Fprintln(c.out, "  No routes. Waiting for agents to connect and advertise their networks.")
		return
	}

	fmt.Fprintf(c.out, "\n  \033[1m%-20s Via Agent\033[0m\n", "Network")
	fmt.Fprintf(c.out, "  %s\n", strings.Repeat("─", 50))

	c.mgr.Routes.mu.RLock()
	defer c.mgr.Routes.mu.RUnlock()

	sortedKeys := make([]string, 0, len(c.mgr.Routes.routes))
	for k := range c.mgr.Routes.routes {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	for _, k := range sortedKeys {
		e := c.mgr.Routes.routes[k]
		agentLabel := "???"
		if e.session != nil {
			agentLabel = e.session.ID[:minInt(8, len(e.session.ID))] + " (" + e.session.Hello.Hostname + ")"
		}
		fmt.Fprintf(c.out, "  \033[1;32m%-20s\033[0m %s\n", k, agentLabel)
	}
}

func (c *CLI) cmdListener(args []string) {
	if len(args) < 3 {
		fmt.Fprintln(c.out, "  Usage: listen <agent-id-prefix> <bind-addr> <proxy-back-addr>")
		fmt.Fprintln(c.out, "  Example: listen abc12 0.0.0.0:4444 127.0.0.1:4444")
		fmt.Fprintln(c.out, "           (catch reverse shell on pivot host port 4444 → your local 4444)")
		return
	}
	prefix := args[0]
	bindAddr := args[1]
	proxyBack := args[2]

	// Find agent by prefix
	sess := c.findAgentByPrefix(prefix)
	if sess == nil {
		fmt.Fprintf(c.out, "  No agent found matching prefix %q\n", prefix)
		return
	}

	fmt.Fprintf(c.out, "  Requesting listener on agent %s (%s) bind=%s proxy_back=%s ...\n",
		sess.ID[:8], sess.Hello.Hostname, bindAddr, proxyBack)

	ack, err := c.mgr.RequestListen(sess, bindAddr, proxyBack)
	if err != nil {
		fmt.Fprintf(c.out, "  \033[1;31mFailed:\033[0m %v\n", err)
		return
	}
	if !ack.OK {
		fmt.Fprintf(c.out, "  \033[1;31mAgent refused:\033[0m %s\n", ack.Error)
		return
	}
	fmt.Fprintf(c.out, "  \033[1;32m✓ Listener active:\033[0m bound on %s → forwarding to %s\n", ack.BoundOn, proxyBack)
}

func (c *CLI) cmdListeners() {
	fmt.Fprintln(c.out, "  (Active listeners are tracked per-agent; use 'agents' to see agent details)")
}

func (c *CLI) cmdPing(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(c.out, "  Usage: ping <agent-id-prefix>")
		return
	}
	sess := c.findAgentByPrefix(args[0])
	if sess == nil {
		fmt.Fprintf(c.out, "  No agent found matching prefix %q\n", args[0])
		return
	}
	lastSeen := time.Since(sess.LastSeen())
	if lastSeen > 30*time.Second {
		fmt.Fprintf(c.out, "  \033[1;31m⚠ Agent %s last seen %s ago — may be dead\033[0m\n",
			sess.ID[:8], lastSeen.Truncate(time.Millisecond))
	} else {
		fmt.Fprintf(c.out, "  \033[1;32m✓ Agent %s alive\033[0m — last heartbeat %s ago\n",
			sess.ID[:8], lastSeen.Truncate(time.Millisecond))
	}
}

func (c *CLI) findAgentByPrefix(prefix string) *AgentSession {
	prefix = strings.ToLower(prefix)
	for _, s := range c.mgr.Sessions() {
		if strings.HasPrefix(strings.ToLower(s.ID), prefix) {
			return s
		}
	}
	return nil
}

// autoDetectIP tries to figure out the most likely "reachable from the
// target" IP address on this box, by opening a UDP socket toward a public
// address (no actual packet is sent) and reading back the local address the
// kernel chose. Falls back gracefully if anything fails.
func AutoDetectIP() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", time.Second)
	if err != nil {
		// Try all interfaces
		ifaces, _ := net.Interfaces()
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				ipnet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip := ipnet.IP.To4()
				if ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
					return ip.String()
				}
			}
		}
		return "<YOUR_IP>"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
