// Command pivot-agent is the small binary deployed on a pivot host. It
// has exactly two run modes:
//
//   - Direct:  ./pivot-agent -connect SERVER:PORT -pin FINGERPRINT [-token T]
//     Dials the operator's pivot-server directly.
//
//   - Chained: ./pivot-agent -chain PARENT:PORT
//     Dials an ALREADY-RUNNING pivot-agent (the "-relay-port" it opens by
//     default) instead of the server, so its traffic rides inside the
//     parent agent's own existing tunnel. This is how a second, third,
//     fourth... pivot is added: no new TUN interface anywhere, no extra
//     flags to get right, no firewall rule needed from the deeper host
//     straight out to the operator (which usually does not exist anyway
//     in a segmented network — that is the whole reason you are
//     pivoting).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"pivot-tool/internal/agent"
)

const version = "pivot-agent/1.0"

func main() {
	connect := flag.String("connect", "", "pivot-server address, host:port (direct mode)")
	pin := flag.String("pin", "", "expected SHA-256 fingerprint of the server's TLS certificate (printed by pivot-server at startup)")
	token := flag.String("token", "", "join token printed by pivot-server at startup")
	chain := flag.String("chain", "", "parent agent address, host:port, to relay through instead of connecting directly (multi-hop mode)")
	relayPort := flag.String("relay-listen", "0.0.0.0:11601", "address this agent listens on so a NEXT agent can -chain through it")
	idFile := flag.String("id-file", defaultIDFile(), "path to a file used to persist this agent's ID across restarts/reboots, so the server recognizes it as the same agent (and keeps its routes) rather than a brand new one")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification entirely INSTEAD of pinning (NOT recommended: only use if you cannot get -pin and accept the MITM risk)")
	flag.Parse()

	if *connect == "" && *chain == "" {
		fmt.Fprintln(os.Stderr, "usage: pivot-agent -connect HOST:PORT -pin FINGERPRINT [-token TOKEN]")
		fmt.Fprintln(os.Stderr, "   or: pivot-agent -chain PARENT_AGENT:PORT   (multi-hop, no cert/token needed — it rides the parent's already-authenticated tunnel)")
		os.Exit(2)
	}
	if *connect != "" && *pin == "" && !*insecure {
		fmt.Fprintln(os.Stderr, "refusing to connect without -pin or -insecure: ")
		fmt.Fprintln(os.Stderr, "  paste the fingerprint pivot-server printed, e.g. -pin 3f9c... ,")
		fmt.Fprintln(os.Stderr, "  or pass -insecure if you understand and accept the MITM risk.")
		os.Exit(2)
	}

	id := loadOrCreateAgentID(*idFile)

	fp := *pin
	if *insecure {
		fp = ""
	}

	cfg := agent.Config{
		ServerAddr:  *connect,
		Fingerprint: fp,
		Token:       *token,
		AgentID:     id,
		Nested:      *chain != "",
		Version:     version,
	}
	if cfg.Nested {
		cfg.ChainThrough = *chain
	}

	// Always start our own relay listener too, in case SOMEONE ELSE
	// wants to chain through *this* agent — this is what makes the
	// chaining recursive without the operator having to remember which
	// hop is "the relay one": every agent is always a potential relay.
	go startRelayListener(*relayPort)

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	agent.Run(context.Background(), cfg)
}

func defaultIDFile() string {
	dir, err := os.UserCacheDir()
	if err != nil || dir == "" {
		return ".pivot-agent-id"
	}
	return filepath.Join(dir, "pivot-agent-id")
}

func loadOrCreateAgentID(path string) string {
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		return string(b)
	}
	id := uuid.NewString()
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte(id), 0o600)
	return id
}

// startRelayListener is intentionally dumb: it is NOT itself a yamux/TLS
// endpoint. It just accepts a raw TCP connection from a would-be child
// agent and hands the raw bytes to our own already-established yamux
// session as a single new stream tagged "nested" (see agent.go /
// manager.go). All the protocol complexity lives in exactly one place
// (manager.Accept's recursion), not duplicated here.
func startRelayListener(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("could not start relay listener on %s (chaining through this agent will not work): %v", addr, err)
		return
	}
	log.Printf("relay listener up on %s — a second agent can -chain through this host via this port", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			agent.RelayNestedConn(c)
		}()
	}
}
