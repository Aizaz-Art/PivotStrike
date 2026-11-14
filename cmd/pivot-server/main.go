// Command pivot-server is the operator-side half of the pivoting tool.
//
// ZERO-CONFIG DEFAULT: run `sudo ./pivot-server` with no flags and it:
//   1. Generates a self-signed TLS cert (or reuses the one from last run)
//   2. Creates a TUN interface named "pivot0"
//   3. Assigns it an unused CGNAT-range /24 (100.64.x.0/24)
//   4. Generates a random join token
//   5. Starts a SOCKS5 proxy on :1080 as a fallback
//   6. Prints one copy-pasteable agent command with all needed flags
//   7. Auto-routes every subnet every agent reports — no `ip route add` ever
//   8. Opens an interactive CLI for status, listeners, agent management
//
// The operator never types `ip tuntap add`, `ip link set`, `ip route add`,
// `autoroute`, or `session` — the entire ligolo-ng dance is ONE command here.
package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"pivot-tool/internal/common"
	"pivot-tool/internal/server"
)

const version = "pivotstrike-server/1.0"

func main() {
	laddr := flag.String("laddr", "0.0.0.0:11601", "address to listen for agents on")
	iface := flag.String("iface", "pivot0", "name of the TUN interface to create")
	cidr := flag.String("cidr", "", "local address/CIDR for the TUN interface (default: auto-pick an unused 100.64.x.0/24)")
	certPath := flag.String("cert", "pivotstrike-server.crt", "path to TLS certificate (generated on first run)")
	keyPath := flag.String("key", "pivotstrike-server.key", "path to TLS key (generated on first run)")
	token := flag.String("token", "", "join token agents must present (default: random)")
	noAuth := flag.Bool("no-auth", false, "disable join-token checking (NOT recommended outside an isolated lab)")
	noTUN := flag.Bool("no-tun", false, "skip TUN interface creation (no SYN scans, only SOCKS5 proxy)")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "SOCKS5 proxy listen address (empty to disable)")
	noSocks := flag.Bool("no-socks", false, "disable the SOCKS5 fallback proxy")
	noCLI := flag.Bool("no-cli", false, "disable interactive CLI (for scripted/daemon use)")
	flag.Parse()

	if *cidr == "" {
		*cidr = fmt.Sprintf("100.64.%d.1/24", rand.Intn(200)+10)
	}
	if *token == "" && !*noAuth {
		*token = uuid.NewString()
	}

	cert, fp, err := common.GenerateSelfSigned(*certPath, *keyPath, []string{})
	if err != nil {
		log.Fatalf("certificate setup failed: %v", err)
	}

	mgr := server.NewSessionManager()
	if !*noAuth {
		mgr.Token = *token
	}

	tunActive := false
	if !*noTUN {
		tun, mtu, cleanup, err := server.OpenTUN(*iface, *cidr)
		if err != nil {
			log.Fatalf("%v", err)
		}
		defer cleanup()
		if _, err := server.NewTunStack(tun, mtu, mgr); err != nil {
			log.Fatalf("starting virtual network stack: %v", err)
		}
		mgr.OnNewRoute = func(cidr string) {
			if err := server.AddOSRoute(cidr, *iface); err != nil {
				log.Printf("⚠ learned route %s but could not add OS route: %v — add manually: sudo ip route add %s dev %s", cidr, err, cidr, *iface)
			} else {
				log.Printf("✓ routed %s → %s automatically", cidr, *iface)
			}
		}
		tunActive = true
		log.Printf("TUN interface %q up at %s — all agent subnets auto-routed", *iface, *cidr)
	} else {
		log.Printf("TUN disabled (-no-tun): SYN scans won't work; use SOCKS5 proxy instead")
	}

	// Start SOCKS5 proxy
	socksActive := false
	if !*noSocks && *socksAddr != "" {
		socks := server.NewSOCKS5Server(mgr)
		if err := socks.Start(*socksAddr); err != nil {
			log.Printf("⚠ could not start SOCKS5 proxy on %s: %v (continuing without it)", *socksAddr, err)
		} else {
			socksActive = true
		}
	}

	if err := server.Listen(*laddr, cert, mgr); err != nil {
		log.Fatalf("listen failed: %v", err)
	}

	// Detect IP for copy-paste convenience
	detectedIP := server.AutoDetectIP()
	_, port, _ := splitHostPort(*laddr)
	connectHost := detectedIP + ":" + port

	// Print the startup banner
	printBanner(connectHost, fp, *token, *noAuth, tunActive, *iface, *cidr, socksActive, *socksAddr)

	// Handle signals for clean shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	if !*noCLI {
		// Run interactive CLI in a goroutine; signals still work
		go func() {
			<-sig
			log.Println("shutting down, cleaning up...")
			os.Exit(0)
		}()
		cli := server.NewCLI(mgr)
		cli.Run()
	} else {
		<-sig
		log.Println("shutting down, cleaning up...")
	}
}

func printBanner(connectHost, fp, token string, noAuth, tunActive bool, iface, cidr string, socksActive bool, socksAddr string) {
	var agentCmd string
	if noAuth {
		agentCmd = fmt.Sprintf("./pivotstrike-agent -connect %s -pin %s", connectHost, fp)
	} else {
		agentCmd = fmt.Sprintf("./pivotstrike-agent -connect %s -pin %s -token %s", connectHost, fp, token)
	}

	fmt.Println()
	fmt.Println("\033[1;36m╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                     PIVOTSTRIKE SERVER READY                       ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝\033[0m")
	fmt.Println()

	// Connection details
	fmt.Println("\033[1;33m  ┌─ Connection ─────────────────────────────────────────────────┐\033[0m")
	fmt.Printf("  │  Listen:  %s\n", connectHost)
	fmt.Printf("  │  Cert FP: %s\n", fp[:16]+"...")
	if !noAuth {
		fmt.Printf("  │  Token:   %s\n", token)
	}
	fmt.Println("\033[1;33m  └─────────────────────────────────────────────────────────────────┘\033[0m")
	fmt.Println()

	// Capabilities
	fmt.Println("\033[1;33m  ┌─ Capabilities ──────────────────────────────────────────────┐\033[0m")
	if tunActive {
		fmt.Printf("  │  \033[1;32m✓\033[0m TUN interface: %s (%s)\n", iface, cidr)
		fmt.Printf("  │    → nmap -sS, nmap -sU, ICMP, raw sockets all work\n")
		fmt.Printf("  │    → routes added automatically — no 'ip route add' needed\n")
	} else {
		fmt.Printf("  │  \033[1;31m✗\033[0m TUN disabled (no SYN scans)\n")
	}
	if socksActive {
		fmt.Printf("  │  \033[1;32m✓\033[0m SOCKS5 proxy: %s\n", socksAddr)
		fmt.Printf("  │    → proxychains / browser proxy / curl --socks5\n")
	}
	fmt.Println("\033[1;33m  └─────────────────────────────────────────────────────────────────┘\033[0m")
	fmt.Println()

	// Deploy command
	fmt.Println("\033[1;33m  ┌─ Deploy Agent (copy-paste this) ─────────────────────────────┐\033[0m")
	fmt.Printf("  │\n")
	fmt.Printf("  │  \033[1;37m%s\033[0m\n", agentCmd)
	fmt.Printf("  │\n")
	fmt.Println("\033[1;33m  └─────────────────────────────────────────────────────────────────┘\033[0m")
	fmt.Println()

	// Multi-hop
	fmt.Println("\033[1;33m  ┌─ Multi-hop (deeper pivots) ──────────────────────────────────┐\033[0m")
	fmt.Printf("  │  On a host only reachable from the first pivot:\n")
	fmt.Printf("  │\n")
	fmt.Printf("  │  \033[1;37m./pivotstrike-agent -chain <first-agent-ip>:11601\033[0m\n")
	fmt.Printf("  │\n")
	fmt.Printf("  │  No extra TUN, no extra routes — it just works.\n")
	fmt.Println("\033[1;33m  └─────────────────────────────────────────────────────────────────┘\033[0m")
	fmt.Println()

	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		fmt.Println("  \033[2mType 'help' for commands, 'status' for overview, 'quit' to exit.\033[0m")
	}
	fmt.Println()
}

func splitHostPort(addr string) (string, string, error) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("no port in address %q", addr)
}

var _ = strings.TrimSpace // reserved
