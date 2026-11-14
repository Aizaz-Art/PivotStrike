package common

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
)

// Protocol overview
// ------------------
// One TLS connection between agent and server carries one yamux session.
// Stream 0 of every session (the first stream the agent opens right after
// the handshake) is the CONTROL stream: newline-delimited JSON Envelope
// messages flow in both directions on it for the lifetime of the session.
//
// All other streams are DATA streams, opened on demand:
//
//   - Kind "connect": opened BY THE SERVER when traffic routed through the
//     virtual TUN interface needs to reach dest_ip:dest_port on the far
//     side of an agent. The first bytes written to the stream by the
//     opener are a StreamHeader (JSON, newline-terminated); after that it
//     is a raw byte pipe. The agent reads the header, net.Dial()s the
//     real target, and splices the stream to that connection.
//
//   - Kind "nested": opened BY THE AGENT when it is relaying a SECOND,
//     independent agent that dialed into one of the first agent's local
//     "-listen" relay ports (this is how multi-hop pivoting works without
//     ever creating a second TUN interface or asking the operator to run
//     another `autoroute`). The bytes on a "nested" stream are themselves
//     a complete, independent TLS+yamux session: the server runs a second
//     instance of its own session-accept logic on top of this stream,
//     exactly as if a brand new TCP connection had arrived. This can
//     recurse to arbitrary depth (triple, quadruple pivot, ...).

// MsgType enumerates control-stream envelope kinds.
type MsgType string

const (
	MsgHello     MsgType = "hello"      // agent -> server, once, right after control stream opens
	MsgHeartbeat MsgType = "heartbeat"  // either direction, periodic liveness + RTT measurement
	MsgRouteAdd  MsgType = "route_add"  // server -> agent (ack only, routes live server-side)
	MsgListenReq MsgType = "listen_req" // server -> agent: please open a TCP listener on the pivot
	MsgListenAck MsgType = "listen_ack" // agent -> server: result of a listen_req
	MsgError     MsgType = "error"
)

// Envelope is the single message type exchanged on the control stream.
// Payload is kind-specific JSON, re-marshalled into the concrete struct by
// the caller.
type Envelope struct {
	Type    MsgType         `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// NetRoute describes one network reachable from an agent, as self-reported
// by the agent at Hello time (and periodically refreshed on heartbeat, in
// case a reboot or a new NIC changes things). The server uses these to
// build its routing table automatically — no manual "autoroute" step.
type NetRoute struct {
	CIDR      string `json:"cidr"`
	Interface string `json:"interface"`
	Metric    int    `json:"metric"` // smaller = preferred; directly-connected = 0
}

// HelloPayload is sent once by the agent as the very first control message.
type HelloPayload struct {
	AgentID     string     `json:"agent_id"`     // stable UUID persisted on disk by the agent, survives reconnects/reboots
	Token       string     `json:"token"`        // pre-shared join token printed by the server at startup; prevents a stray scanner that completes the TLS handshake (trivial against a self-signed cert) from registering itself as an "agent"
	Hostname    string     `json:"hostname"`
	OS          string     `json:"os"`
	Arch        string     `json:"arch"`
	Version     string     `json:"version"`
	Routes      []NetRoute `json:"routes"`
	Nested      bool       `json:"nested"`       // true if this Hello arrived over a "nested" relay stream, not a fresh TCP conn
	ParentAgent string     `json:"parent_agent"` // agent_id of the relay parent, if Nested
}

type HeartbeatPayload struct {
	UnixNano int64 `json:"unix_nano"`
	Echo     bool  `json:"echo"` // true = this is a reply to the peer's heartbeat, not a new ping
}

// ListenReqPayload asks an agent to open bindAddr on the pivot host and
// forward every accepted connection back as a "connect"-kind stream headed
// to this same agent (used for the reverse direction: exposing an internal
// service to the pivot network, e.g. catching a reverse shell FROM the far
// side).
type ListenReqPayload struct {
	ID        string `json:"id"`
	BindAddr  string `json:"bind_addr"`
	ProxyBack string `json:"proxy_back"` // host:port on the operator side to receive connections
}

type ListenAckPayload struct {
	ID      string `json:"id"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	BoundOn string `json:"bound_on,omitempty"`
}

// StreamHeader is the first JSON line written on a freshly opened
// "connect"-kind data stream, telling the receiving end what to do with
// the raw bytes that follow.
type StreamHeader struct {
	Kind    string `json:"kind"`               // "connect" or "nested"
	Network string `json:"network,omitempty"`  // "tcp" or "udp", for "connect"
	Addr    string `json:"addr,omitempty"`      // "host:port", for "connect"
}

// WriteEnvelope/ReadEnvelope implement simple newline-delimited JSON framing
// so the control stream never needs a length prefix and stays trivially
// debuggable with a line-oriented tool if someone pipes it through.

func WriteEnvelope(w io.Writer, typ MsgType, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	env := Envelope{Type: typ, Payload: body}
	line, err := json.Marshal(env)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	_, err = w.Write(line)
	return err
}

func WriteHeader(w io.Writer, h StreamHeader) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// Dial is a tiny convenience used by tests/tools outside this package.
func Dial(network, addr string) (net.Conn, error) {
	return net.Dial(network, addr)
}

var _ = fmt.Sprintf // keep fmt imported for future error formatting without churn
