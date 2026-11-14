package server

import (
	"fmt"
	"io"
	"runtime"
)

// OpenTUN creates (or reuses, if ifName already exists and is ours) a TUN
// interface named ifName, assigns it localCIDR, brings it up, and returns
// the open device handle plus the MTU to use.
//
// This single function is the main "super easy to set up" win over
// ligolo-ng: there, the operator has to run 3-4 separate `ip`/`sudo`
// commands by hand before even starting the proxy, on Linux, and
// separately fetch+place wintun.dll on Windows. Here, one function call
// (invoked automatically when the server starts, unless -no-tun is
// passed) does the equivalent setup and, just as importantly, tears it
// back down on exit via the returned cleanup func, so a crashed or
// Ctrl-C'd run never leaves a stray `pivot0` interface and a dangling
// route behind for the next run (or the next engagement) to trip over.
//
// Platform-specific implementations live in tun_unix.go (Linux/macOS) and
// tun_windows.go, each built only for their own GOOS so a cross-compiled
// Linux binary never references Windows-only fields (and vice versa).
func OpenTUN(ifName, localCIDR string) (io.ReadWriteCloser, uint32, func(), error) {
	if openTUNImpl == nil {
		return nil, 0, nil, fmt.Errorf("unsupported OS %q for automatic TUN setup; run the server with -no-tun and configure the interface yourself", runtime.GOOS)
	}
	return openTUNImpl(ifName, localCIDR)
}

// defaultMTU leaves headroom under 1500 for the TLS/yamux framing
// overhead on the wire, so the virtual link's MTU is never a lossy
// illusion that silently drops or fragments the biggest packets nmap or a
// file transfer sends.
const defaultMTU = 1420

// openTUNImpl is set by exactly one of tun_unix.go / tun_windows.go's
// init(), depending on build target.
var openTUNImpl func(ifName, localCIDR string) (io.ReadWriteCloser, uint32, func(), error)

// AddOSRoute adds a route for cidr via iface to the real OS routing
// table, so traffic the kernel itself originates (an operator running
// nmap/curl/anything, not just packets we already caught) finds its way
// to our TUN interface without the operator ever typing `ip route add`.
func AddOSRoute(cidr, iface string) error {
	if addOSRouteImpl == nil {
		return fmt.Errorf("automatic OS routing not implemented for %s", runtime.GOOS)
	}
	return addOSRouteImpl(cidr, iface)
}

var addOSRouteImpl func(cidr, iface string) error
