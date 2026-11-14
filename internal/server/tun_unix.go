//go:build linux || darwin

package server

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"

	"github.com/songgao/water"
)

func init() {
	openTUNImpl = openTUNUnix
	addOSRouteImpl = addOSRouteUnix
}

func addOSRouteUnix(cidr, iface string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "linux" {
		cmd = exec.Command("ip", "route", "add", cidr, "dev", iface)
	} else {
		cmd = exec.Command("route", "-n", "add", "-net", cidr, "-interface", iface)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Idempotency: re-learning a route we already added (e.g. an
		// agent's periodic Hello refresh reporting the same subnet
		// again after a reconnect) is expected, not an error — the
		// kernel's own "already exists" message is the signal.
		s := string(out)
		if containsAny(s, "File exists", "already in table", "RTNETLINK") {
			return nil
		}
		return fmt.Errorf("%v: %s", err, s)
	}
	return nil
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func openTUNUnix(ifName, localCIDR string) (io.ReadWriteCloser, uint32, func(), error) {
	cfg := water.Config{DeviceType: water.TUN}
	cfg.Name = ifName
	ifce, err := water.New(cfg)
	if err != nil {
		return nil, 0, nil, fmt.Errorf(
			"creating TUN interface %q: %w\n\n"+
				"Most likely causes:\n"+
				"  - not running as root / without CAP_NET_ADMIN (try: sudo setcap cap_net_admin+ep ./pivot-server, or just run with sudo)\n"+
				"  - the kernel is missing the tun module (try: sudo modprobe tun)\n"+
				"  - another process already owns an interface named %q (pass -iface to pick a different name)",
			ifName, err, ifName)
	}

	name := ifce.Name()
	run := func(args ...string) error {
		cmd := exec.Command(args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		return nil
	}

	var upErr error
	if runtime.GOOS == "linux" {
		if err := run("ip", "addr", "add", localCIDR, "dev", name); err != nil {
			upErr = err
		} else if err := run("ip", "link", "set", "dev", name, "up", "mtu", fmt.Sprintf("%d", defaultMTU)); err != nil {
			upErr = err
		}
	} else { // darwin
		ip, _, _ := net.ParseCIDR(localCIDR)
		if err := run("ifconfig", name, "inet", ip.String(), ip.String(), "up"); err != nil {
			upErr = err
		}
	}
	if upErr != nil {
		ifce.Close()
		return nil, 0, nil, fmt.Errorf("interface %q created but could not be configured/brought up: %w", name, upErr)
	}

	cleanup := func() {
		ifce.Close()
		if runtime.GOOS == "linux" {
			_ = run("ip", "link", "delete", name)
		}
	}
	return ifce, defaultMTU, cleanup, nil
}
