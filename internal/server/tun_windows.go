//go:build windows

package server

import (
	"fmt"
	"io"
	"net"
	"os/exec"

	"github.com/songgao/water"
)

func init() {
	openTUNImpl = openTUNWindows
	addOSRouteImpl = addOSRouteWindows
}

func addOSRouteWindows(cidr, iface string) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	mask := net.IP(ipnet.Mask).String()
	cmd := exec.Command("route", "add", ip.String(), "mask", mask, "0.0.0.0", "if", iface)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

func openTUNWindows(ifName, localCIDR string) (io.ReadWriteCloser, uint32, func(), error) {
	cfg := water.Config{DeviceType: water.TUN}
	cfg.PlatformSpecificParams.InterfaceName = ifName
	cfg.PlatformSpecificParams.Network = localCIDR
	ifce, err := water.New(cfg)
	if err != nil {
		return nil, 0, nil, fmt.Errorf(
			"creating TUN interface on Windows: %w\n\n"+
				"wintun.dll (bundled with this release, in the same folder as pivot-server.exe) could not be loaded. "+
				"Run as Administrator, and make sure Windows Defender / your EDR hasn't quarantined wintun.dll "+
				"(it is Wintun, the same signed driver WireGuard uses — add an exclusion for the pivot-server folder if needed).",
			err)
	}
	name := ifce.Name()
	run := func(args ...string) error {
		cmd := exec.Command(args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		return nil
	}
	ip, ipnet, err := net.ParseCIDR(localCIDR)
	if err != nil {
		ifce.Close()
		return nil, 0, nil, fmt.Errorf("invalid -cidr %q: %w", localCIDR, err)
	}
	mask := net.IP(ipnet.Mask).String()
	if err := run("netsh", "interface", "ip", "set", "address", name, "static", ip.String(), mask); err != nil {
		ifce.Close()
		return nil, 0, nil, fmt.Errorf("interface %q created but could not be assigned %s: %w", name, localCIDR, err)
	}
	cleanup := func() { ifce.Close() }
	return ifce, defaultMTU, cleanup, nil
}
