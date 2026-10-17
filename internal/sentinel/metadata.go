package sentinel

import (
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"

	"nocert.io/sentinel/internal/version"
)

// SentinelMetadata contains the sentinel's system information.
type SentinelMetadata struct {
	Hostname  string `json:"hostname,omitempty"`
	OS        string `json:"os,omitempty"`
	Arch      string `json:"arch,omitempty"`
	Version   string `json:"version,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
	// InterfaceSubnets are the IPv4 networks (CIDR) of this host's own
	// non-virtual interfaces. Reported at enrollment so the backend can offer
	// them as one-click suggestions when the operator picks which subnets this
	// sentinel should scan. Advisory only - the sentinel never scans them on
	// its own; the backend tells it what to scan.
	InterfaceSubnets []string `json:"interface_subnets,omitempty"`
}

// CollectMetadata gathers system metadata for the sentinel.
func CollectMetadata(serverURL string) SentinelMetadata {
	m := SentinelMetadata{
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		Version: version.Version,
	}
	if h, err := os.Hostname(); err == nil {
		m.Hostname = h
	}
	m.IPAddress = detectPrimaryIP(serverURL)
	m.InterfaceSubnets = detectInterfaceSubnets()
	return m
}

// detectPrimaryIP finds the machine's primary IP by checking which interface
// would be used to reach the backend server. This naturally avoids Docker
// bridges, loopback, and other virtual interfaces.
func detectPrimaryIP(serverURL string) string {
	// Try using the backend server as the target
	target := ""
	if u, err := url.Parse(serverURL); err == nil && u.Host != "" {
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		target = net.JoinHostPort(host, port)
	}
	if target == "" {
		target = "1.0.0.0:80"
	}

	conn, err := net.Dial("udp", target)
	if err != nil {
		return detectPrimaryIPFallback()
	}
	defer func() { _ = conn.Close() }()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	if localAddr.IP.IsLoopback() || localAddr.IP.IsUnspecified() {
		return detectPrimaryIPFallback()
	}
	return localAddr.IP.String()
}

// virtualIfacePrefixes are interface-name prefixes we treat as virtual/overlay
// (docker bridges, veth pairs, VPN/WireGuard tunnels, loopback) and ignore when
// looking for the host's real network.
var virtualIfacePrefixes = []string{"docker", "br-", "veth", "virbr", "lo", "tun", "wg", "tailscale"}

// isRealInterface reports whether an interface is up, not loopback, and not one
// of the known virtual/overlay kinds.
func isRealInterface(iface net.Interface) bool {
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	name := strings.ToLower(iface.Name)
	for _, prefix := range virtualIfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}

// detectPrimaryIPFallback enumerates network interfaces and picks the first
// non-loopback, non-docker, non-virtual IPv4 address.
func detectPrimaryIPFallback() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if !isRealInterface(iface) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			return ip.String()
		}
	}
	return ""
}

// detectInterfaceSubnets returns the IPv4 networks (CIDR, network address form
// e.g. "10.20.30.0/23") of the host's own real interfaces. The backend offers
// these as suggestions when the operator configures which subnets this sentinel
// should scan - so the suggestion is the exact local network, not a guess.
func detectInterfaceSubnets() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, iface := range ifaces {
		if !isRealInterface(iface) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			network := &net.IPNet{IP: ip.Mask(ipNet.Mask), Mask: ipNet.Mask}
			cidr := network.String()
			if _, dup := seen[cidr]; dup {
				continue
			}
			seen[cidr] = struct{}{}
			out = append(out, cidr)
		}
	}
	return out
}
