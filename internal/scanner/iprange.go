package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
)

// MinCIDRPrefix bounds expansion memory: prefixes shorter than /16 are rejected.
const MinCIDRPrefix = 16

// ExpandCIDR returns all host addresses in the given CIDR range.
// For example, "10.0.0.0/30" yields [10.0.0.1, 10.0.0.2].
// A /32 yields a single address. IPv6 is not supported.
// Ranges broader than /16 are rejected to prevent resource exhaustion.
func ExpandCIDR(cidr string) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parsing CIDR %q: %w", cidr, err)
	}

	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("IPv6 not supported: %s", cidr)
	}

	mask := ipnet.Mask
	ones, bits := mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("unexpected mask size: %d", bits)
	}

	if ones < MinCIDRPrefix {
		return nil, fmt.Errorf("CIDR range %s too large (/%d), minimum prefix is /%d", cidr, ones, MinCIDRPrefix)
	}

	// /32 is a single host
	if ones == 32 {
		return []net.IP{ip}, nil
	}

	hostCount := uint32(1) << (32 - ones)

	start := uint32(1)
	end := hostCount - 1
	if ones == 31 {
		// /31 point-to-point: both addresses are usable
		start = 0
		end = hostCount
	}

	networkIP := binary.BigEndian.Uint32(ipnet.IP.To4())
	results := make([]net.IP, 0, end-start)

	for i := start; i < end; i++ {
		hostIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(hostIP, networkIP+i)
		results = append(results, hostIP)
	}

	return results, nil
}
