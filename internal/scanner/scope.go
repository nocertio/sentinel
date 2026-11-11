package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
)

// MinCIDRPrefix is the broadest range accepted by the scan configuration.
const MinCIDRPrefix = 16

// Scope stores the union of usable IPv4 addresses, not an expanded target list.
// Limits match the backend configuration contract.
type Scope struct {
	ranges []ipSpan
	ports  []int
	hosts  int
}

type ipSpan struct{ first, last uint32 }

func NewScope(cidrs []string, ports []int) (*Scope, error) {
	if len(cidrs) > 64 || len(ports) > 32 {
		return nil, fmt.Errorf("scan scope exceeds configuration limits")
	}
	s := &Scope{}
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() < MinCIDRPrefix {
			return nil, fmt.Errorf("invalid IPv4 scan range")
		}
		addr := prefix.Masked().Addr().As4()
		first := binary.BigEndian.Uint32(addr[:])
		last := first | uint32((uint64(1)<<(32-prefix.Bits()))-1)
		if prefix.Bits() < 31 {
			first++
			last--
		}
		s.ranges = append(s.ranges, ipSpan{first, last})
	}
	slices.SortFunc(s.ranges, func(a, b ipSpan) int {
		if a.first < b.first {
			return -1
		}
		if a.first > b.first {
			return 1
		}
		return 0
	})
	merged := s.ranges[:0]
	for _, r := range s.ranges {
		if len(merged) > 0 && uint64(r.first) <= uint64(merged[len(merged)-1].last)+1 {
			prev := &merged[len(merged)-1]
			prev.last = max(prev.last, r.last)
		} else {
			merged = append(merged, r)
		}
	}
	s.ranges = merged
	for _, r := range s.ranges {
		s.hosts += int(uint64(r.last) - uint64(r.first) + 1)
	}
	s.ports = slices.Clone(ports)
	for _, port := range s.ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid scan port")
		}
	}
	slices.Sort(s.ports)
	s.ports = slices.Compact(s.ports)
	return s, nil
}

func (s *Scope) TotalTargets() int { return s.hosts * len(s.ports) }

// Fingerprint identifies both the scope and the traversal order for checkpoints.
func (s *Scope) Fingerprint() string {
	h := sha256.New()
	_, _ = h.Write([]byte("ipv4-scope-v1"))
	var b [8]byte
	binary.BigEndian.PutUint32(b[:4], uint32(len(s.ranges)))
	binary.BigEndian.PutUint32(b[4:], uint32(len(s.ports)))
	_, _ = h.Write(b[:])
	for _, r := range s.ranges {
		binary.BigEndian.PutUint32(b[:4], r.first)
		binary.BigEndian.PutUint32(b[4:], r.last)
		_, _ = h.Write(b[:])
	}
	for _, port := range s.ports {
		binary.BigEndian.PutUint32(b[:4], uint32(port))
		_, _ = h.Write(b[:4])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// targetAt traverses every host for one port before moving to the next port.
// Adjacent work is spread across IPs without allocating or shuffling the space.
func (s *Scope) targetAt(offset int) target {
	host := offset % s.hosts
	for _, r := range s.ranges {
		count := int(uint64(r.last) - uint64(r.first) + 1)
		if host < count {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], r.first+uint32(host))
			return target{host: netip.AddrFrom4(b).String(), port: s.ports[offset/s.hosts]}
		}
		host -= count
	}
	panic("scan scope offset out of bounds")
}

// ScanScopeBatch probes a bounded part of a scope using the normal connection
// budgets. The caller advances offset only after draining and accepting results.
func (s *Scanner) ScanScopeBatch(ctx context.Context, scope *Scope, offset int) (<-chan ProbeOutput, *ScanMeta) {
	if offset < 0 || offset >= scope.TotalTargets() {
		return s.ScanStream(ctx, ScanConfig{batch: true})
	}
	size := DefaultWorkers
	if s.gentle.Load() {
		size = 5
	}
	end := min(scope.TotalTargets(), offset+size)
	targets := make([]target, 0, max(0, end-offset))
	for i := offset; i < end; i++ {
		targets = append(targets, scope.targetAt(i))
	}
	return s.ScanStream(ctx, ScanConfig{Targets: targets, batch: true})
}
