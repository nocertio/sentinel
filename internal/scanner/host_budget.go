package scanner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"nocert.io/common/pkg/tlsprobe"
)

// hostBudget serializes connections to an IP across ports, SNI names and tasks.
// Idle entries expire after their cooldown; the map does not retain scan history.
type hostBudget struct {
	mu    sync.Mutex
	hosts map[netip.Addr]*hostSlot
}

type hostSlot struct {
	ready chan struct{}
	users int
	next  time.Time
}

func (b *hostBudget) acquire(ctx context.Context, ip netip.Addr, gap time.Duration) (func(), error) {
	ip = ip.Unmap()
	b.mu.Lock()
	if b.hosts == nil {
		b.hosts = make(map[netip.Addr]*hostSlot)
	}
	slot := b.hosts[ip]
	if slot == nil {
		slot = &hostSlot{ready: make(chan struct{}, 1)}
		slot.ready <- struct{}{}
		b.hosts[ip] = slot
	}
	slot.users++
	b.mu.Unlock()
	forget := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		slot.users--
		if slot.users == 0 {
			delay := time.Until(slot.next)
			if delay <= 0 {
				delete(b.hosts, ip)
				return
			}
			time.AfterFunc(delay, func() {
				b.mu.Lock()
				defer b.mu.Unlock()
				if b.hosts[ip] == slot && slot.users == 0 && !time.Now().Before(slot.next) {
					delete(b.hosts, ip)
				}
			})
		}
	}
	select {
	case <-ctx.Done():
		forget()
		return nil, ctx.Err()
	case <-slot.ready:
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			b.mu.Lock()
			slot.next = time.Now().Add(gap)
			b.mu.Unlock()
			slot.ready <- struct{}{}
			forget()
		})
	}
	delay := time.Until(slot.next)
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			release()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

type budgetConn struct {
	net.Conn
	release func()
}

func (c *budgetConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

type scanDialer struct {
	hosts *hostBudget
	ticks <-chan time.Time
	gap   time.Duration
}

func (d *scanDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.DialContextWithTimeout(ctx, network, address, 5*time.Second)
}

func (d *scanDialer) DialContextWithTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		// Resolve before admission so aliases cannot bypass the destination-IP limit.
		dnsCtx, cancel := context.WithTimeout(ctx, timeout)
		ips, err = net.DefaultResolver.LookupNetIP(dnsCtx, "ip", host)
		cancel()
		if err != nil {
			return nil, err
		}
	}
	if len(ips) > 16 {
		ips = ips[:16]
	}
	lastErr := errors.New("no destination addresses")
	for _, ip := range ips {
		release, err := d.hosts.acquire(ctx, ip, d.gap)
		if err != nil {
			return nil, err
		}
		limited := &rateLimitedDialer{base: &net.Dialer{}, ticks: d.ticks}
		conn, err := tlsprobe.DialContext(ctx, limited, network, net.JoinHostPort(ip.String(), port), timeout)
		if err == nil {
			return &budgetConn{Conn: conn, release: release}, nil
		}
		release()
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// Interleave ports and SNI names across hosts to spread admission waits.
func interleaveTargets(targets []target) []target {
	groups := make(map[string][]target)
	var hosts []string
	seen := make(map[target]struct{}, len(targets))
	for _, t := range targets {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		if _, exists := groups[t.host]; !exists {
			hosts = append(hosts, t.host)
		}
		groups[t.host] = append(groups[t.host], t)
	}
	out := make([]target, 0, len(targets))
	for len(hosts) > 0 {
		remaining := hosts[:0]
		for _, host := range hosts {
			group := groups[host]
			out = append(out, group[0])
			if len(group) > 1 {
				groups[host] = group[1:]
				remaining = append(remaining, host)
			}
		}
		hosts = remaining
	}
	return out
}
