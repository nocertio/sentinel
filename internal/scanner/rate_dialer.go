package scanner

import (
	"context"
	"net"
	"time"

	"nocert.io/common/pkg/tlsprobe"
)

type rateLimitedDialer struct {
	base  tlsprobe.ContextDialer
	ticks <-chan time.Time
}

func (d *rateLimitedDialer) wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.ticks:
	}
	return ctx.Err()
}

func (d *rateLimitedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := d.wait(ctx); err != nil {
		return nil, err
	}
	return d.base.DialContext(ctx, network, addr)
}

func (d *rateLimitedDialer) DialContextWithTimeout(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	if err := d.wait(ctx); err != nil {
		return nil, err
	}
	return tlsprobe.DialContext(ctx, d.base, network, addr, timeout)
}
