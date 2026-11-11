package sentinel

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"time"

	"nocert.io/sentinel/internal/transport"
)

// requestDelay keeps normal polls near their configured interval. Failures use
// bounded exponential backoff; server guidance is a minimum, not a retry target
// shared by every agent. No scheduling decision depends on error text.
func requestDelay(interval time.Duration, failures int, err error) time.Duration {
	lower, upper := interval, interval
	if err == nil {
		spread := interval / 10
		lower -= spread
		upper += min(spread, time.Duration(math.MaxInt64)-interval)
	} else {
		ceiling := max(interval, 5*time.Minute)
		for i := 0; i < failures && upper < ceiling; i++ {
			upper += min(upper, ceiling-upper)
		}
		lower = max(interval, upper/2)
	}
	delay := lower + time.Duration(rand.Int64N(int64(upper-lower)+1))
	var status *transport.HTTPError
	if errors.As(err, &status) {
		floor := min(status.RetryAfter, time.Hour)
		if floor > delay {
			extra := min(floor/10, time.Second)
			delay = floor + time.Duration(rand.Int64N(int64(extra)+1))
		}
	}
	return delay
}

func (s *Sentinel) pollLoop(ctx context.Context) error {
	failures := 0
	poll := func() time.Duration {
		err := s.pollOnce(ctx)
		s.trackPollResult(err, "poll failed")
		if err == nil {
			failures = 0
		} else if failures < 64 {
			failures++
		}
		return requestDelay(s.cfg.PollingInterval, failures, err)
	}
	// The first poll stays immediate for onboarding. Subsequent waits start after
	// the response/tasks, so a timeout cannot leave a ticker ready for an instant retry.
	timer := time.NewTimer(poll())
	defer timer.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		if s.sweep != nil && !time.Now().Before(s.sweep.retryAfter) {
			select {
			case <-timer.C:
				timer.Reset(poll())
			default:
				s.runSweepBatch(ctx)
			}
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			timer.Reset(poll())
		}
	}
}
