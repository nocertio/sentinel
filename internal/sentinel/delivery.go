package sentinel

import (
	"context"
	"time"

	"nocert.io/sentinel/internal/transport"
)

// Retain the current targeted-scan batch while delivery is unavailable. The
// collector stops reading, so scanner buffers apply backpressure. New tasks
// are not fetched until this scan finishes; no separate report queue is needed.
func (s *Sentinel) postTargetedReport(ctx context.Context, report *transport.ReportRequest) error {
	interval := s.cfg.PollingInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	failures := 0
	for {
		err := s.client.PostReport(ctx, report)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil || !transport.Retryable(err) {
			return err
		}
		if failures == 0 {
			s.logger.Warn("report delivery delayed; retaining current batch", "task_id", report.TaskID)
		}
		if failures < 64 {
			failures++
		}
		timer := time.NewTimer(requestDelay(interval, failures, err))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
