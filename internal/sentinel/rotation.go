package sentinel

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"nocert.io/sentinel/internal/keystore"
	"nocert.io/sentinel/internal/transport"
)

func (s *Sentinel) keyRotationLoop(ctx context.Context) error {
	first, failures := true, 0
	delay := time.Duration(0)
	for waitForRotation(ctx, delay) {
		kf, err := s.store.Load()
		retry := err != nil
		if err == nil && kf.NeedsRotation(s.cfg.KeyRotationMargin) {
			if first && !waitForRotation(ctx, rotationStartupDelay(s.cfg.KeyRotationCheckInterval, kf.KeyExpiresAt)) {
				return nil
			}
			retry, err = s.rotateKey(ctx, kf)
		}
		first = false
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			failures = 0
		} else {
			if failures == 0 {
				// Proxy bodies and transport diagnostics stay out of local logs.
				var status *transport.HTTPError
				if errors.As(err, &status) {
					s.logger.Warn("key rotation failed", "status", status.StatusCode)
				} else {
					s.logger.Warn("key rotation failed")
				}
			}
			if failures < 64 {
				failures++
			}
		}
		delay = requestDelay(s.cfg.KeyRotationCheckInterval, 0, nil)
		if retry {
			delay = requestDelay(min(s.cfg.KeyRotationCheckInterval, time.Minute), failures, err)
		}
		// Check again before expiry, including with unusually long configured
		// intervals. A server-requested wait still takes precedence.
		if kf != nil && (err == nil || retry) {
			remaining := time.Until(kf.KeyExpiresAt)
			if remaining > 0 && delay > remaining/2 {
				delay = requestDelay(max(time.Second, remaining/4), 0, err)
			}
		}
	}
	return nil
}

func rotationStartupDelay(interval time.Duration, expires time.Time) time.Duration {
	remaining := time.Until(expires)
	if remaining <= time.Minute {
		return 0 // May also be a held key still accepted during the server's grace.
	}
	spread := min(time.Minute, interval/10, remaining/4)
	return time.Duration(rand.Int64N(int64(spread) + 1))
}

func waitForRotation(ctx context.Context, delay time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	}
}

// rotateKey returns whether a failure can be retried soon. A rejected identity
// or unverifiable response keeps the normal check interval.
func (s *Sentinel) rotateKey(ctx context.Context, kf *keystore.KeyFile) (bool, error) {
	newPrivB64, newPubB64, err := keystore.GenerateKeyPair()
	if err != nil {
		return true, err
	}
	rotated := *kf
	rotated.PrivateKey, rotated.PublicKey = newPrivB64, newPubB64
	newPriv, err := rotated.PrivateKeyBytes()
	if err != nil {
		return true, err
	}
	resp, err := s.client.RotateKey(ctx, newPubB64)
	if err != nil {
		return transport.Retryable(err), err
	}
	rotated.KeyID, rotated.KeyExpiresAt = resp.KeyID, resp.KeyExpiresAt
	if err := s.store.Save(&rotated); err != nil {
		return true, err
	}
	s.client.UpdateCredentials(rotated.KeyID, newPriv)
	*kf = rotated
	s.logger.Info("key rotation successful")
	return false, nil
}
