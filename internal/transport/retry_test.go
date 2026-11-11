package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"nocert.io/common/pkg/httpsig"
)

type retryRoundTripper func(*http.Request) (*http.Response, error)

func (f retryRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestReportHonorsRetryAfterAndResigns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		agentKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
		serverKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
		c := NewClient("https://backend.invalid", "agent", "agent-key", agentKey, serverKey.Public().(ed25519.PublicKey), "server-key", "test", slog.Default())
		var arrivals, notBefore []time.Time
		nonces := map[string]bool{}
		c.httpClient.Transport = retryRoundTripper(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			_ = r.Body.Close()
			if r.Header.Get("Content-Digest") != httpsig.ContentDigest(body) {
				t.Fatal("retry changed the signed body digest")
			}
			if err := httpsig.VerifyRequest(r, agentKey.Public().(ed25519.PublicKey), "agent-key", nil); err != nil {
				t.Fatal(err)
			}
			details, err := httpsig.RequestDetails(r)
			if err != nil {
				t.Fatal(err)
			}
			if nonces[details.Nonce] {
				t.Fatal("retry reused a signed nonce")
			}
			nonces[details.Nonce] = true
			arrivals = append(arrivals, time.Now())
			response := &http.Response{StatusCode: 429, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("untrusted diagnostic")), Request: r}
			switch len(arrivals) {
			case 1:
				response.Header.Set("Retry-After", "120")
				notBefore = append(notBefore, time.Now().Add(120*time.Second))
			case 2:
				response.StatusCode = 503
				date := time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat)
				response.Header.Set("Retry-After", date)
				parsed, _ := http.ParseTime(date)
				notBefore = append(notBefore, parsed)
			default:
				response.StatusCode = 202
				reply := []byte(`{"accepted":true}`)
				digest, input, sig := httpsig.SignResponse(202, reply, details.Nonce, serverKey, "server-key")
				response.Header.Set("Content-Digest", digest)
				response.Header.Set("Signature-Input", input)
				response.Header.Set("Signature", sig)
				response.Body = io.NopCloser(bytes.NewReader(reply))
			}
			return response, nil
		})
		if err := c.PostReport(context.Background(), &ReportRequest{}); err != nil {
			t.Fatal(err)
		}
		if len(arrivals) != 3 {
			t.Fatalf("got %d attempts", len(arrivals))
		}
		for i, floor := range notBefore {
			if delta := arrivals[i+1].Sub(floor); delta < 0 || delta > time.Second {
				t.Fatalf("retry %d differs from server minimum by %s", i+1, delta)
			}
		}
	})
}

func TestReportRetryAfterCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key := ed25519.NewKeyFromSeed(make([]byte, 32))
		c := NewClient("https://backend.invalid", "agent", "key", key, key.Public().(ed25519.PublicKey), "key", "test", slog.Default())
		calls := 0
		c.httpClient.Transport = retryRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			_ = r.Body.Close()
			return &http.Response{StatusCode: 503, Header: http.Header{"Retry-After": []string{"120"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		time.AfterFunc(2*time.Second, cancel)
		if err := c.PostReport(ctx, &ReportRequest{}); !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
		if calls != 1 {
			t.Fatalf("got %d requests after cancellation", calls)
		}
	})
}

func TestRetryAfterBoundsAndClassification(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, value := range []string{"-1", "0", "3601", "9999999999999999999999", "garbage", time.Now().Add(2 * time.Hour).UTC().Format(http.TimeFormat), time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat)} {
			if got := parseRetryAfter(value); got != 0 {
				t.Errorf("%q = %s", value, got)
			}
		}
		for _, value := range []string{"120", time.Now().Add(2 * time.Minute).UTC().Format(http.TimeFormat)} {
			if got := parseRetryAfter(value); got != 2*time.Minute {
				t.Errorf("%q = %s", value, got)
			}
		}
		for _, status := range []int{302, 400, 401, 403, 404, 429, 500, 503, 599} {
			e := responseError(&http.Response{StatusCode: status, Header: http.Header{"Retry-After": []string{"120"}}})
			if Retryable(e) != (status == 429 || status >= 500) {
				t.Errorf("retry classification for %d", status)
			}
			want := time.Duration(0)
			if status == 429 || status == 503 {
				want = 2 * time.Minute
			}
			if e.RetryAfter != want {
				t.Errorf("retry guidance for %d: %s", status, e.RetryAfter)
			}
		}
	})
	if Retryable(errors.New("proxy body says status 503")) {
		t.Fatal("error text controlled retry classification")
	}
}

func TestRetryAfterSurvivesExhaustedReportAttempts(t *testing.T) {
	old := reportMaxAttempts
	reportMaxAttempts = 1
	t.Cleanup(func() { reportMaxAttempts = old })
	synctest.Test(t, func(t *testing.T) {
		key := ed25519.NewKeyFromSeed(make([]byte, 32))
		c := NewClient("https://backend.invalid", "agent", "key", key, key.Public().(ed25519.PublicKey), "key", "test", slog.Default())
		calls := 0
		started := time.Now()
		c.httpClient.Transport = retryRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Body != nil {
				_ = r.Body.Close()
			}
			if calls == 2 && time.Since(started) < 120*time.Second {
				t.Fatal("new call bypassed Retry-After")
			}
			details, err := httpsig.RequestDetails(r)
			if err != nil {
				t.Fatal(err)
			}
			if details.Created != time.Now().Unix() {
				t.Fatal("request signed before cooldown ended")
			}
			return &http.Response{StatusCode: 503, Header: http.Header{"Retry-After": []string{"120"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		})
		if err := c.PostReport(context.Background(), &ReportRequest{}); !Retryable(err) {
			t.Fatalf("got %v", err)
		}
		if time.Since(started) != 0 {
			t.Fatal("last report failure should return without an unused retry wait")
		}
		_, _ = c.GetTasks(context.Background())
		if calls != 2 {
			t.Fatalf("got %d calls", calls)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		time.AfterFunc(2*time.Second, cancel)
		if _, err := c.GetTasks(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
		if calls != 2 {
			t.Fatal("request sent after cancellation during shared cooldown")
		}
	})
}
