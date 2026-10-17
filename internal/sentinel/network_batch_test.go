package sentinel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"nocert.io/sentinel/internal/scanner"
)

func TestNetworkBatchesStayWithinBodyLimit(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(fmt.Sprint("local=", local), func(t *testing.T) {
			rr := &reportRecorder{accept: true}
			s := newTestSentinelWithClient(t, rr.server(t), true)
			outputs := make(chan scanner.ProbeOutput, 20)
			// Each endpoint has a large, distinct leaf and nine shared chain certs.
			// A new batch must include the shared certificates again.
			shared := make([][]byte, 9)
			for i := range shared {
				shared[i] = bytes.Repeat([]byte{byte(i)}, 64*1024)
			}
			for i := range 20 {
				chain := append([][]byte{bytes.Repeat([]byte{byte(i + 20)}, 64*1024)}, shared...)
				// Distinct chains ensure even a batch smaller than 50 exceeds 5 MiB.
				for j := 1; j < 5; j++ {
					chain[j] = bytes.Repeat([]byte{byte(50 + i*5 + j)}, 64*1024)
				}
				outputs <- scanner.ProbeOutput{IP: "192.0.2.1", Port: 443 + i, Chain: chain}
			}
			close(outputs)
			s.collectAndPushNetwork(context.Background(), outputs, "task", &scanner.ScanMeta{StartedAt: time.Now()}, local, true)
			total := 0
			for _, report := range rr.reports {
				body, err := json.Marshal(report)
				require.NoError(t, err)
				require.LessOrEqual(t, len(body), 5<<20)
				certs := make(map[string]bool)
				for _, cert := range report.Certificates {
					certs[cert.FingerprintSHA256] = true
				}
				observations := append(report.NetworkObservations, report.LocalObservations...)
				for _, obs := range observations {
					for _, fp := range obs.ObservedChainFingerprints {
						require.True(t, certs[fp], "chain certificate missing from its batch")
					}
				}
				total += len(observations)
			}
			require.Equal(t, 20, total)
			require.Greater(t, len(rr.reports), 2)
		})
	}
}
