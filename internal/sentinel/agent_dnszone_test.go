package sentinel

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonsentinel "nocert.io/common/pkg/api/sentinel"
	"nocert.io/sentinel/internal/transport"
)

func dnsTask(t *testing.T, p commonsentinel.DNSZoneTransferPayload) transport.TaskResponse {
	t.Helper()
	payload, err := json.Marshal(p)
	require.NoError(t, err)
	return transport.TaskResponse{ID: "task-dns", Type: commonsentinel.TaskTypeDNSZoneTransfer, Payload: payload}
}

// Either local switch refuses the task: the names it yields only ever feed
// network scans, which allow_network_scan: false forbids anyway.
func TestDNSZoneTransferRefusedLocallyProducesNoReport(t *testing.T) {
	for _, tc := range []struct{ dns, network bool }{{false, true}, {true, false}} {
		rec := &reportRecorder{}
		s := newTestSentinelWithClient(t, rec.server(t), tc.network)
		s.cfg.AllowDNSZoneTransfer = boolPtr(tc.dns)

		task := dnsTask(t, commonsentinel.DNSZoneTransferPayload{Zones: []commonsentinel.DNSZone{{Name: "corp.lan", Server: "192.0.2.1"}}})
		require.NoError(t, s.dispatchTask(context.Background(), task))
		assert.Empty(t, rec.statuses, "dns=%v network=%v", tc.dns, tc.network)
	}
}

// Without any zone the task still reports the resolver settings: that report
// is how the backend learns which zones to suggest.
func TestDNSZoneTransferWithoutZonesReportsResolver(t *testing.T) {
	rec := &reportRecorder{accept: true}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	s.cfg.AllowDNSZoneTransfer = boolPtr(true)

	require.NoError(t, s.dispatchTask(context.Background(), dnsTask(t, commonsentinel.DNSZoneTransferPayload{})))
	require.Len(t, rec.reports, 1)
	report := rec.reports[0]
	assert.Equal(t, "task-dns", report.TaskID)
	assert.Equal(t, commonsentinel.ReportStatusCompleted, report.Status)
	require.NotNil(t, report.DNSResolver)
	assert.Empty(t, report.DNSZones)
}

func TestDNSZoneTransferReportsOneResultPerZone(t *testing.T) {
	rec := &reportRecorder{accept: true}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	s.cfg.AllowDNSZoneTransfer = boolPtr(true)

	// Neither entry dials anything: an unspecified server and a wildcard zone
	// are both refused before the connection.
	zones := []commonsentinel.DNSZone{{Name: "corp.lan", Server: "0.0.0.0"}, {Name: "*.bad", Server: "192.0.2.1"}}
	require.NoError(t, s.dispatchTask(context.Background(), dnsTask(t, commonsentinel.DNSZoneTransferPayload{Zones: zones, TLSAddresses: []string{"10.0.0.5", "not-an-ip"}})))
	require.Len(t, rec.reports, 1)
	report := rec.reports[0]
	require.NotNil(t, report.DNSResolver)
	require.Len(t, report.DNSZones, 2)
	assert.Equal(t, commonsentinel.DNSZoneResult{Name: "corp.lan", Server: "0.0.0.0", Status: commonsentinel.DNSZoneStatusFailed}, report.DNSZones[0])
	assert.Equal(t, commonsentinel.DNSZoneStatusFailed, report.DNSZones[1].Status)
}

func TestDNSZoneTransferBadPayloadReportsFailed(t *testing.T) {
	rec := &reportRecorder{accept: true}
	s := newTestSentinelWithClient(t, rec.server(t), true)
	s.cfg.AllowDNSZoneTransfer = boolPtr(true)

	task := transport.TaskResponse{ID: "task-dns", Type: commonsentinel.TaskTypeDNSZoneTransfer, Payload: json.RawMessage(`{"zones":"x"}`)}
	require.Error(t, s.dispatchTask(context.Background(), task))
	assert.Equal(t, []string{commonsentinel.ReportStatusFailed}, rec.statuses)
}
