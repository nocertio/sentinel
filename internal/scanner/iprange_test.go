package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandCIDR_Single(t *testing.T) {
	ips, err := ExpandCIDR("10.0.0.1/32")
	require.NoError(t, err)
	require.Len(t, ips, 1)
	assert.Equal(t, "10.0.0.1", ips[0].String())
}

func TestExpandCIDR_Slash30(t *testing.T) {
	ips, err := ExpandCIDR("10.0.0.0/30")
	require.NoError(t, err)
	// /30 = 4 addresses, minus network and broadcast = 2 usable hosts
	require.Len(t, ips, 2)
	assert.Equal(t, "10.0.0.1", ips[0].String())
	assert.Equal(t, "10.0.0.2", ips[1].String())
}

func TestExpandCIDR_Slash24(t *testing.T) {
	ips, err := ExpandCIDR("192.168.1.0/24")
	require.NoError(t, err)
	// /24 = 256 addresses, minus network and broadcast = 254 usable hosts
	assert.Len(t, ips, 254)
	assert.Equal(t, "192.168.1.1", ips[0].String())
	assert.Equal(t, "192.168.1.254", ips[len(ips)-1].String())
}

func TestExpandCIDR_Slash31(t *testing.T) {
	ips, err := ExpandCIDR("10.0.0.0/31")
	require.NoError(t, err)
	// /31 point-to-point: both addresses are usable (RFC 3021)
	require.Len(t, ips, 2)
	assert.Equal(t, "10.0.0.0", ips[0].String())
	assert.Equal(t, "10.0.0.1", ips[1].String())
}

func TestExpandCIDR_Invalid(t *testing.T) {
	_, err := ExpandCIDR("not-a-cidr")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing CIDR")
}

func TestExpandCIDR_IPv6Rejected(t *testing.T) {
	_, err := ExpandCIDR("::1/128")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IPv6 not supported")
}

func TestExpandCIDR_TooLargeRejected(t *testing.T) {
	// /8 = 16 million hosts, must be rejected to prevent memory exhaustion
	_, err := ExpandCIDR("10.0.0.0/8")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")

	// /0 = 4 billion hosts
	_, err = ExpandCIDR("0.0.0.0/0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")

	// /15 is just below the limit
	_, err = ExpandCIDR("10.0.0.0/15")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")

	// /16 is the minimum allowed and should succeed
	ips, err := ExpandCIDR("10.0.0.0/16")
	require.NoError(t, err)
	assert.Len(t, ips, 65534) // 2^16 - 2 (minus network and broadcast)
}
