package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestScopeUnionAndAddressBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name  string
		cidrs []string
		want  []string
	}{
		{"nested", []string{"10.0.0.0/29", "10.0.0.0/30", "10.0.0.3/32"}, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"}},
		{"adjacent network boundaries", []string{"10.0.0.0/30", "10.0.0.4/30"}, []string{"10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.6"}},
		{"point to point and host", []string{"10.0.0.0/31", "10.0.0.1/32", "10.0.0.2/32"}, []string{"10.0.0.0", "10.0.0.1", "10.0.0.2"}},
		{"last address", []string{"255.255.255.255/32", "255.255.255.254/31"}, []string{"255.255.255.254", "255.255.255.255"}},
		{"host bits", []string{"10.0.0.2/30"}, []string{"10.0.0.1", "10.0.0.2"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scope, err := NewScope(tt.cidrs, []int{8443, 443, 443})
			require.NoError(t, err)
			require.Equal(t, len(tt.want)*2, scope.TotalTargets())
			for p, port := range []int{443, 8443} {
				for i, host := range tt.want {
					require.Equal(t, target{host: host, port: port}, scope.targetAt(p*len(tt.want)+i))
				}
			}
		})
	}
}

func TestScopeExhaustiveBeyondFormerCap(t *testing.T) {
	scope, err := NewScope([]string{"10.0.0.0/16", "10.1.0.0/16", "10.0.0.0/24"}, []int{443, 8443})
	require.NoError(t, err)
	require.Equal(t, 2*65534*2, scope.TotalTargets())
	seen := make(map[target]bool, scope.TotalTargets())
	for offset := 0; offset < scope.TotalTargets(); offset++ {
		tgt := scope.targetAt(offset)
		if seen[tgt] {
			t.Fatalf("duplicate at %d: %+v", offset, tgt)
		}
		seen[tgt] = true
	}
	require.True(t, seen[target{host: "10.1.255.254", port: 8443}])
	require.Len(t, scope.ranges, 2)
}

func TestScopeValidationAndStableCheckpointOrder(t *testing.T) {
	a, err := NewScope([]string{"10.0.0.0/29", "10.0.0.0/30"}, []int{8443, 443, 443})
	require.NoError(t, err)
	b, err := NewScope([]string{"10.0.0.0/29"}, []int{443, 8443})
	require.NoError(t, err)
	require.Equal(t, a.Fingerprint(), b.Fingerprint())
	c, err := NewScope([]string{"10.0.0.0/29"}, []int{443})
	require.NoError(t, err)
	require.NotEqual(t, a.Fingerprint(), c.Fingerprint())
	for _, cidr := range []string{"bad", "::/128", "::ffff:192.0.2.1/128", "10.0.0.0/15"} {
		_, err := NewScope([]string{cidr}, []int{443})
		require.Error(t, err)
	}
	for _, port := range []int{-1, 0, 65536} {
		_, err := NewScope([]string{"10.0.0.1/32"}, []int{port})
		require.Error(t, err)
	}
	_, err = NewScope(make([]string, 65), []int{443})
	require.Error(t, err)
	_, err = NewScope(nil, make([]int, 33))
	require.Error(t, err)
}

func TestScopeBatchesUseProfileAndHonorCancellation(t *testing.T) {
	scope, err := NewScope([]string{"10.0.0.0/24"}, []int{443})
	require.NoError(t, err)
	s := NewWithProber(slog.Default(), &mockProber{})
	for _, gentle := range []bool{false, true} {
		t.Run(fmt.Sprint(gentle), func(t *testing.T) {
			s.SetGentle(gentle)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			ch, meta := s.ScanScopeBatch(ctx, scope, 0)
			want := DefaultWorkers
			if gentle {
				want = 5
			}
			require.Equal(t, want, meta.TotalTargets)
			select {
			case _, ok := <-ch:
				require.False(t, ok)
			case <-time.After(time.Second):
				t.Fatal("canceled batch did not drain")
			}
		})
	}
}

func TestExplicitTargetsDeduplicateWithoutMergingSNI(t *testing.T) {
	a := target{host: "192.0.2.1", port: 443, serverName: "a.example"}
	b := target{host: "192.0.2.1", port: 443, serverName: "b.example"}
	require.Equal(t, []target{a, b}, interleaveTargets([]target{a, a, b, a}))
}

func TestScopeMaximumConfigurationRemainsCompact(t *testing.T) {
	cidrs := make([]string, 64)
	for i := range cidrs {
		cidrs[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}
	ports := make([]int, 32)
	for i := range ports {
		ports[i] = i + 1
	}
	scope, err := NewScope(cidrs, ports)
	require.NoError(t, err)
	require.Equal(t, 64*65534*32, scope.TotalTargets())
	require.Len(t, scope.ranges, 64)
	require.Equal(t, target{host: "10.63.255.254", port: 32}, scope.targetAt(scope.TotalTargets()-1))
}
