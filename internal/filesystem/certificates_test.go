//go:build linux

package filesystem

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
	"nocert.io/sentinel/internal/testutil"
)

func TestUnusualCertificates(t *testing.T) {
	t.Setenv("GODEBUG", "x509negativeserial=0")
	for _, tc := range testutil.UnusualCertificates(t) {
		t.Run(tc.Name, func(t *testing.T) {
			der := tc.Certificate.Certificate[0]
			_, err := x509.ParseCertificate(der)
			require.Equal(t, tc.Parseable, err == nil, "fixture parseability")
			for _, data := range [][]byte{der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})} {
				ders, complete := extractCertDER(data)
				require.True(t, complete)
				require.Equal(t, [][]byte{der}, ders)
			}
		})
	}
}

func TestMalformedBundleRetainsFollowingCertificate(t *testing.T) {
	der := testutil.Certificate(t, nil).Certificate[0]
	for _, broken := range [][]byte{der[:len(der)-1], {0x30, 0x82, 0, 1, 0}} {
		bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: broken})
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		ders, complete := extractCertDER(bundle)
		require.True(t, complete)
		require.Equal(t, [][]byte{der}, ders)
	}
}
