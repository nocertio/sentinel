//go:build linux

package filesystem

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSearchPathsIncludeKubernetesControlPlanePKI(t *testing.T) {
	paths := SearchPaths()
	assert.Contains(t, paths, "/etc/kubernetes/pki/")
	assert.Contains(t, paths, "/var/lib/kubelet/pki/")
	assert.Contains(t, paths, "/var/lib/rancher/k3s/server/tls/")
	assert.Contains(t, paths, "/var/lib/rancher/rke2/server/tls/")
}

func TestKubeletPodSecretMountsAreExcluded(t *testing.T) {
	// Secret volumes mounted into pods (tmpfs, root-only) contain private keys
	// next to certs; they must never be walked even if permissions would allow.
	assert.True(t, IsExcluded("/var/lib/kubelet/pods/9a1b/volumes/kubernetes.io~secret/tls/tls.crt"))
}
