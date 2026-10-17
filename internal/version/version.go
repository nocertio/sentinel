package version

import "fmt"

// Version is injected at release time via -ldflags. The fallback marks a binary
// built directly from source rather than from a tagged release; the backend does
// not send an agent task types its version cannot run. It is the only build-time
// value stamped into the binary: commit and build date are deliberately omitted
// so a client rebuilding from the published source archive gets a byte-for-byte
// identical binary (see README.md).
var Version = "0.0.0-dev"

func String() string {
	return fmt.Sprintf("nocert-sentinel %s", Version)
}
