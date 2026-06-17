package policy

import (
	"context"
	"strings"
)

// ResolveOptions configures path resolution behavior.
type ResolveOptions struct {
	// DefaultAsset is the default asset name used for ghrel:// resolution
	// (e.g., "bundle.tar.gz", "schemas.tar.gz"). Introduced now to stabilize
	// the dispatcher signature so future schemes (OCI, ghrel) can be added as
	// independent cases without changing resolveBundlePath's signature. Not yet
	// consumed by any implemented scheme (reserved for the ghrel:// case).
	DefaultAsset string
}

// resolveBundlePath resolves a policy bundle/schemas path to a local directory.
// Returns the local path, a cleanup function (no-op for local dirs), and any error.
// Callers MUST call cleanup() when done (typically in Stop()).
//
// Each URI scheme is handled as an independent case so new schemes can be added
// without nesting if/else chains or duplicating logic.
func resolveBundlePath(ctx context.Context, path string, opts *ResolveOptions) (string, func(), error) {
	noop := func() {}

	switch {
	case strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://"):
		return downloadBundle(ctx, path)
	case strings.HasSuffix(path, ".tar.gz") || strings.HasSuffix(path, ".tgz"):
		return extractBundle(path)
	case strings.HasPrefix(path, ociScheme):
		return pullOCIBundle(ctx, path)
	// Future: case strings.HasPrefix(path, "ghrel://"):
	default:
		// local directory: nothing to download or extract, no cleanup needed
		return path, noop, nil
	}
}
