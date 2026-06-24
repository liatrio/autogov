package policy

import (
	"context"
	"strings"
)

// ResolveOptions configures path resolution behavior.
type ResolveOptions struct {
	// DefaultAsset is the default asset name used for ghrel:// resolution
	// (e.g., "bundle.tar.gz", "schemas.tar.gz"). Stabilizing this on the
	// dispatcher signature lets new schemes (OCI, ghrel) be added as
	// independent cases without changing resolveBundlePath's signature.
	// Consumed by the ghrel:// case to pick the release asset when the
	// reference omits an explicit ?asset= query.
	DefaultAsset string
	// ExpectedDigest, when non-empty, pins the SHA-256 of the downloaded
	// ghrel:// bundle archive (sha256:hex or bare hex). The ghrel resolver
	// hard-fails on a mismatch. It is an opt-in integrity check on the archive
	// bytes, distinct from the SLSA-aligned digest of the extracted contents
	// computed by CalculateDigest, and is only set for the bundle path (never
	// the schemas asset).
	ExpectedDigest string
}

// resolveBundlePath resolves a policy bundle/schemas path to a local directory.
// Returns the local path, a cleanup function (no-op for local dirs), and any error.
// Callers MUST call cleanup() when done (typically in Stop()).
//
// Each URI scheme is handled as an independent case so new schemes can be added
// without nesting if/else chains or duplicating logic.
func resolveBundlePath(ctx context.Context, path string, opts *ResolveOptions) (string, func(), error) {
	noop := func() {}

	// scheme prefixes are matched before the .tar.gz/.tgz suffix: a ghrel:// (or
	// oci://) reference can legitimately end in ".tar.gz" via its ?asset= query
	// (e.g. ghrel://owner/repo?asset=bundle.tar.gz), and must route by scheme, not
	// be mistaken for a local archive file.
	switch {
	case strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://"):
		return downloadBundle(ctx, path)
	case strings.HasPrefix(path, ociScheme):
		return pullOCIBundle(ctx, path)
	case strings.HasPrefix(path, ghrelScheme):
		// first (and only) case that consumes opts: DefaultAsset selects the
		// release asset and ExpectedDigest enforces archive integrity.
		return downloadGHReleaseBundle(ctx, path, opts)
	case strings.HasSuffix(path, ".tar.gz") || strings.HasSuffix(path, ".tgz"):
		return extractBundle(path)
	default:
		// local directory: nothing to download or extract, no cleanup needed
		return path, noop, nil
	}
}
