package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	gogithub "github.com/google/go-github/v88/github"

	"github.com/liatrio/autogov/pkg/digest"
	"github.com/liatrio/autogov/pkg/github"
)

const (
	// ghrelScheme is the URI prefix that routes a bundle path to the GitHub
	// release-asset downloader.
	ghrelScheme = "ghrel://"
	// ghReleaseRetryAttempts bounds the release-resolution retry budget (AC10).
	ghReleaseRetryAttempts = 3
)

// maxGHReleaseAssetSize bounds how many bytes the downloader buffers for a
// single release asset. A GitHub asset's declared size (ReleaseAsset.Size) is
// advisory, so the io.LimitReader cap is the real guard against an oversized
// download exhausting memory. Policy bundles are KB-MB; 128 MiB is generous
// headroom. A var (not const) so tests can lower it to exercise the guard.
var maxGHReleaseAssetSize int64 = 128 << 20

// ghReleaseRetryBackoff is the base delay between release-resolution retries;
// attempt N waits backoff*2^(N-1) (1s, 2s with the default). A var (not const)
// so tests can shrink it and exercise the retry path without real sleeps.
var ghReleaseRetryBackoff = 1 * time.Second

// ghRef is a parsed ghrel:// reference. Tag is empty for the latest release;
// Asset is empty when the reference omits ?asset= (the resolver then falls back
// to ResolveOptions.DefaultAsset).
type ghRef struct {
	Owner string
	Repo  string
	Tag   string
	Asset string
}

// ghReleaseClient is the subset of go-github's RepositoriesService the bundle
// downloader needs: resolve a release (latest or by tag) and download an asset
// by ID. The prod adapter wraps (*github.Client).Repositories; unit tests
// inject a fake so no network is touched (mirrors the ociFetcher seam in
// oci.go).
type ghReleaseClient interface {
	GetLatestRelease(ctx context.Context, owner, repo string) (*gogithub.RepositoryRelease, *gogithub.Response, error)
	GetReleaseByTag(ctx context.Context, owner, repo, tag string) (*gogithub.RepositoryRelease, *gogithub.Response, error)
	DownloadReleaseAsset(ctx context.Context, owner, repo string, id int64, followRedirectsClient *http.Client) (io.ReadCloser, string, error)
}

// ghReleaseRepos adapts the prod *github.Client to ghReleaseClient. The three
// methods exist verbatim on RepositoriesService, so each is a thin pass-through.
type ghReleaseRepos struct {
	repos *gogithub.RepositoriesService
}

func (g ghReleaseRepos) GetLatestRelease(ctx context.Context, owner, repo string) (*gogithub.RepositoryRelease, *gogithub.Response, error) {
	return g.repos.GetLatestRelease(ctx, owner, repo)
}

func (g ghReleaseRepos) GetReleaseByTag(ctx context.Context, owner, repo, tag string) (*gogithub.RepositoryRelease, *gogithub.Response, error) {
	return g.repos.GetReleaseByTag(ctx, owner, repo, tag)
}

func (g ghReleaseRepos) DownloadReleaseAsset(ctx context.Context, owner, repo string, id int64, followRedirectsClient *http.Client) (io.ReadCloser, string, error) {
	return g.repos.DownloadReleaseAsset(ctx, owner, repo, id, followRedirectsClient)
}

// parseGHReleaseReference parses ghrel://owner/repo[@tag][?asset=name] using
// net/url rather than hand-rolled splitting. In ghrel://owner/repo@tag the "@"
// falls after the first "/" (inside the path), so net/url does NOT treat it as
// userinfo — u.User stays nil. Cutting the path on the first "@" is unambiguous
// because GitHub owner/repo names cannot contain "@", and a tag containing "/"
// (e.g. release/v1) survives because only the first "@" is cut.
func parseGHReleaseReference(uri string) (ghRef, error) {
	malformed := fmt.Errorf("invalid ghrel reference %q: expected ghrel://owner/repo[@tag][?asset=name]", uri)

	u, err := url.Parse(uri)
	if err != nil {
		return ghRef{}, malformed
	}

	// reject a userinfo authority (ghrel://alice@github.com/repo) or a port
	// (ghrel://owner:8080/repo): in both cases net/url would fold the extra token
	// into the owner and resolve an unexpected repo. GitHub owners contain neither
	// "@" nor ":", so either is always a malformed reference.
	if u.User != nil || u.Port() != "" {
		return ghRef{}, malformed
	}

	owner := u.Host
	pathPart := strings.TrimPrefix(u.Path, "/")
	repo, tag, hasTag := strings.Cut(pathPart, "@")
	query := u.Query()
	asset := query.Get("asset")

	switch {
	case owner == "" || repo == "":
		return ghRef{}, malformed
	case strings.Contains(repo, "/"):
		// owner/repo is exactly two segments; a trailing slash or extra path
		// segments (ghrel://owner/repo/, ghrel://owner/a/b) would otherwise
		// surface as an opaque GitHub 404 instead of the AC8 parse error.
		return ghRef{}, malformed
	case hasTag && tag == "":
		// a trailing "@" with no tag (ghrel://owner/repo@) is a likely typo that
		// would silently fall through to the latest release, defeating an
		// explicit pin; reject it rather than guess.
		return ghRef{}, malformed
	case query.Has("asset") && asset == "":
		// an explicit but empty ?asset= (ghrel://owner/repo?asset=) is a likely
		// typo that would silently fall back to the default asset; reject it
		// rather than guess, mirroring the trailing-"@" empty-tag case.
		return ghRef{}, malformed
	}

	return ghRef{Owner: owner, Repo: repo, Tag: tag, Asset: asset}, nil
}

// validateExpectedDigest reports whether s is a well-formed sha256 pin
// (sha256:<64 hex> or a bare 64-char hex string). Used to surface a malformed
// --policy-bundle-digest as a clear config error before any network I/O, rather
// than as an opaque post-download mismatch.
func validateExpectedDigest(s string) error {
	alg, hexv, err := digest.Parse(digest.Normalize(s))
	if err != nil {
		return err
	}
	// the comparison hashes the asset with SHA-256, so only a sha256 pin can
	// ever match — reject other algorithms up front rather than after download.
	if alg != "sha256" {
		return fmt.Errorf("unsupported digest algorithm %q (only sha256 is supported)", alg)
	}
	return digest.ValidateFormat(alg, hexv)
}

// downloadGHReleaseBundle is the dispatcher entry point for the ghrel:// scheme.
// It parses the reference, builds the prod GitHub client (authenticated when a
// token is present, anonymous otherwise — AC6), and delegates to the seam-based
// resolver.
func downloadGHReleaseBundle(ctx context.Context, uri string, opts *ResolveOptions) (string, func(), error) {
	ref, err := parseGHReleaseReference(uri)
	if err != nil {
		return "", nil, err
	}

	client, err := github.NewClient()
	if err != nil {
		return "", nil, fmt.Errorf("failed to create GitHub client: %w", err)
	}

	return resolveGHReleaseToDir(ctx, ghReleaseRepos{repos: client.Repositories}, ref, opts)
}

// resolveGHReleaseToDir resolves a release asset to a local directory holding
// the extracted bundle. It honors the resolveBundlePath contract: the temp
// directory is removed on any error after creation, and a cleanup func is
// returned on success.
func resolveGHReleaseToDir(ctx context.Context, client ghReleaseClient, ref ghRef, opts *ResolveOptions) (string, func(), error) {
	assetName, err := resolveGHReleaseAssetName(ref, opts)
	if err != nil {
		return "", nil, err
	}

	// resolve the release (latest or by tag) with transient-failure retry.
	release, err := resolveReleaseWithRetry(ctx, func() (*gogithub.RepositoryRelease, *gogithub.Response, error) {
		if ref.Tag == "" {
			return client.GetLatestRelease(ctx, ref.Owner, ref.Repo)
		}
		return client.GetReleaseByTag(ctx, ref.Owner, ref.Repo, ref.Tag)
	})
	if err != nil {
		if ref.Tag == "" {
			return "", nil, fmt.Errorf("failed to resolve latest release for %s/%s: %w", ref.Owner, ref.Repo, err)
		}
		return "", nil, fmt.Errorf("failed to resolve release tag %q for %s/%s: %w", ref.Tag, ref.Owner, ref.Repo, err)
	}

	assetID, err := findGHReleaseAssetID(release, ref, assetName)
	if err != nil {
		return "", nil, err
	}

	data, err := downloadGHReleaseAssetBytes(ctx, client, ref, assetID, assetName)
	if err != nil {
		return "", nil, err
	}

	if err := verifyGHReleaseDigest(data, ref, assetName, opts); err != nil {
		return "", nil, err
	}

	// extract into a temp dir; clean up on any post-creation error (leak hygiene).
	tempDir, cleanup, err := digest.CreateTempDir("opa-bundle-")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	if err := extractTarGz(bytes.NewReader(data), tempDir); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to extract ghrel bundle: %w", err)
	}

	return tempDir, cleanup, nil
}

// resolveGHReleaseAssetName picks the asset name to download: an explicit
// ?asset= wins, else the per-call default (bundle.tar.gz vs schemas.tar.gz).
// opts is always non-nil from NewOPAEvaluator with a default set, but it guards
// defensively. An empty result is a config error, not a missing asset.
func resolveGHReleaseAssetName(ref ghRef, opts *ResolveOptions) (string, error) {
	assetName := ref.Asset
	if assetName == "" && opts != nil {
		assetName = opts.DefaultAsset
	}
	if assetName == "" {
		return "", fmt.Errorf("invalid ghrel reference %q: no asset specified and no default asset configured", ref.Owner+"/"+ref.Repo)
	}
	return assetName, nil
}

// findGHReleaseAssetID returns the ID of the named asset in the release; the ID
// is required to download (no download-by-name). A missing asset is an error.
func findGHReleaseAssetID(release *gogithub.RepositoryRelease, ref ghRef, assetName string) (int64, error) {
	for _, a := range release.Assets {
		if a.GetName() == assetName {
			return a.GetID(), nil
		}
	}
	return 0, fmt.Errorf("asset %q not found in release %q for %s/%s", assetName, release.GetTagName(), ref.Owner, ref.Repo)
}

// downloadGHReleaseAssetBytes downloads the asset and reads it once into memory
// so the bytes can be both digested (AC9) and extracted. http.DefaultClient
// follows GitHub's redirect to the pre-signed CDN URL (the value recommended by
// DownloadReleaseAsset); that URL needs no auth, while the API call itself is
// authenticated via the client token. The read is capped with io.LimitReader
// (+1 so an exactly-at-limit overflow is detectable) — the asset's declared
// size is not trusted.
func downloadGHReleaseAssetBytes(ctx context.Context, client ghReleaseClient, ref ghRef, assetID int64, assetName string) ([]byte, error) {
	rc, _, err := client.DownloadReleaseAsset(ctx, ref.Owner, ref.Repo, assetID, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to download asset %q (id %d) from %s/%s: %w", assetName, assetID, ref.Owner, ref.Repo, err)
	}
	if rc == nil {
		// DownloadReleaseAsset returns exactly one of (reader, redirectURL);
		// passing http.DefaultClient always yields the reader, but guard so a nil
		// body can never nil-deref the deferred Close below.
		return nil, fmt.Errorf("no readable body for asset %q (id %d) from %s/%s", assetName, assetID, ref.Owner, ref.Repo)
	}
	defer func() {
		if closeErr := rc.Close(); closeErr != nil {
			log.Printf("warning: failed to close ghrel asset reader: %v", closeErr)
		}
	}()

	data, err := io.ReadAll(io.LimitReader(rc, maxGHReleaseAssetSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read asset %q from %s/%s: %w", assetName, ref.Owner, ref.Repo, err)
	}
	if int64(len(data)) > maxGHReleaseAssetSize {
		return nil, fmt.Errorf("ghrel asset %q size exceeds maximum allowed %d bytes", assetName, maxGHReleaseAssetSize)
	}
	return data, nil
}

// verifyGHReleaseDigest digests the archive bytes, ALWAYS logging for
// auditability (AC9), and optionally enforces an expected digest (bundle path
// only). Enforcing here — before extraction — ensures a mismatch leaves no temp
// dir behind.
func verifyGHReleaseDigest(data []byte, ref ghRef, assetName string, opts *ResolveOptions) error {
	got, err := digest.CalculateReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to digest asset %q: %w", assetName, err)
	}
	refLabel := ref.Tag
	if refLabel == "" {
		refLabel = "latest"
	}
	log.Printf("ghrel: downloaded %s (%s/%s@%s) sha256=%s", assetName, ref.Owner, ref.Repo, refLabel, got)

	// optional integrity enforcement, bundle path only (AC9). Compare normalized
	// so a bare-hex flag value still matches.
	if opts != nil && opts.ExpectedDigest != "" {
		// compare case-insensitively: CalculateReader emits lowercase hex, but a
		// user may paste an uppercase pin from a checksum tool — that is a valid
		// match, not tampering.
		if !strings.EqualFold(digest.Normalize(got), digest.Normalize(opts.ExpectedDigest)) {
			return fmt.Errorf("policy bundle digest mismatch: expected %s, got %s", digest.Normalize(opts.ExpectedDigest), got)
		}
	}
	return nil
}

// resolveReleaseWithRetry runs a release-resolution call with transient-failure
// resilience (AC10): up to ghReleaseRetryAttempts attempts with exponential
// backoff. Primary rate-limit exhaustion fails immediately (no retry); a
// secondary rate limit honors its RetryAfter; HTTP 429/502/503 back off and
// retry; any other error returns immediately.
func resolveReleaseWithRetry(ctx context.Context, fetch func() (*gogithub.RepositoryRelease, *gogithub.Response, error)) (*gogithub.RepositoryRelease, error) {
	var lastErr error
	for attempt := 1; attempt <= ghReleaseRetryAttempts; attempt++ {
		release, resp, err := fetch()
		if err == nil {
			return release, nil
		}
		lastErr = err

		// primary rate limit (X-RateLimit-Remaining: 0): never retry — report
		// the reset time and fail immediately.
		var rlErr *gogithub.RateLimitError
		if errors.As(err, &rlErr) {
			return nil, fmt.Errorf("github primary rate limit exceeded; resets at %s: %w",
				rlErr.Rate.Reset.Format(time.RFC3339), err)
		}

		// out of attempts: stop and surface the last error.
		if attempt == ghReleaseRetryAttempts {
			break
		}

		// secondary rate limit: honor RetryAfter (within the attempt budget).
		var abuseErr *gogithub.AbuseRateLimitError
		if errors.As(err, &abuseErr) {
			wait := backoffFor(attempt)
			// honor a positive RetryAfter; a missing or non-positive value falls
			// back to exponential backoff so a 0/negative hint can't busy-spin the
			// attempt budget with no delay.
			if abuseErr.RetryAfter != nil && *abuseErr.RetryAfter > 0 {
				wait = *abuseErr.RetryAfter
			}
			if waitErr := sleepCtx(ctx, wait); waitErr != nil {
				return nil, waitErr
			}
			continue
		}

		// other transient HTTP statuses: back off and retry.
		if resp != nil && isRetryableStatus(resp.StatusCode) {
			if waitErr := sleepCtx(ctx, backoffFor(attempt)); waitErr != nil {
				return nil, waitErr
			}
			continue
		}

		// non-transient error: return immediately.
		return nil, err
	}
	return nil, lastErr
}

// backoffFor returns the exponential backoff for a given (1-based) attempt.
func backoffFor(attempt int) time.Duration {
	return ghReleaseRetryBackoff * time.Duration(1<<(attempt-1))
}

// isRetryableStatus reports whether an HTTP status code is a transient failure
// worth retrying.
func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// sleepCtx waits for d, returning early (with ctx.Err()) if the context is
// cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
