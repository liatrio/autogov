package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogithub "github.com/google/go-github/v88/github"

	"github.com/liatrio/autogov/pkg/digest"
)

// ghResp is one scripted response for the fake's release-resolution calls.
type ghResp struct {
	rel  *gogithub.RepositoryRelease
	resp *gogithub.Response
	err  error
}

// fakeGHReleaseClient is an in-memory ghReleaseClient: no network. Resolution
// calls pop from resolveQueue (the last entry repeats once exhausted), and
// DownloadReleaseAsset serves bytes keyed by asset ID so a test can prove which
// asset was selected.
type fakeGHReleaseClient struct {
	resolveQueue []ghResp
	resolveIdx   int

	latestCalls   int
	byTagCalls    int
	downloadCalls int
	lastID        int64

	assetByID   map[int64][]byte
	downloadErr error
}

func (f *fakeGHReleaseClient) next() ghResp {
	if f.resolveIdx < len(f.resolveQueue) {
		r := f.resolveQueue[f.resolveIdx]
		f.resolveIdx++
		return r
	}
	if len(f.resolveQueue) > 0 {
		return f.resolveQueue[len(f.resolveQueue)-1]
	}
	return ghResp{}
}

func (f *fakeGHReleaseClient) GetLatestRelease(ctx context.Context, owner, repo string) (*gogithub.RepositoryRelease, *gogithub.Response, error) {
	f.latestCalls++
	r := f.next()
	return r.rel, r.resp, r.err
}

func (f *fakeGHReleaseClient) GetReleaseByTag(ctx context.Context, owner, repo, tag string) (*gogithub.RepositoryRelease, *gogithub.Response, error) {
	f.byTagCalls++
	r := f.next()
	return r.rel, r.resp, r.err
}

func (f *fakeGHReleaseClient) DownloadReleaseAsset(ctx context.Context, owner, repo string, id int64, _ *http.Client) (io.ReadCloser, string, error) {
	f.downloadCalls++
	f.lastID = id
	if f.downloadErr != nil {
		return nil, "", f.downloadErr
	}
	data, ok := f.assetByID[id]
	if !ok {
		return nil, "", fmt.Errorf("fake: no bytes registered for asset id %d", id)
	}
	return io.NopCloser(bytes.NewReader(data)), "", nil
}

// makeRelease builds a release with the given tag and (name->id) assets.
func makeRelease(tag string, assets map[string]int64) *gogithub.RepositoryRelease {
	r := &gogithub.RepositoryRelease{TagName: gogithub.Ptr(tag)}
	for name, id := range assets {
		r.Assets = append(r.Assets, &gogithub.ReleaseAsset{ID: gogithub.Ptr(id), Name: gogithub.Ptr(name)})
	}
	return r
}

func TestParseGHReleaseReference(t *testing.T) {
	tests := []struct {
		name      string
		uri       string
		wantOwner string
		wantRepo  string
		wantTag   string
		wantAsset string
	}{
		{"bare", "ghrel://owner/repo", "owner", "repo", "", ""},
		{"tag", "ghrel://owner/repo@v1.2.0", "owner", "repo", "v1.2.0", ""},
		{"asset", "ghrel://owner/repo?asset=custom.tar.gz", "owner", "repo", "", "custom.tar.gz"},
		{"tag+asset", "ghrel://owner/repo@v1.2.0?asset=custom.tar.gz", "owner", "repo", "v1.2.0", "custom.tar.gz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := parseGHReleaseReference(tt.uri)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ref.Owner != tt.wantOwner || ref.Repo != tt.wantRepo || ref.Tag != tt.wantTag || ref.Asset != tt.wantAsset {
				t.Errorf("parseGHReleaseReference(%q) = %+v, want {Owner:%s Repo:%s Tag:%s Asset:%s}",
					tt.uri, ref, tt.wantOwner, tt.wantRepo, tt.wantTag, tt.wantAsset)
			}
		})
	}
}

func TestParseGHReleaseEdgeCases(t *testing.T) {
	t.Run("missing owner errors", func(t *testing.T) {
		if _, err := parseGHReleaseReference("ghrel://"); err == nil {
			t.Fatal("expected error for missing owner/repo")
		} else if !strings.Contains(err.Error(), "invalid ghrel reference") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("missing repo errors", func(t *testing.T) {
		if _, err := parseGHReleaseReference("ghrel://owner"); err == nil {
			t.Fatal("expected error for missing repo")
		} else if !strings.Contains(err.Error(), "invalid ghrel reference") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("tag with slash preserved", func(t *testing.T) {
		ref, err := parseGHReleaseReference("ghrel://owner/repo@release/v1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ref.Tag != "release/v1" {
			t.Errorf("Tag = %q, want %q (tag with / must survive the first-@ cut)", ref.Tag, "release/v1")
		}
		// the @ is in the path, not userinfo — owner/repo unaffected
		if ref.Owner != "owner" || ref.Repo != "repo" {
			t.Errorf("owner/repo = %s/%s, want owner/repo", ref.Owner, ref.Repo)
		}
	})

	t.Run("asset name url-decoded", func(t *testing.T) {
		ref, err := parseGHReleaseReference("ghrel://owner/repo?asset=weird%20name.tar.gz")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ref.Asset != "weird name.tar.gz" {
			t.Errorf("Asset = %q, want %q (url.Query must decode)", ref.Asset, "weird name.tar.gz")
		}
	})

	t.Run("no @ yields empty tag", func(t *testing.T) {
		ref, err := parseGHReleaseReference("ghrel://owner/repo")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ref.Tag != "" {
			t.Errorf("Tag = %q, want empty", ref.Tag)
		}
	})

	// rejections: each would otherwise surface as an opaque 404 or a silently
	// wrong resolution rather than the AC8 clean parse error.
	reject := []struct{ name, uri string }{
		{"userinfo authority", "ghrel://alice@github.com/policies"},
		{"port in authority", "ghrel://owner:8080/repo"},
		{"extra path segment", "ghrel://owner/a/b"},
		{"trailing slash", "ghrel://owner/repo/"},
		{"empty tag", "ghrel://owner/repo@"},
		{"empty asset", "ghrel://owner/repo?asset="},
	}
	for _, tt := range reject {
		t.Run(tt.name+" rejected", func(t *testing.T) {
			if _, err := parseGHReleaseReference(tt.uri); err == nil {
				t.Fatalf("expected error for %q", tt.uri)
			} else if !strings.Contains(err.Error(), "invalid ghrel reference") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateExpectedDigest(t *testing.T) {
	valid := []string{
		"sha256:" + strings.Repeat("a", 64),
		strings.Repeat("a", 64), // bare hex normalizes to sha256:
	}
	for _, v := range valid {
		if err := validateExpectedDigest(v); err != nil {
			t.Errorf("validateExpectedDigest(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{
		"garbage",
		"sha256:xyz",                         // non-hex
		"sha256:" + strings.Repeat("a", 63),  // too short
		"deadbeef",                           // valid hex but wrong length
		"sha512:" + strings.Repeat("a", 128), // well-formed but wrong algorithm
	}
	for _, v := range invalid {
		if err := validateExpectedDigest(v); err == nil {
			t.Errorf("validateExpectedDigest(%q) = nil, want error", v)
		}
	}
}

func TestGHReleaseAssetTooLarge(t *testing.T) {
	orig := maxGHReleaseAssetSize
	maxGHReleaseAssetSize = 8 // lower to 8 bytes; any real tar.gz exceeds it
	t.Cleanup(func() { maxGHReleaseAssetSize = orig })

	ctx := context.Background()
	assetBytes := buildTarGz(t, map[string]string{"policy.rego": "package governance"})
	client := &fakeGHReleaseClient{
		resolveQueue: []ghResp{{rel: makeRelease("v1", map[string]int64{"bundle.tar.gz": 1})}},
		assetByID:    map[int64][]byte{1: assetBytes},
	}

	before := countOpaBundleTempDirs(t)
	_, _, err := resolveGHReleaseToDir(ctx, client, ghRef{Owner: "o", Repo: "r"}, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
	if err == nil {
		t.Fatal("expected oversize-asset error")
	}
	if !strings.Contains(err.Error(), "exceeds maximum allowed") {
		t.Errorf("unexpected error: %v", err)
	}
	// the size cap fires before CreateTempDir, so nothing leaks
	if after := countOpaBundleTempDirs(t); after > before {
		t.Errorf("temp dir leaked on oversize path: before=%d after=%d", before, after)
	}
}

func TestGHReleaseDownloadError(t *testing.T) {
	ctx := context.Background()
	client := &fakeGHReleaseClient{
		resolveQueue: []ghResp{{rel: makeRelease("v1", map[string]int64{"bundle.tar.gz": 1})}},
		downloadErr:  errors.New("connection reset by peer"),
	}

	_, _, err := resolveGHReleaseToDir(ctx, client, ghRef{Owner: "o", Repo: "r"}, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
	if err == nil {
		t.Fatal("expected download error to surface")
	}
	if !strings.Contains(err.Error(), "failed to download asset") || !strings.Contains(err.Error(), "connection reset by peer") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDownloadFromGHRelease(t *testing.T) {
	ctx := context.Background()
	assetBytes := buildTarGz(t, map[string]string{"policy.rego": "package governance"})
	client := &fakeGHReleaseClient{
		resolveQueue: []ghResp{{rel: makeRelease("v1.0.0", map[string]int64{"bundle.tar.gz": 1})}},
		assetByID:    map[int64][]byte{1: assetBytes},
	}

	dir, cleanup, err := resolveGHReleaseToDir(ctx, client, ghRef{Owner: "o", Repo: "r"}, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
	if err != nil {
		t.Fatalf("resolveGHReleaseToDir failed: %v", err)
	}
	if client.lastID != 1 {
		t.Errorf("downloaded asset id = %d, want 1", client.lastID)
	}

	got, err := os.ReadFile(filepath.Join(dir, "policy.rego"))
	if err != nil {
		t.Fatalf("extracted policy.rego missing: %v", err)
	}
	if string(got) != "package governance" {
		t.Errorf("policy.rego = %q, want %q", string(got), "package governance")
	}

	cleanup()
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Errorf("temp dir %s not removed after cleanup", dir)
	}
}

func TestDownloadFromGHReleaseLatestVsByTag(t *testing.T) {
	ctx := context.Background()
	assetBytes := buildTarGz(t, map[string]string{"policy.rego": "package x"})

	t.Run("latest when tag empty", func(t *testing.T) {
		client := &fakeGHReleaseClient{
			resolveQueue: []ghResp{{rel: makeRelease("v9", map[string]int64{"bundle.tar.gz": 1})}},
			assetByID:    map[int64][]byte{1: assetBytes},
		}
		_, cleanup, err := resolveGHReleaseToDir(ctx, client, ghRef{Owner: "o", Repo: "r"}, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
		if err != nil {
			t.Fatalf("resolve failed: %v", err)
		}
		defer cleanup()
		if client.latestCalls != 1 || client.byTagCalls != 0 {
			t.Errorf("latest=%d byTag=%d, want latest=1 byTag=0", client.latestCalls, client.byTagCalls)
		}
	})

	t.Run("by tag when set", func(t *testing.T) {
		client := &fakeGHReleaseClient{
			resolveQueue: []ghResp{{rel: makeRelease("v1.2.0", map[string]int64{"bundle.tar.gz": 1})}},
			assetByID:    map[int64][]byte{1: assetBytes},
		}
		_, cleanup, err := resolveGHReleaseToDir(ctx, client, ghRef{Owner: "o", Repo: "r", Tag: "v1.2.0"}, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
		if err != nil {
			t.Fatalf("resolve failed: %v", err)
		}
		defer cleanup()
		if client.byTagCalls != 1 || client.latestCalls != 0 {
			t.Errorf("latest=%d byTag=%d, want latest=0 byTag=1", client.latestCalls, client.byTagCalls)
		}
	})
}

func TestDownloadFromGHReleaseCustomAsset(t *testing.T) {
	ctx := context.Background()
	bundleBytes := buildTarGz(t, map[string]string{"policy.rego": "package bundle"})
	customBytes := buildTarGz(t, map[string]string{"custom.rego": "package custom"})
	client := &fakeGHReleaseClient{
		resolveQueue: []ghResp{{rel: makeRelease("v1", map[string]int64{"bundle.tar.gz": 1, "custom.tar.gz": 2})}},
		assetByID:    map[int64][]byte{1: bundleBytes, 2: customBytes},
	}

	// ?asset=custom.tar.gz must override the bundle.tar.gz default.
	dir, cleanup, err := resolveGHReleaseToDir(ctx, client, ghRef{Owner: "o", Repo: "r", Asset: "custom.tar.gz"}, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	defer cleanup()
	if client.lastID != 2 {
		t.Errorf("downloaded asset id = %d, want 2 (custom.tar.gz)", client.lastID)
	}
	if _, err := os.Stat(filepath.Join(dir, "custom.rego")); err != nil {
		t.Errorf("expected custom.rego from the custom asset: %v", err)
	}
}

func TestGHReleaseSchemasDefault(t *testing.T) {
	ctx := context.Background()
	bundleBytes := buildTarGz(t, map[string]string{"policy.rego": "package bundle"})
	schemasBytes := buildTarGz(t, map[string]string{"schema.json": `{"type":"object"}`})
	client := &fakeGHReleaseClient{
		resolveQueue: []ghResp{{rel: makeRelease("v1", map[string]int64{"bundle.tar.gz": 1, "schemas.tar.gz": 2})}},
		assetByID:    map[int64][]byte{1: bundleBytes, 2: schemasBytes},
	}

	// no ?asset= + DefaultAsset "schemas.tar.gz" must select the schemas asset
	// (AC4/AC5 share one resolver; the default differs from the bundle default).
	dir, cleanup, err := resolveGHReleaseToDir(ctx, client, ghRef{Owner: "o", Repo: "r"}, &ResolveOptions{DefaultAsset: "schemas.tar.gz"})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	defer cleanup()
	if client.lastID != 2 {
		t.Errorf("downloaded asset id = %d, want 2 (schemas.tar.gz)", client.lastID)
	}
	if _, err := os.Stat(filepath.Join(dir, "schema.json")); err != nil {
		t.Errorf("expected schema.json from the schemas default asset: %v", err)
	}
}

func TestGHReleaseAssetNotFound(t *testing.T) {
	ctx := context.Background()
	client := &fakeGHReleaseClient{
		resolveQueue: []ghResp{{rel: makeRelease("v1.0.0", map[string]int64{"other.tar.gz": 1})}},
		assetByID:    map[int64][]byte{1: nil},
	}

	_, _, err := resolveGHReleaseToDir(ctx, client, ghRef{Owner: "o", Repo: "r"}, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
	if err == nil {
		t.Fatal("expected asset-not-found error")
	}
	if !strings.Contains(err.Error(), `asset "bundle.tar.gz" not found in release "v1.0.0" for o/r`) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGHReleaseReleaseNotFound(t *testing.T) {
	ctx := context.Background()
	t.Run("latest", func(t *testing.T) {
		client := &fakeGHReleaseClient{resolveQueue: []ghResp{{err: errors.New("404 Not Found")}}}
		_, _, err := resolveGHReleaseToDir(ctx, client, ghRef{Owner: "o", Repo: "r"}, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
		if err == nil {
			t.Fatal("expected release-not-found error")
		}
		if !strings.Contains(err.Error(), "failed to resolve latest release for o/r") {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("by tag", func(t *testing.T) {
		client := &fakeGHReleaseClient{resolveQueue: []ghResp{{err: errors.New("404 Not Found")}}}
		_, _, err := resolveGHReleaseToDir(ctx, client, ghRef{Owner: "o", Repo: "r", Tag: "v9.9.9"}, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
		if err == nil {
			t.Fatal("expected release-not-found error")
		}
		if !strings.Contains(err.Error(), `failed to resolve release tag "v9.9.9" for o/r`) {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestGHReleaseDigestVerification(t *testing.T) {
	ctx := context.Background()
	assetBytes := buildTarGz(t, map[string]string{"policy.rego": "package governance"})
	realDigest, err := digest.CalculateReader(bytes.NewReader(assetBytes))
	if err != nil {
		t.Fatalf("failed to compute reference digest: %v", err)
	}

	newClient := func() *fakeGHReleaseClient {
		return &fakeGHReleaseClient{
			resolveQueue: []ghResp{{rel: makeRelease("v1", map[string]int64{"bundle.tar.gz": 1})}},
			assetByID:    map[int64][]byte{1: assetBytes},
		}
	}

	t.Run("matching digest succeeds", func(t *testing.T) {
		dir, cleanup, err := resolveGHReleaseToDir(ctx, newClient(), ghRef{Owner: "o", Repo: "r"},
			&ResolveOptions{DefaultAsset: "bundle.tar.gz", ExpectedDigest: realDigest})
		if err != nil {
			t.Fatalf("expected success with matching digest, got: %v", err)
		}
		defer cleanup()
		if _, err := os.Stat(filepath.Join(dir, "policy.rego")); err != nil {
			t.Errorf("expected extracted bundle: %v", err)
		}
	})

	t.Run("bare-hex digest matches", func(t *testing.T) {
		_, hexOnly, _ := digest.Parse(realDigest)
		_, cleanup, err := resolveGHReleaseToDir(ctx, newClient(), ghRef{Owner: "o", Repo: "r"},
			&ResolveOptions{DefaultAsset: "bundle.tar.gz", ExpectedDigest: hexOnly})
		if err != nil {
			t.Fatalf("expected bare-hex digest to match after normalize, got: %v", err)
		}
		cleanup()
	})

	t.Run("uppercase-hex digest matches (case-insensitive)", func(t *testing.T) {
		_, hexOnly, _ := digest.Parse(realDigest)
		upperPin := "sha256:" + strings.ToUpper(hexOnly)
		_, cleanup, err := resolveGHReleaseToDir(ctx, newClient(), ghRef{Owner: "o", Repo: "r"},
			&ResolveOptions{DefaultAsset: "bundle.tar.gz", ExpectedDigest: upperPin})
		if err != nil {
			t.Fatalf("expected uppercase-hex pin to match a lowercase digest, got: %v", err)
		}
		cleanup()
	})

	t.Run("mismatch hard-fails and leaves no temp dir", func(t *testing.T) {
		before := countOpaBundleTempDirs(t)
		_, _, err := resolveGHReleaseToDir(ctx, newClient(), ghRef{Owner: "o", Repo: "r"},
			&ResolveOptions{DefaultAsset: "bundle.tar.gz", ExpectedDigest: "sha256:" + strings.Repeat("0", 64)})
		if err == nil {
			t.Fatal("expected digest-mismatch error")
		}
		if !strings.Contains(err.Error(), "policy bundle digest mismatch: expected") {
			t.Errorf("unexpected error: %v", err)
		}
		if after := countOpaBundleTempDirs(t); after > before {
			t.Errorf("temp dir leaked on digest-mismatch path: before=%d after=%d", before, after)
		}
	})
}

func TestGHReleaseDigestAlwaysLogged(t *testing.T) {
	ctx := context.Background()
	assetBytes := buildTarGz(t, map[string]string{"policy.rego": "package governance"})
	client := &fakeGHReleaseClient{
		resolveQueue: []ghResp{{rel: makeRelease("v1", map[string]int64{"bundle.tar.gz": 1})}},
		assetByID:    map[int64][]byte{1: assetBytes},
	}

	var cleanup func()
	logOut := captureLog(t, func() {
		var err error
		_, cleanup, err = resolveGHReleaseToDir(ctx, client, ghRef{Owner: "o", Repo: "r"}, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
		if err != nil {
			t.Fatalf("resolve failed: %v", err)
		}
	})
	if cleanup != nil {
		defer cleanup()
	}
	if !strings.Contains(logOut, "ghrel: downloaded bundle.tar.gz") || !strings.Contains(logOut, "sha256=") {
		t.Errorf("expected sha256 of asset to be logged, log was: %q", logOut)
	}
}

func TestGHReleaseRetryTransient(t *testing.T) {
	orig := ghReleaseRetryBackoff
	ghReleaseRetryBackoff = time.Millisecond
	t.Cleanup(func() { ghReleaseRetryBackoff = orig })

	ctx := context.Background()
	assetBytes := buildTarGz(t, map[string]string{"policy.rego": "package x"})

	for _, status := range []struct {
		name string
		code int
	}{
		{"503", http.StatusServiceUnavailable},
		{"504", http.StatusGatewayTimeout},
		{"502", http.StatusBadGateway},
		{"429", http.StatusTooManyRequests},
	} {
		t.Run(status.name+" then success", func(t *testing.T) {
			client := &fakeGHReleaseClient{
				resolveQueue: []ghResp{
					{resp: &gogithub.Response{Response: &http.Response{StatusCode: status.code}}, err: errors.New("transient")},
					{rel: makeRelease("v1", map[string]int64{"bundle.tar.gz": 1})},
				},
				assetByID: map[int64][]byte{1: assetBytes},
			}
			_, cleanup, err := resolveGHReleaseToDir(ctx, client, ghRef{Owner: "o", Repo: "r"}, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
			if err != nil {
				t.Fatalf("expected success after retry, got: %v", err)
			}
			defer cleanup()
			if client.latestCalls != 2 {
				t.Errorf("expected 2 resolve attempts (retry), got %d", client.latestCalls)
			}
		})
	}

	t.Run("secondary rate limit honors RetryAfter then succeeds", func(t *testing.T) {
		retryAfter := time.Millisecond
		client := &fakeGHReleaseClient{
			resolveQueue: []ghResp{
				{err: &gogithub.AbuseRateLimitError{RetryAfter: &retryAfter, Message: "secondary rate limit"}},
				{rel: makeRelease("v1", map[string]int64{"bundle.tar.gz": 1})},
			},
			assetByID: map[int64][]byte{1: assetBytes},
		}
		_, cleanup, err := resolveGHReleaseToDir(ctx, client, ghRef{Owner: "o", Repo: "r"}, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
		if err != nil {
			t.Fatalf("expected success after honoring RetryAfter, got: %v", err)
		}
		defer cleanup()
		if client.latestCalls != 2 {
			t.Errorf("expected 2 resolve attempts, got %d", client.latestCalls)
		}
	})

	t.Run("non-positive RetryAfter falls back to backoff", func(t *testing.T) {
		zero := time.Duration(0)
		client := &fakeGHReleaseClient{
			resolveQueue: []ghResp{
				{err: &gogithub.AbuseRateLimitError{RetryAfter: &zero, Message: "secondary rate limit"}},
				{rel: makeRelease("v1", map[string]int64{"bundle.tar.gz": 1})},
			},
			assetByID: map[int64][]byte{1: assetBytes},
		}
		_, cleanup, err := resolveGHReleaseToDir(ctx, client, ghRef{Owner: "o", Repo: "r"}, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
		if err != nil {
			t.Fatalf("expected success after backoff fallback, got: %v", err)
		}
		defer cleanup()
		if client.latestCalls != 2 {
			t.Errorf("expected 2 resolve attempts, got %d", client.latestCalls)
		}
	})
}

func TestGHReleasePrimaryRateLimit(t *testing.T) {
	ctx := context.Background()
	resetTime := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	rlErr := &gogithub.RateLimitError{
		Rate:    gogithub.Rate{Reset: gogithub.Timestamp{Time: resetTime}},
		Message: "API rate limit exceeded",
		Response: &http.Response{
			StatusCode: http.StatusForbidden,
			Request:    &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: "api.github.com", Path: "/repos/o/r/releases/latest"}},
		},
	}
	client := &fakeGHReleaseClient{resolveQueue: []ghResp{{err: rlErr}}}

	_, _, err := resolveGHReleaseToDir(ctx, client, ghRef{Owner: "o", Repo: "r"}, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
	if err == nil {
		t.Fatal("expected primary rate-limit failure")
	}
	// primary rate limit must NOT be retried
	if client.latestCalls != 1 {
		t.Errorf("primary rate limit must not retry; resolve attempts = %d, want 1", client.latestCalls)
	}
	if !strings.Contains(err.Error(), "primary rate limit") {
		t.Errorf("error should mention the primary rate limit: %v", err)
	}
	if !strings.Contains(err.Error(), resetTime.Format(time.RFC3339)) {
		t.Errorf("error should report the reset time %s: %v", resetTime.Format(time.RFC3339), err)
	}
}

func TestResolveBundlePathRoutesGHRel(t *testing.T) {
	// resolveBundlePath must dispatch ghrel:// to the GitHub release downloader,
	// not fall through to the local-directory passthrough. A malformed reference
	// (missing repo) fails fast in parseGHReleaseReference with no network, so an
	// error here proves the ghrel:// case ran (the default case would return the
	// path with a nil error). Mirrors TestResolveBundlePathRoutesOCI.
	_, _, err := resolveBundlePath(context.Background(), "ghrel://owner", &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
	if err == nil {
		t.Fatal("expected resolveBundlePath to route ghrel:// and surface a parse error")
	}
	if !strings.Contains(err.Error(), "invalid ghrel reference") {
		t.Errorf("unexpected error (did ghrel:// route correctly?): %v", err)
	}
}
