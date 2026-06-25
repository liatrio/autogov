package root

import (
	"errors"
	"testing"
)

// swaps the live fetch seam and the cached live root, restoring both on cleanup
// so tests don't leak the process-wide refresh state into each other.
func withFetchStub(t *testing.T, stub func() ([]byte, error)) {
	t.Helper()
	origFetch := fetchPublicTrustedRoot
	publicTrustedRootMu.Lock()
	origLive := livePublicTrustedRoot
	livePublicTrustedRoot = nil
	publicTrustedRootMu.Unlock()
	fetchPublicTrustedRoot = stub
	t.Cleanup(func() {
		fetchPublicTrustedRoot = origFetch
		publicTrustedRootMu.Lock()
		livePublicTrustedRoot = origLive
		publicTrustedRootMu.Unlock()
	})
}

// default (refresh not requested): GetPublicTrustedRoot serves the embedded snapshot.
func TestGetPublicTrustedRootDefaultUsesEmbedded(t *testing.T) {
	withFetchStub(t, func() ([]byte, error) {
		t.Fatalf("live fetch must not run when refresh is not requested")
		return nil, nil
	})
	if got := GetPublicTrustedRoot(); string(got) != string(PublicSigstoreTrustedRoot) {
		t.Error("default GetPublicTrustedRoot did not return the embedded snapshot")
	}
}

// refresh on + success: GetPublicTrustedRoot serves the live root afterwards.
func TestRefreshPublicTrustedRootSuccess(t *testing.T) {
	// the embedded snapshot is a real, valid trusted root; reuse it as the fake
	// "live" payload but tag it so we can prove the live value is served.
	live := append([]byte(nil), PublicSigstoreTrustedRoot...)
	withFetchStub(t, func() ([]byte, error) { return live, nil })

	if err := RefreshPublicTrustedRoot(); err != nil {
		t.Fatalf("RefreshPublicTrustedRoot returned error on success: %v", err)
	}
	got := GetPublicTrustedRoot()
	if &got[0] != &live[0] {
		t.Error("GetPublicTrustedRoot did not serve the live-refreshed root after a successful refresh")
	}
}

// refresh on + fetch failure: must error (fail-closed) and NOT poison the served
// root — GetPublicTrustedRoot must still return the embedded snapshot.
func TestRefreshPublicTrustedRootFetchFailureFailsClosed(t *testing.T) {
	withFetchStub(t, func() ([]byte, error) { return nil, errors.New("network down") })

	if err := RefreshPublicTrustedRoot(); err == nil {
		t.Fatal("RefreshPublicTrustedRoot did not error on fetch failure (fail-closed expected)")
	}
	if got := GetPublicTrustedRoot(); string(got) != string(PublicSigstoreTrustedRoot) {
		t.Error("after a failed refresh GetPublicTrustedRoot should still serve the embedded snapshot")
	}
}

// refresh on + invalid payload: a fetched-but-unparseable root must error and not
// be cached (fail-closed against accepting an unverified/garbage root).
func TestRefreshPublicTrustedRootInvalidPayloadFailsClosed(t *testing.T) {
	withFetchStub(t, func() ([]byte, error) { return []byte("not a trusted root"), nil })

	if err := RefreshPublicTrustedRoot(); err == nil {
		t.Fatal("RefreshPublicTrustedRoot did not error on an invalid payload (fail-closed expected)")
	}
	if got := GetPublicTrustedRoot(); string(got) != string(PublicSigstoreTrustedRoot) {
		t.Error("after an invalid refresh GetPublicTrustedRoot should still serve the embedded snapshot")
	}
}
