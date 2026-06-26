package certid

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestValidatorIsValidIdentity(t *testing.T) {
	// create a temp file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test-identities.json")

	// create test data
	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")

	testData := `{
		"identities": [
			{
				"version": "1.0.0",
				"sha": "abcdef1234567890",
				"status": "latest",
				"identities": ["https://github.com/liatrio/test-repo/.github/workflows/test.yaml@abc1234567890abcdef1234567890abcdef12345"],
				"added": "` + today + `"
			},
			{
				"version": "0.9.0",
				"sha": "1234567890abcdef",
				"status": "approved",
				"identities": ["https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v1.0.0"],
				"added": "` + yesterday + `",
				"expires": "` + tomorrow + `"
			},
			{
				"version": "0.8.0",
				"sha": "0123456789abcdef",
				"status": "approved",
				"identities": ["https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v0.9.0"],
				"added": "` + yesterday + `",
				"expires": "` + yesterday + `"
			},
			{
				"version": "0.5.0",
				"sha": "fedcba9876543210",
				"status": "revoked",
				"identities": ["https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v0.5.0"],
				"added": "` + yesterday + `",
				"revoked": "` + today + `",
				"reason": "Security vulnerability"
			}
		],
		"metadata": {
			"last_updated": "` + today + `",
			"version": "1.0.0",
			"maintainer": "Test"
		}
	}`

	if err := os.WriteFile(testFile, []byte(testData), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(testData))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	tests := []struct {
		name         string
		certIdentity string
		want         bool
		errContains  string
	}{
		{
			name:         "Latest - Valid",
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@abc1234567890abcdef1234567890abcdef12345",
			want:         true,
			errContains:  "",
		},
		{
			name:         "Approved - Valid",
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v1.0.0",
			want:         true,
			errContains:  "",
		},
		{
			name:         "Approved - Expired",
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v0.9.0",
			want:         false,
			errContains:  "expired",
		},
		{
			name:         "Invalid - Not Found",
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/nonexistent",
			want:         false,
			errContains:  "not found in approved lists",
		},
		{
			name:         "Revoked - Always Invalid",
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v0.5.0",
			want:         false,
			errContains:  "revoked",
		},
		{
			name:         "Normalization - Without refs/ prefix",
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@tags/v1.0.0",
			want:         true,
			errContains:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := Options{
				URL:          server.URL,
				DisableCache: true,
			}

			v, err := NewValidator(opts)
			if err != nil {
				t.Fatalf("Failed to create validator: %v", err)
			}

			if err := v.LoadIdentities(context.Background()); err != nil {
				t.Fatalf("Failed to load identities: %v", err)
			}

			got, err := v.IsValidIdentity(tt.certIdentity)
			if got != tt.want {
				t.Errorf("IsValidIdentity() = %v, want %v", got, tt.want)
			}

			if tt.errContains != "" && err == nil {
				t.Errorf("Expected error containing %q, got nil", tt.errContains)
			} else if tt.errContains == "" && err != nil {
				t.Errorf("Expected no error, got %v", err)
			} else if tt.errContains != "" && err != nil && !contains(err.Error(), tt.errContains) {
				t.Errorf("Expected error containing %q, got %v", tt.errContains, err)
			}
		})
	}
}

func TestValidatorGetValidIdentities(t *testing.T) {
	// create a temp file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test-identities.json")

	// create test data
	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")

	testData := `{
		"identities": [
			{
				"version": "1.1.0",
				"sha": "abcdef1234567890",
				"status": "latest",
				"identities": ["https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v1.1.0"],
				"added": "` + today + `"
			},
			{
				"version": "1.0.0",
				"sha": "1234567890abcdef",
				"status": "latest",
				"identities": ["https://github.com/liatrio/test-repo/.github/workflows/test2.yaml@refs/tags/v1.0.0"],
				"added": "` + today + `"
			},
			{
				"version": "0.9.1",
				"sha": "2345678901abcdef",
				"status": "approved",
				"identities": ["https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v1.0.0"],
				"added": "` + yesterday + `",
				"expires": "` + tomorrow + `"
			},
			{
				"version": "0.9.0",
				"sha": "3456789012abcdef",
				"status": "approved",
				"identities": ["https://github.com/liatrio/test-repo/.github/workflows/test2.yaml@refs/tags/v0.9.0"],
				"added": "` + yesterday + `",
				"expires": "` + tomorrow + `"
			},
			{
				"version": "0.8.0",
				"sha": "4567890123abcdef",
				"status": "approved",
				"identities": ["https://github.com/liatrio/test-repo/.github/workflows/test3.yaml@refs/tags/v0.9.0"],
				"added": "` + yesterday + `",
				"expires": "` + yesterday + `"
			},
			{
				"version": "0.5.0",
				"sha": "fedcba9876543210",
				"status": "revoked",
				"identities": ["https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v0.5.0"],
				"added": "` + yesterday + `",
				"revoked": "` + today + `",
				"reason": "Security vulnerability"
			}
		],
		"metadata": {
			"last_updated": "` + today + `",
			"version": "1.0.0",
			"maintainer": "Test"
		}
	}`

	if err := os.WriteFile(testFile, []byte(testData), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(testData))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// Test case for all valid identities
	t.Run("Get Valid Identities", func(t *testing.T) {
		opts := Options{
			URL:          server.URL,
			DisableCache: true,
		}

		v, err := NewValidator(opts)
		if err != nil {
			t.Fatalf("Failed to create validator: %v", err)
		}

		if err := v.LoadIdentities(context.Background()); err != nil {
			t.Fatalf("Failed to load identities: %v", err)
		}

		identities, err := v.GetValidIdentities()
		if err != nil {
			t.Fatalf("Failed to get valid identities: %v", err)
		}

		// should return all latest and non-expired approved identities (2 latest + 2 non-expired approved = 4)
		expectedCount := 4
		if len(identities) != expectedCount {
			t.Errorf("GetValidIdentities() returned %d identities, expected %d", len(identities), expectedCount)
		}

		// Check that expired identity is not included
		for _, id := range identities {
			expiredID := "https://github.com/liatrio/test-repo/.github/workflows/test3.yaml@refs/tags/v0.9.0"
			for _, ident := range id.Identities {
				if ident == expiredID {
					t.Errorf("GetValidIdentities() included expired identity: %s", ident)
				}
			}
		}
	})
}

func TestCaching(t *testing.T) {
	// create a temp file
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, ".cache")

	// create test data
	today := time.Now().Format("2006-01-02")
	testData := `{
		"identities": [
			{
				"version": "1.0.0",
				"sha": "abcdef1234567890",
				"status": "approved",
				"identities": ["https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v1.0.0"],
				"added": "` + today + `"
			}
		],
		"metadata": {
			"last_updated": "` + today + `",
			"version": "1.0.0",
			"maintainer": "Test"
		}
	}`

	// create test server
	serverHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits++
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(testData))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// test caching
	t.Run("Cache Enabled", func(t *testing.T) {
		opts := Options{
			URL:          server.URL,
			DisableCache: false,
			CacheDir:     cacheDir,
		}

		// request should hit server
		v, err := NewValidator(opts)
		if err != nil {
			t.Fatalf("Failed to create validator: %v", err)
		}
		if err := v.LoadIdentities(context.Background()); err != nil {
			t.Fatalf("Failed to load identities: %v", err)
		}

		initialHits := serverHits

		// second request should use cache
		v, err = NewValidator(opts)
		if err != nil {
			t.Fatalf("Failed to create validator: %v", err)
		}
		if err := v.LoadIdentities(context.Background()); err != nil {
			t.Fatalf("Failed to load identities: %v", err)
		}

		if serverHits != initialHits {
			t.Errorf("Cache not used, server hit count increased from %d to %d", initialHits, serverHits)
		}
	})

	// test cache disabled
	t.Run("Cache Disabled", func(t *testing.T) {
		opts := Options{
			URL:          server.URL,
			DisableCache: true,
			CacheDir:     cacheDir,
		}

		initialHits := serverHits

		// with cache disabled, should hit server
		v, err := NewValidator(opts)
		if err != nil {
			t.Fatalf("Failed to create validator: %v", err)
		}
		if err := v.LoadIdentities(context.Background()); err != nil {
			t.Fatalf("Failed to load identities: %v", err)
		}

		if serverHits <= initialHits {
			t.Errorf("Server not hit despite cache being disabled")
		}
	})
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestGetValidIdentitySANs(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test-identities.json")

	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")

	const (
		shaRevoked      = "1111111111111111111111111111111111111111" // 40-hex, matches the by-sha revoked entry
		sanValid1       = "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v1.1.0"
		sanValid2       = "https://github.com/liatrio/test-repo/.github/workflows/test2.yaml@refs/tags/v1.0.0"
		sanRevokedBySAN = "https://github.com/liatrio/test-repo/.github/workflows/old.yaml@refs/tags/v0.5.0"
		sanRevokedBySha = "https://github.com/liatrio/test-repo/.github/workflows/sha.yaml@" + shaRevoked
		sanExpired      = "https://github.com/liatrio/test-repo/.github/workflows/expired.yaml@refs/tags/v0.1.0"
	)

	// revoked entries are placed FIRST so IsValidIdentity (which short-circuits on the
	// first valid match per entry) catches the cross-entry revocation. this exercises the
	// drop logic with exact parity to the single-identity guard it replaces. (in real
	// cert-identities.json SANs are version-unique, so a revoked version's SANs never also
	// appear under an approved entry — GetValidIdentities' status filter already excludes them.)
	testData := `{
		"identities": [
			{"version": "0.5.0", "sha": "deadbeefdeadbeef", "status": "revoked", "identities": ["` + sanRevokedBySAN + `"], "added": "` + yesterday + `", "revoked": "` + today + `", "reason": "revoked by SAN"},
			{"version": "0.4.0", "sha": "` + shaRevoked + `", "status": "revoked", "identities": [], "added": "` + yesterday + `", "revoked": "` + today + `", "reason": "revoked by sha"},
			{"version": "1.1.0", "sha": "abcabcabcabcabca", "status": "latest", "identities": ["` + sanValid1 + `"], "added": "` + today + `"},
			{"version": "1.0.0", "sha": "abcabcabcabcabcb", "status": "approved", "identities": ["` + sanValid2 + `", "` + sanValid1 + `"], "added": "` + yesterday + `", "expires": "` + tomorrow + `"},
			{"version": "0.9.0", "sha": "abcabcabcabcabcc", "status": "approved", "identities": ["` + sanRevokedBySAN + `"], "added": "` + yesterday + `", "expires": "` + tomorrow + `"},
			{"version": "0.8.0", "sha": "abcabcabcabcabcd", "status": "approved", "identities": ["` + sanRevokedBySha + `"], "added": "` + yesterday + `", "expires": "` + tomorrow + `"},
			{"version": "0.1.0", "sha": "abcabcabcabcabce", "status": "approved", "identities": ["` + sanExpired + `"], "added": "` + yesterday + `", "expires": "` + yesterday + `"}
		],
		"metadata": {"last_updated": "` + today + `", "version": "1.0.0", "maintainer": "Test"}
	}`

	if err := os.WriteFile(testFile, []byte(testData), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	v, err := NewValidator(Options{URL: testFile, DisableCache: true})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	if err := v.LoadIdentities(context.Background()); err != nil {
		t.Fatalf("LoadIdentities: %v", err)
	}

	sans, err := v.GetValidIdentitySANs()
	if err != nil {
		t.Fatalf("GetValidIdentitySANs: %v", err)
	}

	got := make(map[string]int)
	for _, s := range sans {
		got[s]++
	}

	// valid SANs returned, deduped (sanValid1 appears under both latest + approved → once)
	want := map[string]bool{sanValid1: true, sanValid2: true}
	for w := range want {
		if got[w] != 1 {
			t.Errorf("expected %q exactly once, got %d (full set: %v)", w, got[w], sans)
		}
	}
	// excluded: expired entry's SAN, cross-entry revoked-by-SAN, cross-entry revoked-by-sha
	for _, excluded := range []string{sanExpired, sanRevokedBySAN, sanRevokedBySha} {
		if got[excluded] != 0 {
			t.Errorf("expected %q to be excluded, but it was present (full set: %v)", excluded, sans)
		}
	}
	if len(sans) != 2 {
		t.Errorf("expected exactly 2 valid SANs, got %d: %v", len(sans), sans)
	}
}

func TestIsValidIdentityRevocationOrderIndependent(t *testing.T) {
	// a SAN/sha named in a status:"revoked" entry must be rejected regardless of whether
	// the revoked entry is listed before OR after a valid entry naming it (revocation is
	// checked across all entries before any match is accepted). both the SAN-match and the
	// sha-match revocation paths are exercised so neither invariant can silently regress.
	today := time.Now().Format("2006-01-02")
	tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")

	// by-SAN: the revoked entry names the SAN in its identities list
	const san = "https://github.com/liatrio/test-repo/.github/workflows/dup.yaml@refs/tags/v1.0.0"
	approvedSAN := `{"version": "1.0.0", "sha": "aaaaaaaaaaaaaaaa", "status": "approved", "identities": ["` + san + `"], "added": "` + today + `", "expires": "` + tomorrow + `"}`
	revokedSAN := `{"version": "0.9.0", "sha": "bbbbbbbbbbbbbbbb", "status": "revoked", "identities": ["` + san + `"], "added": "` + today + `", "revoked": "` + today + `", "reason": "compromised"}`

	// by-sha: the candidate SAN embeds a 40-hex sha and a separate revoked entry revokes
	// that sha (with no matching SAN), exercising the id.Sha == certSHA revocation path
	const revokedSha = "1111111111111111111111111111111111111111"
	const shaSAN = "https://github.com/liatrio/test-repo/.github/workflows/sha.yaml@" + revokedSha
	approvedSha := `{"version": "1.0.0", "sha": "cccccccccccccccc", "status": "approved", "identities": ["` + shaSAN + `"], "added": "` + today + `", "expires": "` + tomorrow + `"}`
	revokedShaEntry := `{"version": "0.9.0", "sha": "` + revokedSha + `", "status": "revoked", "identities": [], "added": "` + today + `", "revoked": "` + today + `", "reason": "sha compromised"}`

	cases := []struct {
		name  string
		body  string
		query string
	}{
		{"by-SAN, revoked before approved", `{"identities": [` + revokedSAN + `,` + approvedSAN + `], "metadata": {}}`, san},
		{"by-SAN, approved before revoked", `{"identities": [` + approvedSAN + `,` + revokedSAN + `], "metadata": {}}`, san},
		{"by-sha, revoked before approved", `{"identities": [` + revokedShaEntry + `,` + approvedSha + `], "metadata": {}}`, shaSAN},
		{"by-sha, approved before revoked", `{"identities": [` + approvedSha + `,` + revokedShaEntry + `], "metadata": {}}`, shaSAN},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "list.json")
			if err := os.WriteFile(p, []byte(tc.body), 0644); err != nil {
				t.Fatal(err)
			}
			v, err := NewValidator(Options{URL: p, DisableCache: true})
			if err != nil {
				t.Fatalf("NewValidator: %v", err)
			}
			if err := v.LoadIdentities(context.Background()); err != nil {
				t.Fatalf("LoadIdentities: %v", err)
			}
			ok, err := v.IsValidIdentity(tc.query)
			if ok || err == nil || !strings.Contains(err.Error(), "revoked") {
				t.Errorf("expected (false, revoked) regardless of entry order, got ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestResolveAcceptedIdentities(t *testing.T) {
	today := time.Now().Format("2006-01-02")
	tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")

	const (
		listSAN1    = "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-image.yaml@refs/tags/v0.28.0"
		listSAN2    = "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-verify.yaml@refs/tags/v0.28.0"
		extIdentity = "https://github.com/liatrio/autogov/.github/workflows/build.yml@refs/heads/main"
	)

	writeList := func(t *testing.T, body string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "list.json")
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			t.Fatalf("write list: %v", err)
		}
		return p
	}

	validList := `{
		"identities": [
			{"version": "0.28.0", "sha": "aaaaaaaaaaaaaaaa", "status": "latest", "identities": ["` + listSAN1 + `", "` + listSAN2 + `"], "added": "` + today + `", "expires": "` + tomorrow + `"}
		],
		"metadata": {"last_updated": "` + today + `", "version": "1.0.0", "maintainer": "Test"}
	}`

	t.Run("cert-identity only is accepted as-typed (no list, not revocation-checked)", func(t *testing.T) {
		got, err := ResolveAcceptedIdentities(context.Background(), extIdentity, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0] != extIdentity {
			t.Errorf("expected [%q], got %v", extIdentity, got)
		}
	})

	t.Run("list only resolves to the list SANs (#257: enforced, not ignored)", func(t *testing.T) {
		opts := Options{URL: writeList(t, validList), DisableCache: true}
		got, err := ResolveAcceptedIdentities(context.Background(), "", &opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 || !slices.Contains(got, listSAN1) || !slices.Contains(got, listSAN2) {
			t.Errorf("expected list SANs, got %v", got)
		}
	})

	t.Run("union of cert-identity and list, deduped", func(t *testing.T) {
		opts := Options{URL: writeList(t, validList), DisableCache: true}
		got, err := ResolveAcceptedIdentities(context.Background(), extIdentity, &opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// cert-identity first, then the two list SANs
		if len(got) != 3 || got[0] != extIdentity || !slices.Contains(got, listSAN1) || !slices.Contains(got, listSAN2) {
			t.Errorf("expected union [%q, list...], got %v", extIdentity, got)
		}
	})

	t.Run("cert-identity that is also a list SAN is not duplicated", func(t *testing.T) {
		opts := Options{URL: writeList(t, validList), DisableCache: true}
		got, err := ResolveAcceptedIdentities(context.Background(), listSAN1, &opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("expected 2 deduped identities, got %d: %v", len(got), got)
		}
	})

	t.Run("malformed list fails closed (never accept-any)", func(t *testing.T) {
		opts := Options{URL: writeList(t, "this is not json"), DisableCache: true}
		got, err := ResolveAcceptedIdentities(context.Background(), extIdentity, &opts)
		if err == nil {
			t.Fatalf("expected error for malformed list, got nil (resolved: %v)", got)
		}
		if got != nil {
			t.Errorf("expected nil result on error, got %v", got)
		}
	})

	t.Run("neither cert-identity nor list yields empty (unsafe handled upstream)", func(t *testing.T) {
		got, err := ResolveAcceptedIdentities(context.Background(), "", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected empty, got %v", got)
		}
	})

	// all entries revoked (by status) or expired → GetValidIdentitySANs yields nothing.
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	allInvalidList := `{
		"identities": [
			{"version": "0.1.0", "sha": "aaaaaaaaaaaaaaaa", "status": "revoked", "identities": ["` + listSAN1 + `"], "added": "` + yesterday + `", "revoked": "` + today + `", "reason": "test"},
			{"version": "0.2.0", "sha": "bbbbbbbbbbbbbbbb", "status": "approved", "identities": ["` + listSAN2 + `"], "added": "` + yesterday + `", "expires": "` + yesterday + `"}
		],
		"metadata": {"last_updated": "` + today + `", "version": "1.0.0", "maintainer": "Test"}
	}`

	t.Run("list configured but all revoked/expired fails closed (SLSA: never accept-any)", func(t *testing.T) {
		// #257: a list the operator asked to enforce that resolves to zero acceptable
		// identities (no --cert-identity) must NOT degrade to WithoutIdentitiesUnsafe.
		opts := Options{URL: writeList(t, allInvalidList), DisableCache: true}
		got, err := ResolveAcceptedIdentities(context.Background(), "", &opts)
		if err == nil {
			t.Fatalf("expected fail-closed error for all-revoked/expired list with no --cert-identity, got nil (resolved: %v)", got)
		}
		if got != nil {
			t.Errorf("expected nil result on fail-closed, got %v", got)
		}
	})

	t.Run("cert-identity present is accepted even when the list resolves empty (accepted as-typed)", func(t *testing.T) {
		// the empty-allowlist guard must only bite when accepted is truly empty; a
		// supplied --cert-identity (accepted as-typed) keeps the run valid.
		opts := Options{URL: writeList(t, allInvalidList), DisableCache: true}
		got, err := ResolveAcceptedIdentities(context.Background(), extIdentity, &opts)
		if err != nil {
			t.Fatalf("unexpected error when --cert-identity is set: %v", err)
		}
		if len(got) != 1 || got[0] != extIdentity {
			t.Errorf("expected [%q] (cert-identity as-typed, list contributes nothing), got %v", extIdentity, got)
		}
	})
}

func TestGetValidIdentitySANsSkipsEmpty(t *testing.T) {
	// an empty-string SAN must not leak into the result: IsValidIdentity("") matches an
	// empty-SAN entry as (true, nil), so it is filtered at the candidate stage instead.
	today := time.Now().Format("2006-01-02")
	tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")
	const realSAN = "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v1.0.0"

	data := `{
		"identities": [
			{"version": "1.0.0", "sha": "abcabcabcabcabca", "status": "approved", "identities": ["", "` + realSAN + `"], "added": "` + today + `", "expires": "` + tomorrow + `"}
		],
		"metadata": {"last_updated": "` + today + `", "version": "1.0.0", "maintainer": "Test"}
	}`

	p := filepath.Join(t.TempDir(), "list.json")
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatalf("write list: %v", err)
	}
	v, err := NewValidator(Options{URL: p, DisableCache: true})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	if err := v.LoadIdentities(context.Background()); err != nil {
		t.Fatalf("LoadIdentities: %v", err)
	}

	sans, err := v.GetValidIdentitySANs()
	if err != nil {
		t.Fatalf("GetValidIdentitySANs: %v", err)
	}
	if slices.Contains(sans, "") {
		t.Errorf("empty-string SAN leaked into result: %v", sans)
	}
	if len(sans) != 1 || sans[0] != realSAN {
		t.Errorf("expected exactly [%q], got %v", realSAN, sans)
	}
}

// the on-disk cache filename is derived from sha256(Options.URL), so two
// validators with different URLs but the SAME CacheDir never read or write the
// same file. a cache warmed from url A must NOT be served for url B; B refetches.
func TestCacheKeyedByURL(t *testing.T) {
	today := time.Now().Format("2006-01-02")
	const (
		sanA = "https://github.com/liatrio/test-repo/.github/workflows/a.yaml@refs/tags/v1.0.0"
		sanB = "https://github.com/liatrio/test-repo/.github/workflows/b.yaml@refs/tags/v1.0.0"
	)
	mkBody := func(san string) string {
		return `{"identities":[{"version":"1.0.0","sha":"abcabcabcabcabca","status":"latest","identities":["` + san + `"],"added":"` + today + `"}],"metadata":{"last_updated":"` + today + `","version":"1.0.0","maintainer":"Test"}}`
	}

	bodyA, bodyB := mkBody(sanA), mkBody(sanB)
	var hitsA, hitsB int
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hitsA++
		_, _ = w.Write([]byte(bodyA))
	}))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hitsB++
		_, _ = w.Write([]byte(bodyB))
	}))
	defer srvB.Close()

	cacheDir := t.TempDir() // one shared CacheDir for both validators

	// warm the cache from url A
	vA, err := NewValidator(Options{URL: srvA.URL, CacheDir: cacheDir})
	if err != nil {
		t.Fatalf("NewValidator(A): %v", err)
	}
	if err := vA.LoadIdentities(context.Background()); err != nil {
		t.Fatalf("LoadIdentities(A): %v", err)
	}
	if hitsA != 1 {
		t.Fatalf("expected url A hit once warming cache, got %d", hitsA)
	}

	// load url B against the SAME CacheDir: must NOT be served A's warm cache
	vB, err := NewValidator(Options{URL: srvB.URL, CacheDir: cacheDir})
	if err != nil {
		t.Fatalf("NewValidator(B): %v", err)
	}
	if err := vB.LoadIdentities(context.Background()); err != nil {
		t.Fatalf("LoadIdentities(B): %v", err)
	}

	// (a) B's server is hit at least once (fresh fetch, not A's cache)
	if hitsB < 1 {
		t.Errorf("expected url B to be fetched (cross-url cache must not serve A's data), got %d hits", hitsB)
	}

	// (b) the two cache files on disk have different names
	pathA, pathB := vA.cacheFilePath(), vB.cacheFilePath()
	if pathA == pathB {
		t.Fatalf("expected distinct url-keyed cache filenames, both = %q", pathA)
	}
	if _, err := os.Stat(pathA); err != nil {
		t.Errorf("url A cache file missing: %v", err)
	}
	if _, err := os.Stat(pathB); err != nil {
		t.Errorf("url B cache file missing: %v", err)
	}

	// (c) B's loaded list matches B's body, not A's
	sansB, err := vB.GetValidIdentitySANs()
	if err != nil {
		t.Fatalf("GetValidIdentitySANs(B): %v", err)
	}
	if !slices.Contains(sansB, sanB) || slices.Contains(sansB, sanA) {
		t.Errorf("url B served the wrong (cross-url) list: got %v, want only %q", sansB, sanB)
	}
}

// the cache file must be written 0600 (owner-only): the allowlist is
// security-relevant local state.
func TestCacheFileMode0600(t *testing.T) {
	today := time.Now().Format("2006-01-02")
	body := `{"identities":[{"version":"1.0.0","sha":"abcabcabcabcabca","status":"latest","identities":["https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/tags/v1.0.0"],"added":"` + today + `"}],"metadata":{"last_updated":"` + today + `","version":"1.0.0","maintainer":"Test"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	v, err := NewValidator(Options{URL: srv.URL, CacheDir: cacheDir})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	if err := v.LoadIdentities(context.Background()); err != nil {
		t.Fatalf("LoadIdentities: %v", err)
	}

	fi, err := os.Stat(v.cacheFilePath())
	if err != nil {
		t.Fatalf("stat cache file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("cache file mode = %#o, want 0600", perm)
	}
}

// an as-typed --cert-identity that the list marks revoked/expired is still
// accepted (no behavior change) but emits exactly ONE stderr warning. a SAN that
// is valid, merely absent (ordinary vouch), or supplied with no list at all gets
// no warning.
func TestResolveAcceptedWarnsOnRevokedAsTyped(t *testing.T) {
	// capture warnings into a buffer; restore in cleanup
	var warnings []string
	orig := warnf
	warnf = func(format string, a ...any) { warnings = append(warnings, fmt.Sprintf(format, a...)) }
	t.Cleanup(func() { warnf = orig })

	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")

	const (
		sanRevoked = "https://github.com/liatrio/test-repo/.github/workflows/revoked.yaml@refs/tags/v0.5.0"
		sanExpired = "https://github.com/liatrio/test-repo/.github/workflows/expired.yaml@refs/tags/v0.6.0"
		sanValid   = "https://github.com/liatrio/test-repo/.github/workflows/valid.yaml@refs/tags/v1.0.0"
		sanAbsent  = "https://github.com/liatrio/test-repo/.github/workflows/absent.yaml@refs/heads/main"
	)

	// ONE fixture list: a revoked SAN R, an expired approved SAN E, and a valid latest SAN V.
	list := `{
		"identities": [
			{"version":"0.5.0","sha":"aaaaaaaaaaaaaaaa","status":"revoked","identities":["` + sanRevoked + `"],"added":"` + yesterday + `","revoked":"` + today + `","reason":"compromised"},
			{"version":"0.6.0","sha":"bbbbbbbbbbbbbbbb","status":"approved","identities":["` + sanExpired + `"],"added":"` + yesterday + `","expires":"` + yesterday + `"},
			{"version":"1.0.0","sha":"cccccccccccccccc","status":"latest","identities":["` + sanValid + `"],"added":"` + today + `","expires":"` + tomorrow + `"}
		],
		"metadata": {"last_updated":"` + today + `","version":"1.0.0","maintainer":"Test"}
	}`

	writeList := func(t *testing.T, body string) *Options {
		t.Helper()
		p := filepath.Join(t.TempDir(), "list.json")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write list: %v", err)
		}
		return &Options{URL: p, DisableCache: true}
	}

	reset := func() { warnings = nil }

	t.Run("positive: revoked as-typed accepted + exactly one warning", func(t *testing.T) {
		reset()
		got, err := ResolveAcceptedIdentities(context.Background(), sanRevoked, writeList(t, list))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !slices.Contains(got, sanRevoked) {
			t.Errorf("revoked as-typed identity must still be accepted, got %v", got)
		}
		if len(warnings) != 1 {
			t.Fatalf("expected exactly one warning, got %d: %v", len(warnings), warnings)
		}
		if !strings.HasPrefix(warnings[0], "warning:") || !strings.Contains(warnings[0], "revoked") || !strings.Contains(warnings[0], sanRevoked) {
			t.Errorf("warning text wrong: %q", warnings[0])
		}
	})

	t.Run("positive: expired as-typed accepted + exactly one warning", func(t *testing.T) {
		reset()
		got, err := ResolveAcceptedIdentities(context.Background(), sanExpired, writeList(t, list))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !slices.Contains(got, sanExpired) {
			t.Errorf("expired as-typed identity must still be accepted, got %v", got)
		}
		if len(warnings) != 1 {
			t.Fatalf("expected exactly one warning, got %d: %v", len(warnings), warnings)
		}
		if !strings.Contains(warnings[0], "expired") || !strings.Contains(warnings[0], sanExpired) {
			t.Errorf("warning text wrong: %q", warnings[0])
		}
	})

	t.Run("negative: valid-in-list as-typed → no warning", func(t *testing.T) {
		reset()
		got, err := ResolveAcceptedIdentities(context.Background(), sanValid, writeList(t, list))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !slices.Contains(got, sanValid) {
			t.Errorf("valid identity must be accepted, got %v", got)
		}
		if len(warnings) != 0 {
			t.Errorf("expected no warning for a genuinely valid identity, got %v", warnings)
		}
	})

	t.Run("negative: absent (ordinary vouch) as-typed → no warning", func(t *testing.T) {
		reset()
		got, err := ResolveAcceptedIdentities(context.Background(), sanAbsent, writeList(t, list))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !slices.Contains(got, sanAbsent) {
			t.Errorf("absent as-typed identity must still be accepted (vouch), got %v", got)
		}
		if len(warnings) != 0 {
			t.Errorf("expected no warning for an absent (not revoked/expired) identity, got %v", warnings)
		}
	})

	t.Run("negative: no list → accepted, no warning, no load", func(t *testing.T) {
		reset()
		got, err := ResolveAcceptedIdentities(context.Background(), sanRevoked, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0] != sanRevoked {
			t.Errorf("expected [%q] accepted as-typed with no list, got %v", sanRevoked, got)
		}
		if len(warnings) != 0 {
			t.Errorf("expected no warning when no list is supplied, got %v", warnings)
		}
	})

	t.Run("edge: revoked as-typed with an all-revoked/expired list → accepted, one warning, no fail-closed", func(t *testing.T) {
		reset()
		// every entry is revoked or expired → GetValidIdentitySANs yields nothing.
		// the warning must fire BEFORE the len(accepted)==0 guard, which does not trip
		// because the revoked as-typed identity was added.
		allInvalid := `{
			"identities": [
				{"version":"0.5.0","sha":"aaaaaaaaaaaaaaaa","status":"revoked","identities":["` + sanRevoked + `"],"added":"` + yesterday + `","revoked":"` + today + `","reason":"compromised"},
				{"version":"0.6.0","sha":"bbbbbbbbbbbbbbbb","status":"approved","identities":["` + sanExpired + `"],"added":"` + yesterday + `","expires":"` + yesterday + `"}
			],
			"metadata": {"last_updated":"` + today + `","version":"1.0.0","maintainer":"Test"}
		}`
		got, err := ResolveAcceptedIdentities(context.Background(), sanRevoked, writeList(t, allInvalid))
		if err != nil {
			t.Fatalf("must not fail closed when the revoked as-typed identity keeps the set non-empty: %v", err)
		}
		if len(got) != 1 || got[0] != sanRevoked {
			t.Errorf("expected [%q] accepted, got %v", sanRevoked, got)
		}
		if len(warnings) != 1 {
			t.Errorf("expected exactly one warning, got %d: %v", len(warnings), warnings)
		}
	})
}
