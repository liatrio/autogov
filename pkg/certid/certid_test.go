package certid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
				"identities": ["https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/heads/main"],
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
			certIdentity: "https://github.com/liatrio/test-repo/.github/workflows/test.yaml@refs/heads/main",
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
