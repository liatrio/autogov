package root

import (
	"encoding/json"
	"fmt"
	"strings"

	_ "embed"

	"github.com/cli/go-gh/v2"
)

//go:embed github-trusted-root.json
var GithubTrustedRoot []byte

// fetches gh trusted root
func FetchTrustedRoot() ([]byte, error) {
	stdout, stderr, err := gh.Exec("attestation", "trusted-root")
	if err != nil {
		return nil, fmt.Errorf("failed to get trusted root: %v (stderr: %s)", err, stderr.String())
	}

	lines := strings.Split(stdout.String(), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var trustedRoot map[string]interface{}
		if err := json.Unmarshal([]byte(line), &trustedRoot); err != nil {
			continue
		}

		// check if trusted root contains fulcio.githubapp.com certificate authority
		if cas, ok := trustedRoot["certificateAuthorities"].([]interface{}); ok {
			for _, ca := range cas {
				if caMap, ok := ca.(map[string]interface{}); ok {
					if uri, ok := caMap["uri"].(string); ok && uri == "fulcio.githubapp.com" {
						return json.MarshalIndent(trustedRoot, "", "  ")
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("no trusted root found for fulcio.githubapp.com")
}

// returns the GitHub trusted root with fallback mechanism.
// first attempts to fetch the latest root dynamically, and falls back
// to the embedded root if the dynamic fetch fails.
func GetTrustedRoot() ([]byte, error) {
	// try to fetch dynamically first
	trustedRoot, err := FetchTrustedRoot()
	if err == nil {
		fmt.Println("✓ Using dynamically fetched trusted root")
		return trustedRoot, nil
	}

	// fallback to the embedded root if fetching fails
	fmt.Printf("! Failed to fetch dynamic trusted root (%v), falling back to embedded version\n", err)
	return GithubTrustedRoot, nil
}
