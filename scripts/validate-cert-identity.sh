#!/bin/bash
set -eo pipefail

# test script that validates certificate identities locally

# do cert-identities.json exists ?
if [ ! -f cert-identities.json ]; then
  echo "Creating cert-identities.json in current directory..."
  cat > cert-identities.json << 'EOL'
{
  "latest": [
    {
      "name": "HP Attest Image",
      "version": "1.0.0",
      "identity": "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-image.yaml@refs/heads/main",
      "added": "2024-10-22"
    },
    {
      "name": "LP Attest Blob",
      "version": "1.0.0",
      "identity": "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-blob.yaml@refs/heads/main",
      "added": "2024-10-22"
    }
  ],
  "approved": [
    {
      "name": "LP Attest Blob main",
      "version": "0.9.0",
      "identity": "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-blob.yaml@refs/heads/main",
      "added": "2024-10-22",
      "expires": "2026-10-22"
    },
    {
      "name": "LP Attest Blob main (non-normalized)",
      "version": "0.9.0",
      "identity": "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-blob.yaml@main",
      "added": "2024-10-22",
      "expires": "2026-10-22"
    },
    {
      "name": "LP Attest Blob commit SHA",
      "version": "0.8.0",
      "identity": "https://github.com/liatrio/autogov-workflows/.github/workflows/rw-attest-blob.yaml@6177b4481c00308b3839969c3eca88c96a91775f",
      "added": "2024-10-22",
      "expires": "2026-10-22"
    }
  ],
  "revoked": [],
  "metadata": {
    "last_updated": "2024-10-22",
    "version": "1.0.0",
    "maintainer": "Liatrio"
  }
}
EOL
fi

# cli args
if [ $# -eq 0 ]; then
  echo "Usage: $0 <certificate-identity>"
  exit 1
fi

identity="$1"

# basic go app to validate cert-ids
echo "Building validator..."
cat > validator.go << 'EOL'
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// cert-id struct
type CertIdentity struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Identity    string `json:"identity"`
	Added       string `json:"added"`
	Expires     string `json:"expires,omitempty"`
	Revoked     string `json:"revoked,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// cert-id file struct
type CertIdentities struct {
	Latest   []CertIdentity       `json:"latest"`
	Approved []CertIdentity       `json:"approved"`
	Revoked  []CertIdentity       `json:"revoked"`
	Metadata map[string]string    `json:"metadata"`
}

// normalize gh refs
func normalizeRef(ref string) string {
	// no normalize if it looks like a commit SHA (40 hex chars)
	if len(ref) == 40 && isHex(ref) {
		return ref
	}
	
	// handle specific path prefixes
	if strings.HasPrefix(ref, "heads/") {
		return "refs/" + ref
	}
	
	if strings.HasPrefix(ref, "tags/") {
		return "refs/" + ref
	}
	
	// default case for branch names
	if !strings.HasPrefix(ref, "refs/") {
		return "refs/heads/" + ref
	}
	
	return ref
}

// checks hex
func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// normalize full cert0id url
func normalizeIdentity(identity string) string {
	parts := strings.Split(identity, "@")
	if len(parts) != 2 {
		return identity
	}
	
	baseURL := parts[0]
	ref := parts[1]
	
	// norm ref part
	normalizedRef := normalizeRef(ref)
	if normalizedRef == ref {
		return identity // No change needed
	}
	
	return baseURL + "@" + normalizedRef
}

// validate certificate identity
func validateIdentity(identity string) (bool, string, error) {
	data, err := os.ReadFile("cert-identities.json")
	if err != nil {
		return false, "", fmt.Errorf("failed to read cert-identities.json: %w", err)
	}
	
	// parse json
	var identities CertIdentities
	if err := json.Unmarshal(data, &identities); err != nil {
		return false, "", fmt.Errorf("failed to parse cert-identities.json: %w", err)
	}
	
	// check if revoked
	for _, id := range identities.Revoked {
		if id.Identity == identity {
			return false, fmt.Sprintf("Identity is revoked: %s", id.Reason), nil
		}
	}
	
	normalizedIdentity := normalizeIdentity(identity)
	fmt.Printf("Original identity: %s\n", identity)
	if normalizedIdentity != identity {
		fmt.Printf("Normalized to:    %s\n", normalizedIdentity)
	}
	
	for _, id := range identities.Latest {
		if id.Identity == identity || id.Identity == normalizedIdentity {
			fmt.Printf("Found in latest list as: %s\n", id.Identity)
			return true, "", nil
		}
	}
	
	// check approved
	for _, id := range identities.Approved {
		if id.Identity == identity || id.Identity == normalizedIdentity {
			fmt.Printf("Found in approved list as: %s\n", id.Identity)
			
			// check expired
			if id.Expires != "" {
				expiryDate, err := time.Parse("2006-01-02", id.Expires)
				if err != nil {
					return false, "", fmt.Errorf("invalid expiry date format: %w", err)
				}
				if time.Now().After(expiryDate) {
					return false, fmt.Sprintf("Certificate identity has expired (expiry: %s)", id.Expires), nil
				}
			}
			
			return true, "", nil
		}
	}
	
	return false, "Certificate identity not found in any list", nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: validator <cert-identity>")
		os.Exit(1)
	}
	
	identity := os.Args[1]
	
	valid, message, err := validateIdentity(identity)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	
	if valid {
		fmt.Printf("✅ SUCCESS: Certificate identity is valid\n")
		os.Exit(0)
	} else {
		fmt.Printf("❌ FAILED: %s\n", message)
		os.Exit(1)
	}
}
EOL

# Build and run
echo "Validating certificate identity: $identity"
echo "------------------------------------------"

go run validator.go "$identity"
status=$?

# Clean up
rm -f validator.go

exit $status 