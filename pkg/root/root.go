package root

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	_ "embed"

	"github.com/cli/go-gh/v2"
)

//go:embed github-trusted-root.json
var GithubTrustedRoot []byte

//go:embed public-trusted-root.json
var PublicSigstoreTrustedRoot []byte

// trusted root source selection
type TrustedRootSource string

const (
	TrustedRootSourceGitHub TrustedRootSource = "github"
	TrustedRootSourcePublic TrustedRootSource = "public"
	TrustedRootSourceAuto   TrustedRootSource = "auto"
)

// known OIDC issuers for auto-detection
const (
	GitHubActionsIssuer = "https://token.actions.githubusercontent.com"
	GoogleOIDCIssuer    = "https://accounts.google.com"
	GitHubOAuthIssuer   = "https://github.com/login/oauth"
	GitLabIssuer        = "https://gitlab.com"
)

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

// selects trusted root based on source and optional certificate
func SelectTrustedRoot(source TrustedRootSource, certPEM []byte) ([]byte, TrustedRootSource, error) {
	switch source {
	case TrustedRootSourceGitHub:
		fmt.Println("✓ Using GitHub trusted root (explicit)")
		return GithubTrustedRoot, TrustedRootSourceGitHub, nil
	case TrustedRootSourcePublic:
		fmt.Println("✓ Using public Sigstore trusted root (explicit)")
		return PublicSigstoreTrustedRoot, TrustedRootSourcePublic, nil
	case TrustedRootSourceAuto:
		// auto-detect from cert issuer
		if len(certPEM) > 0 {
			detectedSource, err := DetectTrustedRootFromCert(certPEM)
			if err == nil {
				if detectedSource == TrustedRootSourceGitHub {
					fmt.Println("✓ Using GitHub trusted root (auto-detected from certificate)")
					return GithubTrustedRoot, TrustedRootSourceGitHub, nil
				}
				fmt.Println("✓ Using public Sigstore trusted root (auto-detected from certificate)")
				return PublicSigstoreTrustedRoot, TrustedRootSourcePublic, nil
			}
			fmt.Printf("! Could not auto-detect trusted root from certificate: %v\n", err)
		}
		// default to github for backward compatibility
		fmt.Println("✓ Using GitHub trusted root (default)")
		return GithubTrustedRoot, TrustedRootSourceGitHub, nil
	default:
		return nil, "", fmt.Errorf("unknown trusted root source: %s", source)
	}
}

// detects trusted root from certificate's OIDC issuer
func DetectTrustedRootFromCert(certPEM []byte) (TrustedRootSource, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		// try DER directly
		cert, err := x509.ParseCertificate(certPEM)
		if err != nil {
			return "", fmt.Errorf("failed to parse certificate: %w", err)
		}
		return detectFromCert(cert)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	return detectFromCert(cert)
}

// determines trusted root from parsed certificate
func detectFromCert(cert *x509.Certificate) (TrustedRootSource, error) {
	// fulcio uses OID 1.3.6.1.4.1.57264.1.1 for OIDC issuer
	const fulcioIssuerOID = "1.3.6.1.4.1.57264.1.1"

	for _, ext := range cert.Extensions {
		if ext.Id.String() == fulcioIssuerOID {
			issuer := string(ext.Value)
			return detectFromIssuer(issuer), nil
		}
	}

	// fallback: check cert issuer org
	if len(cert.Issuer.Organization) > 0 {
		org := cert.Issuer.Organization[0]
		if strings.Contains(strings.ToLower(org), "github") {
			return TrustedRootSourceGitHub, nil
		}
		if strings.Contains(strings.ToLower(org), "sigstore") {
			return TrustedRootSourcePublic, nil
		}
	}

	return "", fmt.Errorf("could not determine trusted root from certificate")
}

// maps OIDC issuer URL to trusted root source
func detectFromIssuer(issuer string) TrustedRootSource {
	switch issuer {
	case GitHubActionsIssuer:
		return TrustedRootSourceGitHub
	case GoogleOIDCIssuer, GitHubOAuthIssuer, GitLabIssuer:
		return TrustedRootSourcePublic
	default:
		if strings.Contains(issuer, "github") && strings.Contains(issuer, "actions") {
			return TrustedRootSourceGitHub
		}
		return TrustedRootSourcePublic
	}
}

// returns embedded public sigstore trusted root
func GetPublicTrustedRoot() []byte {
	return PublicSigstoreTrustedRoot
}

// returns embedded github trusted root
func GetGitHubTrustedRoot() []byte {
	return GithubTrustedRoot
}
