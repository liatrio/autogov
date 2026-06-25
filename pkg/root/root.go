package root

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"

	_ "embed"

	"github.com/cli/go-gh/v2"
	sigstorego_root "github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

//go:embed github-trusted-root.json
var GithubTrustedRoot []byte

// static snapshot of the public-good Sigstore trusted root. by default this
// embedded snapshot is used (hermetic, offline-capable). an opt-in live refresh
// (--refresh-trusted-root) replaces it via RefreshPublicTrustedRoot before
// verification; the embedded snapshot is re-vendored periodically via
// `task vendor-public-trusted-root` so it can't silently rot.
//
//go:embed public-trusted-root.json
var PublicSigstoreTrustedRoot []byte

// fetchPublicTrustedRoot fetches the public-good Sigstore trusted root live from
// the Sigstore TUF repo. seam for tests.
var fetchPublicTrustedRoot = func() ([]byte, error) {
	tr, err := sigstorego_root.FetchTrustedRootWithOptions(tuf.DefaultOptions())
	if err != nil {
		return nil, err
	}
	return tr.MarshalJSON()
}

// holds the live-refreshed public-good root once RefreshPublicTrustedRoot
// succeeds; nil means GetPublicTrustedRoot serves the embedded snapshot. this is
// process-global state shared by every verification in the process — correct for
// the single-shot CLI; an embedding library doing concurrent verifications with
// differing refresh policies would need to inject the root explicitly instead.
var (
	publicTrustedRootMu   sync.RWMutex
	livePublicTrustedRoot []byte
)

// RefreshPublicTrustedRoot fetches the public-good Sigstore trusted root live
// from the Sigstore TUF repo and, on success, makes GetPublicTrustedRoot serve
// it for the rest of the process. it is fail-closed: any fetch or parse error is
// returned and nothing is cached, so the caller must abort rather than fall back
// to the embedded snapshot. only invoke this when the operator opts in via
// --refresh-trusted-root; otherwise GetPublicTrustedRoot keeps serving the
// embedded snapshot (unchanged hermetic behavior).
func RefreshPublicTrustedRoot() error {
	data, err := fetchPublicTrustedRoot()
	if err != nil {
		return fmt.Errorf("failed to refresh public-good trusted root from TUF: %w", err)
	}
	// validate the fetched root parses before trusting it; never cache garbage.
	if _, err := sigstorego_root.NewTrustedRootFromJSON(data); err != nil {
		return fmt.Errorf("refreshed public-good trusted root is invalid: %w", err)
	}
	publicTrustedRootMu.Lock()
	livePublicTrustedRoot = data
	publicTrustedRootMu.Unlock()
	return nil
}

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
// to the embedded root if the dynamic fetch fails. note this GitHub-root path
// is intentionally fail-OPEN (embedded fallback) because the GitHub root is
// stable; the public-good root rotates, so its live refresh
// (RefreshPublicTrustedRoot) is fail-CLOSED instead.
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
	// the Fulcio CA that issued the cert determines which trusted root can chain
	// it, so prefer the issuer over the OIDC issuer extension: the latter is
	// identical (token.actions.githubusercontent.com) for both GitHub's internal
	// Fulcio and the public-good Sigstore Fulcio that public repositories use.
	issuer := strings.ToLower(strings.Join(cert.Issuer.Organization, " ") + " " + cert.Issuer.CommonName)
	switch {
	case strings.Contains(issuer, "sigstore"):
		return TrustedRootSourcePublic, nil
	case strings.Contains(issuer, "github"):
		return TrustedRootSourceGitHub, nil
	}

	// fall back to the fulcio OIDC issuer extension (OID 1.3.6.1.4.1.57264.1.1)
	const fulcioIssuerOID = "1.3.6.1.4.1.57264.1.1"
	for _, ext := range cert.Extensions {
		if ext.Id.String() == fulcioIssuerOID {
			return detectFromIssuer(string(ext.Value)), nil
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

// returns the public sigstore trusted root: the live-refreshed root if
// RefreshPublicTrustedRoot succeeded this run, otherwise the embedded snapshot.
func GetPublicTrustedRoot() []byte {
	publicTrustedRootMu.RLock()
	defer publicTrustedRootMu.RUnlock()
	if livePublicTrustedRoot != nil {
		return livePublicTrustedRoot
	}
	return PublicSigstoreTrustedRoot
}

// returns embedded github trusted root
func GetGitHubTrustedRoot() []byte {
	return GithubTrustedRoot
}
