package gitsign

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/liatrio/autogov/pkg/root"
)

// VerifyOptions configures gitsign commit verification.
type VerifyOptions struct {
	// CertIdentity is the expected OIDC subject (email or URI) in the certificate SAN.
	CertIdentity string
	// CertIssuer is the expected OIDC issuer URL.
	CertIssuer string
}

// VerificationResult holds the outcome of verifying a single commit.
//
// Verified is true only when the gitsign signature is both cryptographically
// valid (cert chain pinned to a trusted timestamp) AND transparency-bound: a
// verified RFC3161 TSA timestamp on the GitHub-internal path, or a verified
// Rekor inclusion proof on the public-good path. TransparencyVerified records
// the transparency dimension on its own so callers can tell "cms ok but not
// transparency-bound" apart from "cms failed"; Verified is never true while
// TransparencyVerified is false.
type VerificationResult struct {
	CommitHash           string    `json:"commit"`
	Verified             bool      `json:"verified"`
	TransparencyVerified bool      `json:"transparency_verified"`
	Signer               string    `json:"signer,omitempty"`
	Issuer               string    `json:"issuer,omitempty"`
	CertFingerprint      string    `json:"cert_fingerprint,omitempty"`
	Timestamp            time.Time `json:"timestamp,omitempty"`
	RekorLogIndex        int64     `json:"rekor_log_index,omitempty"`
	ErrorMsg             string    `json:"error,omitempty"`
	Unsigned             bool      `json:"unsigned,omitempty"`
}

// OpenRepository opens a git repository at the given path.
func OpenRepository(path string) (*git.Repository, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("verify git: open repository: %w", err)
	}
	return repo, nil
}

// NewMemoryObject returns a new plumbing.MemoryObject for use with EncodeWithoutSignature.
func NewMemoryObject() *plumbing.MemoryObject {
	return new(plumbing.MemoryObject)
}

// VerifyCommit verifies a single commit's gitsign signature.
// Returns a VerificationResult regardless of signed/unsigned status.
// Only returns an error for infrastructure failures (repo access, bad revision).
func VerifyCommit(repo *git.Repository, revision string, opts VerifyOptions) (*VerificationResult, error) {
	hash, err := resolveRevision(repo, revision)
	if err != nil {
		return nil, fmt.Errorf("verify git: resolve revision %q: %w", revision, err)
	}

	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("verify git: get commit %s: %w", hash, err)
	}

	return verifyCommitObject(commit, opts)
}

// VerifyCommitRange verifies all commits in the range [from..to] (both inclusive).
// Unsigned commits are included in results with Unsigned=true, not as errors.
func VerifyCommitRange(repo *git.Repository, from, to string, opts VerifyOptions) ([]*VerificationResult, error) {
	fromHash, err := resolveRevision(repo, from)
	if err != nil {
		return nil, fmt.Errorf("verify git: resolve from ref %q: %w", from, err)
	}

	toHash, err := resolveRevision(repo, to)
	if err != nil {
		return nil, fmt.Errorf("verify git: resolve to ref %q: %w", to, err)
	}

	commits, err := collectCommitRange(repo, fromHash, toHash)
	if err != nil {
		return nil, fmt.Errorf("verify git: collect commit range: %w", err)
	}

	var results []*VerificationResult
	for _, c := range commits {
		r, err := verifyCommitObject(c, opts)
		if err != nil {
			// infrastructure error — propagate
			return nil, err
		}
		results = append(results, r)
	}

	return results, nil
}

// verifyCommitObject performs the actual signature verification for a commit object.
func verifyCommitObject(commit *object.Commit, opts VerifyOptions) (*VerificationResult, error) {
	result := &VerificationResult{
		CommitHash: commit.Hash.String(),
		Timestamp:  commit.Author.When,
	}

	sig := commit.PGPSignature
	if sig == "" {
		result.Unsigned = true
		return result, nil
	}

	// detect PGP armor (standard gpg/ssh signing) before attempting PEM decode,
	// since encoding/pem cannot parse PGP armor (the =CRC line breaks it)
	if strings.Contains(sig, "-----BEGIN PGP SIGNATURE-----") {
		result.ErrorMsg = "unsupported signature type: PGP (not a gitsign/Sigstore signature)"
		return result, nil
	}

	// decode PEM block (gitsign uses "SIGNED MESSAGE" type)
	block, _ := pem.Decode([]byte(sig))
	if block == nil {
		result.ErrorMsg = "unsupported signature format: not PEM-encoded"
		return result, nil
	}

	// only handle CMS/PKCS7 "SIGNED MESSAGE" blocks
	if block.Type != "SIGNED MESSAGE" {
		result.ErrorMsg = fmt.Sprintf("unsupported signature type: %q (expected SIGNED MESSAGE)", block.Type)
		return result, nil
	}

	// get the raw commit content that was signed
	commitData, err := encodeCommitWithoutSignature(commit)
	if err != nil {
		return nil, fmt.Errorf("verify git: encode commit: %w", err)
	}

	// parse CMS/PKCS7
	p7, err := pkcs7.Parse(block.Bytes)
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("failed to parse CMS signature: %v", err)
		return result, nil
	}

	// for detached signatures, set the content to be verified
	p7.Content = commitData

	// extract signer certificate
	signerCert := p7.GetOnlySigner()
	if signerCert == nil {
		result.ErrorMsg = "no signer certificate found in CMS signature"
		return result, nil
	}

	// build Fulcio cert pool from embedded trusted root
	certPool, err := buildFulcioPool()
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("failed to build Fulcio cert pool: %v", err)
		return result, nil
	}

	// establish the trusted time the cert chain must be validated at. a Fulcio
	// signer cert is valid for ~10 minutes, so the entire keyless-signing trust
	// model hinges on pinning chain validation to a timestamp proven to fall
	// inside that window by an independent, tamper-evident anchor — NOT the
	// attacker-asserted CMS signingTime attribute and NOT wall-clock now.
	//
	// the anchor is per backend (see transparency.go):
	//   - GitHub-internal (fulcio.githubapp.com): a verified RFC3161 TSA token.
	//   - public-good (sigstore.dev): a verified Rekor inclusion proof.
	ts, err := establishTrustedTimestamp(block.Bytes, signerCert)
	if err != nil {
		// transparency-unbound: cms may be structurally fine, but we cannot
		// anchor when it was produced, so it does not count as Verified. record
		// a machine-readable marker (TransparencyVerified stays false) so callers
		// distinguish this from a cms failure.
		result.ErrorMsg = fmt.Sprintf("not transparency-verified: %v", err)
		return result, nil
	}

	// the trusted timestamp (TSA genTime / Rekor integrated time) is the
	// authoritative signing time — replace the attacker-controlled commit author
	// time so downstream consumers report the anchored time, not the claimed one.
	result.Timestamp = ts.Time

	// verify the CMS signature with the cert chain pinned to the trusted time.
	// VerifyWithChainAtTime ignores the CMS signingTime attribute and validates
	// the chain at the supplied time.
	if err := p7.VerifyWithChainAtTime(certPool, ts.Time); err != nil {
		result.ErrorMsg = fmt.Sprintf("CMS signature verification failed: %v", err)
		return result, nil
	}

	// extract signer identity from certificate SAN
	signer, issuer := extractIdentity(signerCert)
	result.Signer = signer
	result.Issuer = issuer
	result.CertFingerprint = certFingerprint(signerCert)

	// validate cert-identity if requested
	if opts.CertIdentity != "" && !matchIdentity(signer, opts.CertIdentity) {
		result.ErrorMsg = fmt.Sprintf("cert-identity mismatch: got %q, want %q", signer, opts.CertIdentity)
		return result, nil
	}

	// validate cert-issuer if requested
	if opts.CertIssuer != "" && !strings.EqualFold(issuer, opts.CertIssuer) {
		result.ErrorMsg = fmt.Sprintf("cert-issuer mismatch: got %q, want %q", issuer, opts.CertIssuer)
		return result, nil
	}

	// both cms-at-trusted-time and transparency succeeded.
	result.TransparencyVerified = true
	result.RekorLogIndex = ts.RekorLogIndex
	result.Verified = true
	return result, nil
}

// establishTrustedTimestamp resolves a trusted time for the signature by its
// sigstore backend. The signer cert's issuing Fulcio CA selects the path:
//   - GitHub-internal certs anchor on an RFC3161 TSA token embedded in the CMS.
//   - public-good (sigstore.dev) certs anchor on a Rekor inclusion proof.
//
// Returns an error (leaving the result transparency-unbound) when no trusted
// anchor can be established.
func establishTrustedTimestamp(cmsDER []byte, signerCert *x509.Certificate) (*trustedTimestamp, error) {
	// the signer cert's issuing Fulcio CA must be unambiguously identifiable;
	// fail closed if it is not, rather than guessing a path. guessing GitHub
	// could otherwise route a public-good cert onto the TSA path and bypass the
	// public-good fail-closed stance.
	src, err := root.DetectTrustedRootFromCert(encodeCertPEM(signerCert))
	if err != nil {
		return nil, fmt.Errorf("cannot determine sigstore backend from signer cert: %w", err)
	}

	switch src {
	case root.TrustedRootSourceGitHub:
		// GitHub-internal path: extract and verify the RFC3161 TSA token, bound
		// to the signature value of the same SignerInfo that carried it.
		token, sigValue, ok := extractTimestampTokenAndSig(cmsDER)
		if !ok {
			return nil, fmt.Errorf("no RFC3161 timestamp token present in signature")
		}
		genTime, err := verifyTSATimestamp(token, sigValue)
		if err != nil {
			return nil, fmt.Errorf("TSA timestamp verification failed: %w", err)
		}
		return &trustedTimestamp{Time: genTime, Source: "tsa"}, nil
	default:
		// public-good path (sigstore.dev): a Rekor inclusion proof is the
		// transparency anchor. live-log lookup / recorded-fixture verification is
		// not yet wired into the gitsign path (tracked as phase-a follow-up), so
		// fail closed rather than trust an unverified signature.
		return nil, fmt.Errorf("public-good Rekor inclusion verification not yet supported on the gitsign path")
	}
}

// encodeCommitWithoutSignature returns the raw bytes of the commit object without the signature.
func encodeCommitWithoutSignature(commit *object.Commit) ([]byte, error) {
	obj := new(plumbing.MemoryObject)
	if err := commit.EncodeWithoutSignature(obj); err != nil {
		return nil, err
	}
	reader, err := obj.Reader()
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}

// resolveRevision resolves a revision string (ref, hash, HEAD) to a commit hash.
func resolveRevision(repo *git.Repository, revision string) (plumbing.Hash, error) {
	// try as plumbing.Revision (handles HEAD, branches, tags, hashes)
	hash, err := repo.ResolveRevision(plumbing.Revision(revision))
	if err != nil {
		return plumbing.ZeroHash, err
	}
	return *hash, nil
}

// collectCommitRange walks commits from the 'to' hash back to the 'from' hash (both inclusive).
// Follows first-parent only. Returns an error if 'from' is not reachable from 'to'.
func collectCommitRange(repo *git.Repository, from, to plumbing.Hash) ([]*object.Commit, error) {
	// if from == to, single commit
	if from == to {
		commit, err := repo.CommitObject(to)
		if err != nil {
			return nil, err
		}
		return []*object.Commit{commit}, nil
	}

	// walk from 'to' back to 'from', following first parent
	var commits []*object.Commit
	current, err := repo.CommitObject(to)
	if err != nil {
		return nil, err
	}

	foundFrom := false
	seen := make(map[plumbing.Hash]bool)
	for current != nil {
		if seen[current.Hash] {
			break
		}
		seen[current.Hash] = true
		commits = append(commits, current)

		if current.Hash == from {
			foundFrom = true
			break
		}

		if current.NumParents() == 0 {
			break
		}

		parent, err := current.Parent(0)
		if err != nil {
			return nil, fmt.Errorf("walk parent of %s: %w", current.Hash, err)
		}
		current = parent
	}

	if !foundFrom {
		return nil, fmt.Errorf("commit %s is not reachable from %s", from, to)
	}

	return commits, nil
}

// buildFulcioPool extracts Fulcio CA certificates from the embedded trusted roots
// and returns an x509.CertPool for chain verification.
// Returns an error if no certificates could be loaded from any trusted root.
// It is a package var so tests can inject a self-signed test CA pool.
var buildFulcioPool = func() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	added := 0

	// try both GitHub and public Sigstore trusted roots
	for _, rootData := range [][]byte{root.GetGitHubTrustedRoot(), root.GetPublicTrustedRoot()} {
		n, err := addCertsFromTrustedRoot(pool, rootData)
		if err != nil {
			continue // non-fatal: try next root
		}
		added += n
	}

	if added == 0 {
		return nil, fmt.Errorf("no Fulcio CA certificates found in trusted roots")
	}

	return pool, nil
}

// trustedRootJSON mirrors the relevant fields of the sigstore trusted root JSON format.
type trustedRootJSON struct {
	CertificateAuthorities []struct {
		CertChain struct {
			Certificates []struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"certChain"`
	} `json:"certificateAuthorities"`
}

// addCertsFromTrustedRoot parses a sigstore trusted root JSON and adds its CA certs to the pool.
// Returns the number of certificates successfully added.
func addCertsFromTrustedRoot(pool *x509.CertPool, data []byte) (int, error) {
	var tr trustedRootJSON
	if err := json.Unmarshal(data, &tr); err != nil {
		return 0, fmt.Errorf("unmarshal trusted root: %w", err)
	}

	added := 0
	for _, ca := range tr.CertificateAuthorities {
		for _, c := range ca.CertChain.Certificates {
			der, err := base64.StdEncoding.DecodeString(c.RawBytes)
			if err != nil {
				continue
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				continue
			}
			pool.AddCert(cert)
			added++
		}
	}

	return added, nil
}

// extractIdentity extracts the OIDC subject and issuer from a Fulcio certificate's SAN.
func extractIdentity(cert *x509.Certificate) (signer, issuer string) {
	// prefer URI SAN (OIDC identity for service accounts / workflows)
	for _, uri := range cert.URIs {
		if uri != nil {
			signer = uri.String()
			break
		}
	}

	// fallback: email SAN (human users)
	if signer == "" && len(cert.EmailAddresses) > 0 {
		signer = cert.EmailAddresses[0]
	}

	// extract issuer from Fulcio OID extension 1.3.6.1.4.1.57264.1.1
	const fulcioIssuerOID = "1.3.6.1.4.1.57264.1.1"
	for _, ext := range cert.Extensions {
		if ext.Id.String() == fulcioIssuerOID {
			issuer = string(ext.Value)
			return
		}
	}

	// fallback: use cert issuer CN
	issuer = cert.Issuer.CommonName
	return
}

// certFingerprint returns the SHA-256 fingerprint of a certificate as hex.
func certFingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", h)
}

// encodeCertPEM PEM-encodes a certificate's DER for trusted-root detection.
func encodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// matchIdentity checks whether the signer identity matches the expected value.
// Supports exact match or path-bounded prefix match for URI identities.
// "https://github.com/org/repo" matches ".../org/repo/.github/workflows/..."
// but NOT ".../org/repo-evil/..." — the prefix must align on a "/" or "@" boundary.
func matchIdentity(signer, expected string) bool {
	if signer == expected {
		return true
	}
	if strings.HasPrefix(signer, expected) {
		rest := signer[len(expected):]
		return len(rest) > 0 && (rest[0] == '/' || rest[0] == '@')
	}
	return false
}
