package certid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/liatrio/autogov/pkg/github"
)

// default cache dir
const CacheDir = ".autogov"

// default cache file
const CacheFile = "cert-identities.json"

// default cache expiration
const CacheExpirationHours = 24

// represents a single certificate identity
type Identity struct {
	Version    string   `json:"version"`
	Sha        string   `json:"sha"`
	Status     string   `json:"status"`
	Identities []string `json:"identities"`
	Added      string   `json:"added"`
	Expires    string   `json:"expires,omitempty"`
	Revoked    string   `json:"revoked,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

// contains categorized lists of cert-ids
type IdentityList struct {
	Identities []Identity `json:"identities,omitempty"`
	Metadata   struct {
		LastUpdated string `json:"last_updated"`
		Version     string `json:"version"`
		Maintainer  string `json:"maintainer"`
	} `json:"metadata"`
}

// configures the identity validator
type Options struct {
	// url to fetch the identity list from
	URL string
	// disables caching
	DisableCache bool
	// dir to store cached identity lists
	CacheDir string
}

// returns the default id validator options
func DefaultOptions() Options {
	return Options{
		URL:          "", // URL must be explicitly provided
		DisableCache: false,
		CacheDir:     filepath.Join(os.Getenv("HOME"), CacheDir),
	}
}

// handles certificate identity validation
type Validator struct {
	options Options
	list    *IdentityList
}

// creates a new cert-id validator
func NewValidator(opts Options) (*Validator, error) {
	// URL is required and must be explicitly provided
	if opts.URL == "" {
		return nil, fmt.Errorf("URL is required for certificate identity validation")
	}
	if opts.CacheDir == "" {
		opts.CacheDir = DefaultOptions().CacheDir
	}
	return &Validator{
		options: opts,
	}, nil
}

// loads the cert-id list from the remote source, local file, or cache
func (v *Validator) LoadIdentities(ctx context.Context) error {
	var data []byte
	var err error

	// check if URL is actually a local file path
	if isLocalFile(v.options.URL) {
		return v.loadFromLocalFile()
	}

	// check cache if enabled
	if !v.options.DisableCache {
		cacheFilePath := filepath.Join(v.options.CacheDir, CacheFile)
		data, err = v.loadFromCache(cacheFilePath)
		if err == nil {
			// cache hit / parse the data
			var list IdentityList
			if err := json.Unmarshal(data, &list); err == nil {
				v.list = &list
				return nil
			}
		}
	}

	// cache miss / disabled, fetch from remote
	httpCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(httpCtx, http.MethodGet, v.options.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// add github token for authentication if accessing github raw files
	if strings.Contains(v.options.URL, "raw.githubusercontent.com") {
		if token := github.GetToken(); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch remote identity file: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("warning: failed to close response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch remote identity file: %s", resp.Status)
	}

	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read remote identity file: %w", err)
	}

	var list IdentityList
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("failed to parse identity list: %w", err)
	}

	v.list = &list

	// update cache
	if !v.options.DisableCache {
		if err := v.updateCache(data); err != nil {
			log.Printf("warning: failed to update cache: %v", err)
		}
	}

	return nil
}

// checks if the provided string is a local file path
func isLocalFile(path string) bool {
	// check if it's a URL scheme
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return false
	}
	// only return true if the file actually exists
	if _, err := os.Stat(path); err == nil {
		return true
	}
	// if it contains path separators but doesn't exist, it's likely an invalid file path
	// let it fall through to the URL handling which will provide a clearer error
	return false
}

// loads the cert-id list from a local file
func (v *Validator) loadFromLocalFile() error {
	data, err := os.ReadFile(v.options.URL)
	if err != nil {
		return fmt.Errorf("failed to read local identity file: %w", err)
	}

	var list IdentityList
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("failed to parse identity list: %w", err)
	}

	v.list = &list
	return nil
}

// loads the identity list from the cache file if it exists and is not expired
func (v *Validator) loadFromCache(cacheFilePath string) ([]byte, error) {
	// check cache file exists
	fi, err := os.Stat(cacheFilePath)
	if err != nil {
		return nil, err
	}

	// check if cache is expired
	if time.Since(fi.ModTime()).Hours() > CacheExpirationHours {
		return nil, fmt.Errorf("cache expired")
	}

	return os.ReadFile(cacheFilePath)
}

// updates cache file with latest cert-id list
func (v *Validator) updateCache(data []byte) error {
	// check if cache dir exists
	if err := os.MkdirAll(v.options.CacheDir, 0755); err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(v.options.CacheDir, CacheFile), data, 0644)
}

// checks if the given cert-id is valid
func (v *Validator) IsValidIdentity(certIdentity string) (bool, error) {
	if v.list == nil {
		return false, fmt.Errorf("identity list not loaded, call LoadIdentities first")
	}

	normalizedIdentity, certSHA := normalizeIdentity(certIdentity)

	// revocation wins regardless of position: check ALL entries for a revocation
	// before accepting any match, so a SAN revoked by a later-listed entry can't be
	// rescued by an earlier approved/latest entry that names the same SAN or sha.
	for _, id := range v.list.Identities {
		if err := checkIfRevoked(id, certIdentity, normalizedIdentity, certSHA); err != nil {
			return false, err
		}
	}

	// then accept on the first valid (non-expired latest/approved) match
	for _, id := range v.list.Identities {
		valid, err := checkIfValid(id, certIdentity, normalizedIdentity, certSHA)
		if err != nil {
			return false, err
		}
		if valid {
			return true, nil
		}
	}
	return false, fmt.Errorf("certificate identity not found in approved lists")
}

// normalizes the cert identity and extracts the sha if present
func normalizeIdentity(certIdentity string) (string, string) {
	certSHA := ""
	normalizedIdentity := certIdentity
	if strings.Contains(certIdentity, "@") {
		parts := strings.Split(certIdentity, "@")
		if len(parts) == 2 {
			if len(parts[1]) == 40 && isHexString(parts[1]) {
				certSHA = parts[1]
			}
			if !strings.Contains(certIdentity, "@refs/") && certSHA == "" {
				if strings.HasPrefix(parts[1], "heads/") {
					normalizedIdentity = parts[0] + "@refs/" + parts[1]
				} else if strings.HasPrefix(parts[1], "tags/") {
					normalizedIdentity = parts[0] + "@refs/" + parts[1]
				} else if !strings.HasPrefix(parts[1], "refs/") {
					normalizedIdentity = parts[0] + "@refs/heads/" + parts[1]
				}
			}
		}
	}

	return normalizedIdentity, certSHA
}

// checks if an identity is revoked
func checkIfRevoked(id Identity, certIdentity, normalizedIdentity, certSHA string) error {
	if id.Status != "revoked" {
		return nil
	}

	for _, identity := range id.Identities {
		if identity == certIdentity || identity == normalizedIdentity {
			return fmt.Errorf("certificate identity is revoked: %s", id.Reason)
		}
	}

	if certSHA != "" && id.Sha == certSHA {
		return fmt.Errorf("certificate identity is revoked: %s", id.Reason)
	}

	return nil
}

// checks if an identity is valid and not expired
func checkIfValid(id Identity, certIdentity, normalizedIdentity, certSHA string) (bool, error) {
	if id.Status != "latest" && id.Status != "approved" {
		return false, nil
	}

	identityMatch := false
	for _, identity := range id.Identities {
		if identity == certIdentity || identity == normalizedIdentity {
			identityMatch = true
			break
		}
	}

	if !identityMatch && (certSHA == "" || id.Sha != certSHA) {
		return false, nil
	}

	expired, err := isExpired(id)
	if err != nil {
		return false, err
	}
	if expired {
		return false, fmt.Errorf("certificate identity has expired")
	}

	return true, nil
}

// helper function checks if a string is a valid hex string (for sha validation)
func isHexString(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// checks if an identity has expired based on its expiry date
func isExpired(id Identity) (bool, error) {
	if id.Expires == "" {
		return false, nil
	}
	expiryDate, err := time.Parse("2006-01-02", id.Expires)
	if err != nil {
		return false, fmt.Errorf("invalid expiry date format: %w", err)
	}
	// add a day to consider it valid throughout the expiry date itself
	expiryDate = expiryDate.AddDate(0, 0, 1)
	return time.Now().After(expiryDate), nil
}

// returns the loaded cert-id list
// returns all valid identities from both latest and approved lists
func (v *Validator) GetValidIdentities() ([]Identity, error) {
	var validIdentities []Identity

	if v.list == nil {
		return nil, fmt.Errorf("identity list not loaded, call LoadIdentities first")
	}

	// get valid identities (latest and non-expired approved)
	for _, id := range v.list.Identities {
		if id.Status != "latest" && id.Status != "approved" {
			continue
		}
		expired, err := isExpired(id)
		if err != nil || expired {
			continue // skip invalid or expired identities
		}
		validIdentities = append(validIdentities, id)
	}

	return validIdentities, nil
}

// returns the flat, deduped set of SANs from all valid identities, with each
// SAN re-checked through IsValidIdentity. GetValidIdentities filters by
// status/expiry only; running each candidate SAN through IsValidIdentity
// re-applies checkIfRevoked across ALL entries, so a SAN named in a separate
// status:"revoked" entry (by SAN or sha) is dropped — preserving the revocation
// rigor of the single-identity guard this enables removing.
func (v *Validator) GetValidIdentitySANs() ([]string, error) {
	valid, err := v.GetValidIdentities()
	if err != nil {
		return nil, err
	}

	// flatten + dedupe candidate SANs from valid (latest/approved, non-expired) entries
	seen := make(map[string]struct{})
	var candidates []string
	for _, id := range valid {
		for _, san := range id.Identities {
			// skip empty SANs: IsValidIdentity("") matches an empty-SAN entry as
			// (true, nil), so an unfiltered "" would leak into the allowlist.
			if san == "" {
				continue
			}
			if _, dup := seen[san]; dup {
				continue
			}
			seen[san] = struct{}{}
			candidates = append(candidates, san)
		}
	}

	// keep only SANs that pass IsValidIdentity (true, nil) — drops cross-entry
	// revoked/expired SANs (fail-closed: anything not affirmatively valid is excluded)
	var sans []string
	for _, san := range candidates {
		if ok, err := v.IsValidIdentity(san); err == nil && ok {
			sans = append(sans, san)
		}
	}

	return sans, nil
}

// builds the effective signer allowlist (union): certIdentity accepted
// as-typed (operator vouches — NOT revocation-checked) unioned with the
// revocation-checked valid SANs from the configured list (if any). The list is
// loaded at most once. Fail-closed: any validator/load/resolution error is
// returned, and a configured list that resolves to zero acceptable identities
// (with no --cert-identity) is rejected rather than degrading to accept-any —
// per SLSA, a verifier must only accept provenance proving it came from an
// acceptable builder. Returns an empty slice ONLY when NEITHER a --cert-identity
// NOR a list is configured (the deliberate, separately-warned backward-compat
// unsafe case handled at the policy sites).
func ResolveAcceptedIdentities(ctx context.Context, certIdentity string, listOpts *Options) ([]string, error) {
	seen := make(map[string]struct{})
	var accepted []string
	add := func(s string) {
		if s == "" {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		accepted = append(accepted, s)
	}

	// --cert-identity is accepted as-typed (not list-membership or revocation checked)
	add(certIdentity)

	if listOpts != nil {
		v, err := NewValidator(*listOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate identity validator: %w", err)
		}
		if err := v.LoadIdentities(ctx); err != nil {
			return nil, fmt.Errorf("failed to load certificate identities: %w", err)
		}
		sans, err := v.GetValidIdentitySANs()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve valid certificate identities: %w", err)
		}
		for _, san := range sans {
			add(san)
		}

		// SLSA fail-closed: a list was configured, so the operator asked to enforce a
		// signer allowlist. if it resolves to zero acceptable identities (every entry
		// revoked/expired) and no --cert-identity was given, refuse rather than fall
		// through to WithoutIdentitiesUnsafe (accept-any) at the policy sites. (len==0
		// here implies certIdentity was empty: a non-empty one is added above.)
		if len(accepted) == 0 {
			return nil, fmt.Errorf("certificate identity list resolved to zero acceptable identities (all entries revoked/expired); refusing to verify with an empty signer allowlist — set --cert-identity or provide a list with at least one valid identity")
		}
	}

	return accepted, nil
}
