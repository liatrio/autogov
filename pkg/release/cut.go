package release

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	gogithub "github.com/google/go-github/v88/github"
	"github.com/liatrio/autogov/pkg/mutate"
	"gopkg.in/yaml.v3"
)

// ReleaseMode controls how autogov performs git read operations
type ReleaseMode string

const (
	ModeAuto  ReleaseMode = "auto"  // use API if token present; fall back to local on error
	ModeAPI   ReleaseMode = "api"   // require GitHub API, fail hard on error
	ModeLocal ReleaseMode = "local" // use local go-git only (offline)
)

// ValidateMode checks that a ReleaseMode string is one of the allowed values.
func ValidateMode(mode ReleaseMode) error {
	switch mode {
	case ModeAuto, ModeAPI, ModeLocal, "":
		return nil
	default:
		return fmt.Errorf("invalid --mode %q: must be one of auto, api, local", mode)
	}
}

// CutOptions contains configuration for executing a release cut
type CutOptions struct {
	RepoPath        string            // path to git repo (default ".")
	Branch          string            // expected branch (default "main")
	Remote          string            // git remote name (default "origin")
	PlanFile        string            // path to pre-generated plan JSON/YAML
	MutationsConfig string            // path to mutations config file
	DryRun          bool              // show what would happen without side effects
	Publish         bool              // create published release directly (no draft)
	Mode            ReleaseMode       // "auto" (default), "api", "local"
	CommitAuthor    string            // bot commit author name
	CommitEmail     string            // bot commit author email
	Token           string            // GitHub token for API and push
	ReleaseAPI      ReleaseService    // optional; created from Token if nil
	Assets          []string          // file paths to upload as release assets
	AssetLabels     map[string]string // optional asset name -> display label
}

// CutResult captures the outcome of a release cut
type CutResult struct {
	TagName        string   `json:"tag_name"`
	Version        string   `json:"version"`
	CommitSHA      string   `json:"commit_sha"`
	ReleaseURL     string   `json:"release_url,omitempty"`
	ReleaseID      int64    `json:"release_id,omitempty"`
	Draft          bool     `json:"draft"`
	Published      bool     `json:"published"`
	FilesModified  []string `json:"files_modified,omitempty"`
	UploadedAssets []string `json:"uploaded_assets,omitempty"`
	DryRun         bool     `json:"dry_run"`
	NoRelease      bool     `json:"no_release"`
	Reason         string   `json:"reason,omitempty"`
}

// DefaultCutOptions returns options with sensible defaults
func DefaultCutOptions() *CutOptions {
	return &CutOptions{
		RepoPath:     ".",
		Branch:       "main",
		Remote:       "origin",
		CommitAuthor: "autogov[bot]",
		CommitEmail:  "autogov[bot]@users.noreply.github.com",
	}
}

// ReleaseService abstracts GitHub API operations for testability
type ReleaseService interface {
	// release operations
	GetReleaseByTag(ctx context.Context, owner, repo, tag string) (*gogithub.RepositoryRelease, *gogithub.Response, error)
	GetRelease(ctx context.Context, owner, repo string, id int64) (*gogithub.RepositoryRelease, *gogithub.Response, error)
	CreateRelease(ctx context.Context, owner, repo string, release *gogithub.RepositoryRelease) (*gogithub.RepositoryRelease, *gogithub.Response, error)
	UpdateRelease(ctx context.Context, owner, repo string, id int64, release *gogithub.RepositoryRelease) (*gogithub.RepositoryRelease, *gogithub.Response, error)
	ListReleases(ctx context.Context, owner, repo string, opts *gogithub.ListOptions) ([]*gogithub.RepositoryRelease, *gogithub.Response, error)
	UploadReleaseAsset(ctx context.Context, owner, repo string, id int64, opts *gogithub.UploadOptions, file *os.File) (*gogithub.ReleaseAsset, *gogithub.Response, error)
	// read operations (tag discovery, commit comparison, branch validation)
	ListTags(ctx context.Context, owner, repo string, opts *gogithub.ListOptions) ([]*gogithub.RepositoryTag, *gogithub.Response, error)
	CompareCommits(ctx context.Context, owner, repo, base, head string, opts *gogithub.ListOptions) (*gogithub.CommitsComparison, *gogithub.Response, error)
	GetBranch(ctx context.Context, owner, repo, branch string, maxRedirects int) (*gogithub.Branch, *gogithub.Response, error)
	// git data operations (commits/tags created via API are auto-signed by GitHub per SLSA v1.2)
	CreateTree(ctx context.Context, owner, repo, baseTree string, entries []*gogithub.TreeEntry) (*gogithub.Tree, *gogithub.Response, error)
	CreateCommit(ctx context.Context, owner, repo string, commit gogithub.Commit, opts *gogithub.CreateCommitOptions) (*gogithub.Commit, *gogithub.Response, error)
	CreateTag(ctx context.Context, owner, repo string, tag gogithub.CreateTag) (*gogithub.Tag, *gogithub.Response, error)
	CreateRef(ctx context.Context, owner, repo string, ref gogithub.CreateRef) (*gogithub.Reference, *gogithub.Response, error)
	UpdateRef(ctx context.Context, owner, repo, ref string, updateRef gogithub.UpdateRef) (*gogithub.Reference, *gogithub.Response, error)
	DeleteRef(ctx context.Context, owner, repo, ref string) (*gogithub.Response, error)
}

type githubReleaseService struct {
	client *gogithub.Client
}

func (s *githubReleaseService) GetReleaseByTag(ctx context.Context, owner, repo, tag string) (*gogithub.RepositoryRelease, *gogithub.Response, error) {
	return s.client.Repositories.GetReleaseByTag(ctx, owner, repo, tag)
}

func (s *githubReleaseService) GetRelease(ctx context.Context, owner, repo string, id int64) (*gogithub.RepositoryRelease, *gogithub.Response, error) {
	return s.client.Repositories.GetRelease(ctx, owner, repo, id)
}

func (s *githubReleaseService) CreateRelease(ctx context.Context, owner, repo string, release *gogithub.RepositoryRelease) (*gogithub.RepositoryRelease, *gogithub.Response, error) {
	return s.client.Repositories.CreateRelease(ctx, owner, repo, release)
}

func (s *githubReleaseService) UpdateRelease(ctx context.Context, owner, repo string, id int64, release *gogithub.RepositoryRelease) (*gogithub.RepositoryRelease, *gogithub.Response, error) {
	return s.client.Repositories.EditRelease(ctx, owner, repo, id, release)
}

func (s *githubReleaseService) ListReleases(ctx context.Context, owner, repo string, opts *gogithub.ListOptions) ([]*gogithub.RepositoryRelease, *gogithub.Response, error) {
	return s.client.Repositories.ListReleases(ctx, owner, repo, opts)
}

func (s *githubReleaseService) UploadReleaseAsset(ctx context.Context, owner, repo string, id int64, opts *gogithub.UploadOptions, file *os.File) (*gogithub.ReleaseAsset, *gogithub.Response, error) {
	return s.client.Repositories.UploadReleaseAsset(ctx, owner, repo, id, opts, file)
}

func (s *githubReleaseService) ListTags(ctx context.Context, owner, repo string, opts *gogithub.ListOptions) ([]*gogithub.RepositoryTag, *gogithub.Response, error) {
	return s.client.Repositories.ListTags(ctx, owner, repo, opts)
}

func (s *githubReleaseService) CompareCommits(ctx context.Context, owner, repo, base, head string, opts *gogithub.ListOptions) (*gogithub.CommitsComparison, *gogithub.Response, error) {
	return s.client.Repositories.CompareCommits(ctx, owner, repo, base, head, opts)
}

func (s *githubReleaseService) GetBranch(ctx context.Context, owner, repo, branch string, maxRedirects int) (*gogithub.Branch, *gogithub.Response, error) {
	return s.client.Repositories.GetBranch(ctx, owner, repo, branch, maxRedirects)
}

func (s *githubReleaseService) CreateTree(ctx context.Context, owner, repo, baseTree string, entries []*gogithub.TreeEntry) (*gogithub.Tree, *gogithub.Response, error) {
	return s.client.Git.CreateTree(ctx, owner, repo, baseTree, entries)
}

func (s *githubReleaseService) CreateCommit(ctx context.Context, owner, repo string, commit gogithub.Commit, opts *gogithub.CreateCommitOptions) (*gogithub.Commit, *gogithub.Response, error) {
	return s.client.Git.CreateCommit(ctx, owner, repo, commit, opts)
}

func (s *githubReleaseService) CreateTag(ctx context.Context, owner, repo string, tag gogithub.CreateTag) (*gogithub.Tag, *gogithub.Response, error) {
	return s.client.Git.CreateTag(ctx, owner, repo, tag)
}

func (s *githubReleaseService) CreateRef(ctx context.Context, owner, repo string, ref gogithub.CreateRef) (*gogithub.Reference, *gogithub.Response, error) {
	return s.client.Git.CreateRef(ctx, owner, repo, ref)
}

func (s *githubReleaseService) UpdateRef(ctx context.Context, owner, repo, ref string, updateRef gogithub.UpdateRef) (*gogithub.Reference, *gogithub.Response, error) {
	return s.client.Git.UpdateRef(ctx, owner, repo, ref, updateRef)
}

func (s *githubReleaseService) DeleteRef(ctx context.Context, owner, repo, ref string) (*gogithub.Response, error) {
	return s.client.Git.DeleteRef(ctx, owner, repo, ref)
}

func newGitHubReleaseService(token string) (ReleaseService, error) {
	client, err := gogithub.NewClient(gogithub.WithAuthToken(token))
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub client: %w", err)
	}
	return &githubReleaseService{client: client}, nil
}

// ExecuteCut orchestrates the full release cut flow
func ExecuteCut(opts *CutOptions) (*CutResult, error) {
	if opts == nil {
		opts = DefaultCutOptions()
	}

	if err := ValidateMode(opts.Mode); err != nil {
		return nil, err
	}

	// fail-fast: every asset path must exist before any commit/tag/push side effects
	if err := validateAssets(opts.Assets, opts.AssetLabels); err != nil {
		return nil, err
	}

	repo, err := OpenRepository(opts.RepoPath)
	if err != nil {
		return nil, err
	}

	// initialize GitHub release service if token is available
	if opts.Token != "" && opts.ReleaseAPI == nil {
		releaseAPI, err := newGitHubReleaseService(opts.Token)
		if err != nil {
			return nil, err
		}
		opts.ReleaseAPI = releaseAPI
	}

	// fail early if api mode requires a token
	if opts.Mode == ModeAPI && opts.ReleaseAPI == nil {
		return nil, fmt.Errorf("--mode=api requires a GitHub token")
	}

	// step 1: validate working tree / branch
	if opts.Mode == ModeAPI && opts.ReleaseAPI != nil {
		// in API mode skip local worktree clean check — verify branch exists via API
		owner, repoName, parseErr := parseOwnerRepo(repo)
		if parseErr != nil {
			return nil, parseErr
		}
		ctx := context.Background()
		if err := validateBranchViaAPI(ctx, opts.ReleaseAPI, owner, repoName, opts.Branch); err != nil {
			return nil, fmt.Errorf("branch validation failed: %w", err)
		}
	} else {
		if err := validateWorktree(repo, opts.Branch); err != nil {
			return nil, fmt.Errorf("worktree validation failed: %w", err)
		}
	}

	// step 2: generate or load the release plan
	plan, err := resolvePlan(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve release plan: %w", err)
	}

	if !plan.ReleaseNeeded {
		return &CutResult{
			NoRelease: true,
			Reason:    plan.Reason,
		}, nil
	}

	tagName := plan.NextVersion // already has v prefix from Version.String()

	// step 3: resume detection + immutability. A prior cut for this exact tag may have
	// been interrupted after the tag was created — unlike the step-7 branch-ref failure
	// (rolled back per #249), a failure in steps 8–10 leaves the tag, commit, and a draft
	// release in place. Detect that draft and resume into it instead of failing the
	// immutability check.
	var resumeRelease *gogithub.RepositoryRelease
	if opts.ReleaseAPI != nil {
		owner, repoName, parseErr := parseOwnerRepo(repo)
		if parseErr != nil {
			return nil, parseErr
		}
		resumeRelease, err = detectResume(context.Background(), opts, owner, repoName, tagName)
		if err != nil {
			return nil, err
		}
	}
	if resumeRelease == nil {
		if err := checkImmutability(repo, opts, tagName); err != nil {
			return nil, fmt.Errorf("immutability check failed: %w", err)
		}
	}

	result := &CutResult{
		TagName:   tagName,
		Version:   strings.TrimPrefix(plan.NextVersion, "v"),
		Draft:     !opts.Publish,
		Published: opts.Publish,
		DryRun:    opts.DryRun,
	}

	// resume completes the interrupted cut: reuse the existing draft release, upload only
	// the missing assets, and publish if requested. Mutations/commit/tag/branch are
	// already on the remote and must not be repeated.
	if resumeRelease != nil {
		return executeResume(opts, repo, result, resumeRelease, tagName)
	}

	// step 4: apply file mutations (if configured)
	var mutationSummary []string
	if opts.MutationsConfig != "" && plan.ReleaseNeeded {
		// strip v prefix for mutation substitution (finding F1)
		versionForMutation := strings.TrimPrefix(plan.NextVersion, "v")
		mutationSummary, err = applyMutations(opts.RepoPath, opts.MutationsConfig, versionForMutation, opts.DryRun)
		if err != nil {
			return nil, fmt.Errorf("failed to apply mutations: %w", err)
		}
		result.FilesModified = mutationSummary
	}

	if opts.DryRun {
		fmt.Fprintf(os.Stderr, "dry-run: would create release %s\n", tagName)
		if len(mutationSummary) > 0 {
			fmt.Fprintf(os.Stderr, "dry-run: would modify files: %s\n", strings.Join(mutationSummary, ", "))
		}
		action := "draft"
		if opts.Publish {
			action = "published"
		}
		fmt.Fprintf(os.Stderr, "dry-run: would create commit, tag, push, and create %s GitHub release\n", action)
		if len(opts.Assets) > 0 {
			names := make([]string, len(opts.Assets))
			for i, p := range opts.Assets {
				names[i] = filepath.Base(p)
			}
			fmt.Fprintf(os.Stderr, "dry-run: would upload %d asset(s): %s\n", len(names), strings.Join(names, ", "))
		}
		return result, nil
	}

	// require GitHub API for non-dry-run (commits/tags must be API-signed per SLSA v1.2)
	if opts.ReleaseAPI == nil {
		return nil, fmt.Errorf("GitHub token is required for release cut (API-signed commits per SLSA v1.2)")
	}

	owner, repoName, err := parseOwnerRepo(repo)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	// step 5: create release commit via GitHub API (auto-signed/verified)
	headSHA, commitSHA, err := createReleaseCommitViaAPI(ctx, repo, opts, plan, owner, repoName)
	if err != nil {
		return nil, fmt.Errorf("failed to create release commit: %w", err)
	}
	result.CommitSHA = commitSHA

	// step 6: create annotated tag on the parent (trigger) commit, not the release commit.
	// This matches semantic-release behavior: the tag points to the code commit, and the
	// release commit (with mutations) sits on top. Consumers pin to the tag SHA which then
	// matches cert-identities entries.
	if err := createAnnotatedTagViaAPI(ctx, opts, tagName, headSHA, plan, owner, repoName); err != nil {
		return nil, fmt.Errorf("failed to create tag %s: %w", tagName, err)
	}

	// step 7: update branch ref to point at new commit. The tag was created in step 6,
	// so a failure here (e.g. a concurrent push to the branch turning the fast-forward
	// into a 422) would otherwise leave refs/tags/<version> orphaned on the remote — a
	// retry then trips checkImmutability ("tag already exists"). Roll the tag back so the
	// next run is clean; if the rollback itself fails, surface the manual recovery step.
	if err := updateBranchRef(ctx, opts, owner, repoName, opts.Branch, commitSHA); err != nil {
		if delErr := deleteTagRef(ctx, opts, owner, repoName, tagName); delErr != nil {
			return nil, fmt.Errorf("failed to update branch ref: %w; release tag %s could not be rolled back (%v): delete refs/tags/%s before retrying", err, tagName, delErr, tagName)
		}
		return nil, fmt.Errorf("failed to update branch ref: %w (rolled back tag %s)", err, tagName)
	}

	// step 8: always create the release as a draft first, so assets are uploaded
	// before it becomes visible/published. With --publish we flip it in step 10 —
	// this avoids a window where a published release shows zero/partial assets.
	releaseURL, releaseID, err := createGitHubRelease(repo, opts, plan, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub release: %w", err)
	}
	result.ReleaseURL = releaseURL
	result.ReleaseID = releaseID
	result.Draft = true
	result.Published = false

	// step 9: upload release assets (if any). On failure return the PARTIAL result:
	// the release/tag already exist and immutability blocks a re-cut, so the caller
	// needs the release URL/ID and the names that did upload in order to recover.
	if len(opts.Assets) > 0 {
		uploaded, uploadErr := uploadAssets(ctx, opts.ReleaseAPI, owner, repoName, releaseID, opts.Assets, opts.AssetLabels)
		result.UploadedAssets = uploaded
		if uploadErr != nil {
			return result, fmt.Errorf("failed to upload release assets: %w", uploadErr)
		}
	}

	// step 10: publish (flip draft -> published) only after assets are uploaded.
	if opts.Publish {
		if err := markReleasePublished(ctx, opts.ReleaseAPI, owner, repoName, releaseID); err != nil {
			return result, fmt.Errorf("failed to publish release: %w", err)
		}
		result.Draft = false
		result.Published = true
	}

	return result, nil
}

// markReleasePublished flips a draft release to published via the GitHub API.
func markReleasePublished(ctx context.Context, svc ReleaseService, owner, repo string, releaseID int64) error {
	rel := &gogithub.RepositoryRelease{Draft: gogithub.Ptr(false)}
	_, resp, err := svc.UpdateRelease(ctx, owner, repo, releaseID, rel)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}

// validateAssets checks the requested assets fail-fast, before any release side
// effects: each path must exist and be a non-empty regular file, no two assets may
// share an upload name (base name), and every --asset-label must match one of those
// names. (A file removed between this check and the upload would still fail later,
// once the release exists — but the common mistakes are caught up front.)
func validateAssets(assets []string, labels map[string]string) error {
	names := make(map[string]struct{}, len(assets))
	for _, path := range assets {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("asset not found: %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("asset is not a regular file: %s", path)
		}
		if info.Size() == 0 {
			return fmt.Errorf("asset is empty (0 bytes): %s", path)
		}
		name := filepath.Base(path)
		if _, dup := names[name]; dup {
			return fmt.Errorf("multiple assets resolve to the same name %q; release asset names must be unique", name)
		}
		names[name] = struct{}{}
	}
	for name := range labels {
		if _, ok := names[name]; !ok {
			return fmt.Errorf("--asset-label %q does not match any --asset name (the name is the file's base name)", name)
		}
	}
	return nil
}

// uploadAssets uploads each asset file to the release and returns the uploaded asset
// names. The asset name is the file's base name; an optional label is looked up by
// that name in labels. Fails fast on the first upload error.
func uploadAssets(ctx context.Context, svc ReleaseService, owner, repo string, releaseID int64, assets []string, labels map[string]string) ([]string, error) {
	uploaded := make([]string, 0, len(assets))
	for _, path := range assets {
		name := filepath.Base(path)
		file, err := os.Open(path)
		if err != nil {
			return uploaded, fmt.Errorf("failed to open asset %s: %w", path, err)
		}
		uploadOpts := &gogithub.UploadOptions{Name: name, Label: labels[name]}
		_, resp, uploadErr := svc.UploadReleaseAsset(ctx, owner, repo, releaseID, uploadOpts, file)
		if resp != nil {
			_ = resp.Body.Close()
		}
		closeErr := file.Close()
		if uploadErr != nil {
			return uploaded, fmt.Errorf("failed to upload asset %s: %w", name, uploadErr)
		}
		if closeErr != nil {
			return uploaded, fmt.Errorf("failed to close asset %s: %w", name, closeErr)
		}
		uploaded = append(uploaded, name)
	}
	return uploaded, nil
}

// detectResume checks whether a prior cut for tagName was interrupted, leaving a draft
// release behind that can be resumed. It returns that draft release (to resume into) or
// nil for a fresh cut. A published (non-draft) release is immutable and returns an error.
// A missing release (or any lookup error, e.g. 404) is treated as a fresh cut.
func detectResume(ctx context.Context, opts *CutOptions, owner, repoName, tagName string) (*gogithub.RepositoryRelease, error) {
	rel, resp, err := opts.ReleaseAPI.GetReleaseByTag(ctx, owner, repoName, tagName)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil || rel == nil {
		return nil, nil // no release for this tag → fresh cut
	}
	if !rel.GetDraft() {
		return nil, fmt.Errorf("published release already exists for tag %s (id: %d)", tagName, rel.GetID())
	}
	return rel, nil // draft release → resumable
}

// executeResume completes an interrupted cut whose draft release already exists. It
// uploads only the assets not already attached and publishes if requested; it never
// re-runs mutations or recreates the commit/tag/branch.
func executeResume(opts *CutOptions, repo *git.Repository, result *CutResult, rel *gogithub.RepositoryRelease, tagName string) (*CutResult, error) {
	result.ReleaseURL = rel.GetHTMLURL()
	result.ReleaseID = rel.GetID()
	result.Draft = true
	result.Published = false

	skip := existingAssetNames(rel)
	toUpload := assetsToUpload(opts.Assets, skip)

	if opts.DryRun {
		fmt.Fprintf(os.Stderr, "dry-run: would resume interrupted cut for %s (reuse draft release id %d), upload %d missing asset(s)\n", tagName, result.ReleaseID, len(toUpload))
		if opts.Publish {
			fmt.Fprintln(os.Stderr, "dry-run: would then publish the release")
		}
		return result, nil
	}

	owner, repoName, err := parseOwnerRepo(repo)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	fmt.Fprintf(os.Stderr, "note: resuming interrupted cut for %s — reusing draft release, %d asset(s) to upload\n", tagName, len(toUpload))

	if len(toUpload) > 0 {
		uploaded, uploadErr := uploadAssets(ctx, opts.ReleaseAPI, owner, repoName, result.ReleaseID, toUpload, opts.AssetLabels)
		result.UploadedAssets = uploaded
		if uploadErr != nil {
			return result, fmt.Errorf("failed to upload release assets: %w", uploadErr)
		}
	}

	if opts.Publish {
		if err := markReleasePublished(ctx, opts.ReleaseAPI, owner, repoName, result.ReleaseID); err != nil {
			return result, fmt.Errorf("failed to publish release: %w", err)
		}
		result.Draft = false
		result.Published = true
	}

	return result, nil
}

// existingAssetNames returns the set of fully-uploaded asset names attached to rel. Only
// assets in GitHub's "uploaded" state count as present: an asset left in a partial state
// by an interrupted upload must be re-uploaded, not skipped, so resume never publishes a
// release with a half-written asset.
func existingAssetNames(rel *gogithub.RepositoryRelease) map[string]struct{} {
	names := make(map[string]struct{}, len(rel.Assets))
	for _, a := range rel.Assets {
		if a.GetState() != "uploaded" {
			continue
		}
		names[a.GetName()] = struct{}{}
	}
	return names
}

// assetsToUpload filters asset paths down to those whose upload name (base name) is not
// already present in skip, making re-upload on a resumed cut idempotent.
func assetsToUpload(assets []string, skip map[string]struct{}) []string {
	out := make([]string, 0, len(assets))
	for _, p := range assets {
		if _, done := skip[filepath.Base(p)]; done {
			fmt.Fprintf(os.Stderr, "note: asset %s already attached to the release, skipping\n", filepath.Base(p))
			continue
		}
		out = append(out, p)
	}
	return out
}

// validateWorktree checks that the working tree is clean and on the expected branch.
// Supports detached HEAD (e.g., CI checkout by SHA) by verifying the HEAD SHA matches
// the tip of the expected branch.
func validateWorktree(repo *git.Repository, expectedBranch string) error {
	wt, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	status, err := wt.Status()
	if err != nil {
		return fmt.Errorf("failed to get worktree status: %w", err)
	}

	if !status.IsClean() {
		return fmt.Errorf("working tree is not clean; commit or stash changes first")
	}

	if expectedBranch == "" {
		return nil
	}

	head, err := repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get HEAD: %w", err)
	}

	currentBranch := head.Name().Short()
	if currentBranch == expectedBranch {
		return nil
	}

	// Detached HEAD (e.g., CI checkout by SHA): accept if the expected branch exists.
	// The workflow's own trigger conditions (e.g., github.ref == refs/heads/main) are
	// the real guard for which branch is being released. In CI, the branch tip may have
	// advanced past the checkout SHA due to release commits from previous runs.
	if !head.Name().IsBranch() {
		// verify the expected branch exists (locally or in remotes)
		_, err := repo.Reference(plumbing.NewBranchReferenceName(expectedBranch), true)
		if err != nil {
			remotes, remoteErr := repo.Remotes()
			found := false
			if remoteErr == nil {
				for _, remote := range remotes {
					_, refErr := repo.Reference(
						plumbing.NewRemoteReferenceName(remote.Config().Name, expectedBranch), true)
					if refErr == nil {
						found = true
						break
					}
				}
			}
			if !found {
				return fmt.Errorf("expected branch %q but on detached HEAD (branch not found)", expectedBranch)
			}
		}
		fmt.Fprintf(os.Stderr, "note: detached HEAD at %s, expected branch %q exists\n", head.Hash().String()[:8], expectedBranch)
		return nil
	}

	return fmt.Errorf("expected branch %q but on %q", expectedBranch, currentBranch)
}

// validateBranchViaAPI checks that the branch exists remotely (used in API mode).
func validateBranchViaAPI(ctx context.Context, svc ReleaseService, owner, repoName, branch string) error {
	_, resp, err := svc.GetBranch(ctx, owner, repoName, branch, 0)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("branch %q not found via GitHub API: %w", branch, err)
	}
	return nil
}

// checkRemoteTagViaAPI checks whether a tag already exists on the remote using the GitHub API.
// Returns an error if the tag exists; nil if it doesn't.
func checkRemoteTagViaAPI(ctx context.Context, svc ReleaseService, owner, repo, tagName string) error {
	tags, err := listTagsFromAPI(ctx, svc, owner, repo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not check remote tags via API: %v\n", err)
		return nil // non-fatal: allow the cut to proceed
	}
	for _, t := range tags {
		if t == tagName {
			return fmt.Errorf("tag %s already exists on remote", tagName)
		}
	}
	return nil
}

// resolvePlan either loads from file or generates fresh
func resolvePlan(opts *CutOptions) (*ReleasePlan, error) {
	if opts.PlanFile != "" {
		return loadPlanFromFile(opts.PlanFile)
	}

	planOpts := &PlanOptions{
		RepoPath:        opts.RepoPath,
		MutationsConfig: opts.MutationsConfig,
		Mode:            opts.Mode,
		ReleaseAPI:      opts.ReleaseAPI,
		Branch:          opts.Branch,
	}
	return GeneratePlan(planOpts)
}

// loadPlanFromFile reads a release plan from a JSON or YAML file
func loadPlanFromFile(path string) (*ReleasePlan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read plan file %s: %w", path, err)
	}

	plan := &ReleasePlan{}
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".json":
		if err := json.Unmarshal(data, plan); err != nil {
			return nil, fmt.Errorf("failed to parse JSON plan: %w", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, plan); err != nil {
			return nil, fmt.Errorf("failed to parse YAML plan: %w", err)
		}
	default:
		// try JSON first, then YAML
		if err := json.Unmarshal(data, plan); err != nil {
			if err2 := yaml.Unmarshal(data, plan); err2 != nil {
				return nil, fmt.Errorf("failed to parse plan file (JSON: %v, YAML: %v)", err, err2)
			}
		}
	}

	return plan, nil
}

// checkImmutability verifies no existing tag or published release conflicts
func checkImmutability(repo *git.Repository, opts *CutOptions, tagName string) error {
	// check local tags (skip in API mode — shallow clones may have incomplete local refs)
	if opts.Mode != ModeAPI {
		if _, err := repo.Tag(tagName); err == nil {
			return fmt.Errorf("tag %s already exists locally", tagName)
		}
	}

	// check remote tags: use GitHub API if available (works with shallow clones),
	// otherwise fall back to go-git ls-remote
	if opts.Mode == ModeAPI && opts.ReleaseAPI != nil {
		owner, repoName, parseErr := parseOwnerRepo(repo)
		if parseErr == nil {
			if err := checkRemoteTagViaAPI(context.Background(), opts.ReleaseAPI, owner, repoName, tagName); err != nil {
				return err
			}
		}
	} else {
		remote, err := repo.Remote(opts.Remote)
		if err == nil {
			listOpts := &git.ListOptions{}
			if opts.Token != "" {
				listOpts.Auth = &http.BasicAuth{Username: "x-access-token", Password: opts.Token}
			}

			refs, err := remote.List(listOpts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not list remote refs: %v\n", err)
			} else {
				tagRef := plumbing.NewTagReferenceName(tagName)
				for _, ref := range refs {
					if ref.Name() == tagRef {
						return fmt.Errorf("tag %s already exists on remote %q", tagName, opts.Remote)
					}
				}
			}
		}
	}

	// check for published (non-draft) GitHub release
	if opts.ReleaseAPI != nil {
		repoName := GetRepositoryName(repo)
		parts := strings.SplitN(repoName, "/", 2)
		if len(parts) == 2 {
			ctx := context.Background()

			rel, resp, err := opts.ReleaseAPI.GetReleaseByTag(ctx, parts[0], parts[1], tagName)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if err == nil && rel != nil {
				if !rel.GetDraft() {
					return fmt.Errorf("published release already exists for tag %s (id: %d)", tagName, rel.GetID())
				}
				// draft release exists — allowed (re-cut scenario)
				fmt.Fprintf(os.Stderr, "note: existing draft release found for %s, will be superseded\n", tagName)
			}
		}
	}

	return nil
}

// applyMutations runs the mutation engine and returns list of modified files
func applyMutations(repoPath, configPath, version string, dryRun bool) ([]string, error) {
	cfg, err := mutate.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}

	results, err := mutate.ApplyMutations(repoPath, cfg, version, dryRun)
	if err != nil {
		return nil, err
	}

	var modified []string
	for _, r := range results {
		if r.Error != "" {
			return nil, fmt.Errorf("mutation failed for %s: %s", r.Rule.Path, r.Error)
		}
		if r.Applied || dryRun {
			modified = append(modified, r.Rule.Path)
		}
	}

	return modified, nil
}

// parseOwnerRepo extracts owner and repo name from remote URL
func parseOwnerRepo(repo *git.Repository) (string, string, error) {
	repoName := GetRepositoryName(repo)
	parts := strings.SplitN(repoName, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("cannot determine owner/repo from remote URL")
	}
	return parts[0], parts[1], nil
}

// createReleaseCommitViaAPI creates a commit via GitHub's Git Data API (auto-signed/verified).
// Returns (parentSHA, commitSHA, error) — parentSHA is the trigger commit, commitSHA is the release commit.
func createReleaseCommitViaAPI(ctx context.Context, repo *git.Repository, opts *CutOptions, plan *ReleasePlan, owner, repoName string) (string, string, error) {
	head, err := repo.Head()
	if err != nil {
		return "", "", fmt.Errorf("failed to get HEAD: %w", err)
	}
	headSHA := head.Hash().String()

	// get the base tree from current HEAD
	headCommit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return "", "", fmt.Errorf("failed to get HEAD commit: %w", err)
	}
	baseTreeSHA := headCommit.TreeHash.String()

	// read mutated files from worktree
	wt, err := repo.Worktree()
	if err != nil {
		return "", "", fmt.Errorf("failed to get worktree: %w", err)
	}

	status, err := wt.Status()
	if err != nil {
		return "", "", fmt.Errorf("failed to get worktree status: %w", err)
	}

	var entries []*gogithub.TreeEntry
	for filePath := range status {
		content, err := os.ReadFile(filepath.Join(opts.RepoPath, filePath))
		if err != nil {
			return "", "", fmt.Errorf("failed to read mutated file %s: %w", filePath, err)
		}
		entries = append(entries, &gogithub.TreeEntry{
			Path:    gogithub.Ptr(filePath),
			Mode:    gogithub.Ptr("100644"),
			Type:    gogithub.Ptr("blob"),
			Content: gogithub.Ptr(string(content)),
		})
	}

	// determine tree SHA: create new tree if files changed, otherwise reuse HEAD tree
	treeSHA := baseTreeSHA
	if len(entries) > 0 {
		tree, resp, err := opts.ReleaseAPI.CreateTree(ctx, owner, repoName, baseTreeSHA, entries)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			return "", "", fmt.Errorf("failed to create tree: %w", err)
		}
		treeSHA = tree.GetSHA()
	}

	// create commit via API; omit author/committer so GitHub auto-signs as the
	// authenticated identity (SLSA v1.2 verified commits for bots)
	commit := gogithub.Commit{
		Message: gogithub.Ptr(buildCommitMessage(plan)),
		Tree:    &gogithub.Tree{SHA: gogithub.Ptr(treeSHA)},
		Parents: []*gogithub.Commit{{SHA: gogithub.Ptr(headSHA)}},
	}

	created, resp, err := opts.ReleaseAPI.CreateCommit(ctx, owner, repoName, commit, nil)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return "", "", fmt.Errorf("failed to create commit via API: %w", err)
	}

	return headSHA, created.GetSHA(), nil
}

// buildCommitMessage creates a conventional commit message for the release
func buildCommitMessage(plan *ReleasePlan) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("chore(release): %s\n\nRelease %s\n", plan.NextVersion, plan.NextVersion))

	if len(plan.FileMutations) > 0 {
		sb.WriteString("\nFiles modified:\n")
		for _, fm := range plan.FileMutations {
			if fm.Type != "error" {
				sb.WriteString(fmt.Sprintf("- %s: %s → %s\n", fm.Path, fm.OldValue, fm.NewValue))
			}
		}
	}

	sb.WriteString("\n[skip ci]")

	return sb.String()
}

// createAnnotatedTagViaAPI creates an annotated tag via GitHub's Git Data API. NOTE:
// unlike commits, annotated tag objects created via the API are NOT GPG-signed by
// GitHub — the tag is unsigned and anchors its integrity through the verified commit
// it points to.
func createAnnotatedTagViaAPI(ctx context.Context, opts *CutOptions, tagName, commitSHA string, plan *ReleasePlan, owner, repoName string) error {
	tagMessage := fmt.Sprintf("Release %s\n\n%s", tagName, plan.ChangelogPreview)

	// omit tagger so the tag records the authenticated identity (the tag object itself
	// is not signed by GitHub — see the note on this function)
	tag := gogithub.CreateTag{
		Tag:     tagName,
		Message: tagMessage,
		Object:  commitSHA,
		Type:    "commit",
	}

	tagObj, resp, err := opts.ReleaseAPI.CreateTag(ctx, owner, repoName, tag)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("failed to create tag object: %w", err)
	}

	// create ref pointing to the tag object
	ref := gogithub.CreateRef{
		Ref: "refs/tags/" + tagName,
		SHA: tagObj.GetSHA(),
	}

	_, resp, err = opts.ReleaseAPI.CreateRef(ctx, owner, repoName, ref)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("failed to create tag ref: %w", err)
	}

	return nil
}

// updateBranchRef fast-forwards the branch to the new commit via GitHub API
func updateBranchRef(ctx context.Context, opts *CutOptions, owner, repoName, branch, commitSHA string) error {
	updateRef := gogithub.UpdateRef{
		SHA:   commitSHA,
		Force: gogithub.Ptr(false),
	}

	_, resp, err := opts.ReleaseAPI.UpdateRef(ctx, owner, repoName, "refs/heads/"+branch, updateRef)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("failed to update branch ref: %w", err)
	}

	return nil
}

// deleteTagRef removes refs/tags/<tagName> from the remote. It is used to roll back a
// just-created tag when a later step of the cut fails, so a retry is not blocked by the
// immutability check.
func deleteTagRef(ctx context.Context, opts *CutOptions, owner, repoName, tagName string) error {
	resp, err := opts.ReleaseAPI.DeleteRef(ctx, owner, repoName, "refs/tags/"+tagName)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("failed to delete tag ref refs/tags/%s: %w", tagName, err)
	}

	return nil
}

// createGitHubRelease creates a GitHub release via the API.
// When draft is true, creates a draft release; when false, creates a published release directly.
func createGitHubRelease(repo *git.Repository, opts *CutOptions, plan *ReleasePlan, draft bool) (string, int64, error) {
	repoName := GetRepositoryName(repo)
	parts := strings.SplitN(repoName, "/", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("cannot determine owner/repo from remote URL")
	}

	ctx := context.Background()

	release := &gogithub.RepositoryRelease{
		TagName:              gogithub.Ptr(plan.NextVersion),
		Name:                 gogithub.Ptr(plan.NextVersion),
		Body:                 gogithub.Ptr(plan.ChangelogPreview),
		Draft:                gogithub.Ptr(draft),
		Prerelease:           gogithub.Ptr(false),
		GenerateReleaseNotes: gogithub.Ptr(false),
	}

	created, resp, err := opts.ReleaseAPI.CreateRelease(ctx, parts[0], parts[1], release)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return "", 0, fmt.Errorf("failed to create GitHub release: %w", err)
	}

	return created.GetHTMLURL(), created.GetID(), nil
}

// createDraftRelease creates a draft GitHub release via the API.
func createDraftRelease(repo *git.Repository, opts *CutOptions, plan *ReleasePlan) (string, int64, error) {
	return createGitHubRelease(repo, opts, plan, true)
}

// ToJSON serializes the cut result to JSON
func (r *CutResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
