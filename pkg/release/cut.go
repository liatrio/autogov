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
	RepoPath        string         // path to git repo (default ".")
	Branch          string         // expected branch (default "main")
	Remote          string         // git remote name (default "origin")
	PlanFile        string         // path to pre-generated plan JSON/YAML
	MutationsConfig string         // path to mutations config file
	DryRun          bool           // show what would happen without side effects
	Publish         bool           // create published release directly (no draft)
	Mode            ReleaseMode    // "auto" (default), "api", "local"
	CommitAuthor    string         // bot commit author name
	CommitEmail     string         // bot commit author email
	Token           string         // GitHub token for API and push
	ReleaseAPI      ReleaseService // optional; created from Token if nil
}

// CutResult captures the outcome of a release cut
type CutResult struct {
	TagName       string   `json:"tag_name"`
	Version       string   `json:"version"`
	CommitSHA     string   `json:"commit_sha"`
	ReleaseURL    string   `json:"release_url,omitempty"`
	ReleaseID     int64    `json:"release_id,omitempty"`
	Draft         bool     `json:"draft"`
	Published     bool     `json:"published"`
	FilesModified []string `json:"files_modified,omitempty"`
	DryRun        bool     `json:"dry_run"`
	NoRelease     bool     `json:"no_release"`
	Reason        string   `json:"reason,omitempty"`
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

	// step 3: immutability checks
	if err := checkImmutability(repo, opts, tagName); err != nil {
		return nil, fmt.Errorf("immutability check failed: %w", err)
	}

	result := &CutResult{
		TagName:   tagName,
		Version:   strings.TrimPrefix(plan.NextVersion, "v"),
		Draft:     !opts.Publish,
		Published: opts.Publish,
		DryRun:    opts.DryRun,
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

	// step 7: update branch ref to point at new commit
	if err := updateBranchRef(ctx, opts, owner, repoName, opts.Branch, commitSHA); err != nil {
		return nil, fmt.Errorf("failed to update branch ref: %w", err)
	}

	// step 8: create GitHub release (draft or published based on --publish flag)
	releaseURL, releaseID, err := createGitHubRelease(repo, opts, plan, !opts.Publish)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub release: %w", err)
	}
	result.ReleaseURL = releaseURL
	result.ReleaseID = releaseID

	return result, nil
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

// createAnnotatedTagViaAPI creates an annotated tag via GitHub's Git Data API (auto-signed/verified)
func createAnnotatedTagViaAPI(ctx context.Context, opts *CutOptions, tagName, commitSHA string, plan *ReleasePlan, owner, repoName string) error {
	tagMessage := fmt.Sprintf("Release %s\n\n%s", tagName, plan.ChangelogPreview)

	// omit tagger so GitHub auto-signs as the authenticated identity
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
