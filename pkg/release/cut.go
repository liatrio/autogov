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
	gogithub "github.com/google/go-github/v82/github"
	"github.com/liatrio/autogov-verify/pkg/mutate"
	"gopkg.in/yaml.v3"
)

// CutOptions contains configuration for executing a release cut
type CutOptions struct {
	RepoPath        string         // path to git repo (default ".")
	Branch          string         // expected branch (default "main")
	Remote          string         // git remote name (default "origin")
	PlanFile        string         // path to pre-generated plan JSON/YAML
	MutationsConfig string         // path to mutations config file
	DryRun          bool           // show what would happen without side effects
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
	FilesModified []string `json:"files_modified,omitempty"`
	DryRun        bool     `json:"dry_run"`
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
	CreateRelease(ctx context.Context, owner, repo string, release *gogithub.RepositoryRelease) (*gogithub.RepositoryRelease, *gogithub.Response, error)
	UpdateRelease(ctx context.Context, owner, repo string, id int64, release *gogithub.RepositoryRelease) (*gogithub.RepositoryRelease, *gogithub.Response, error)
	ListReleases(ctx context.Context, owner, repo string, opts *gogithub.ListOptions) ([]*gogithub.RepositoryRelease, *gogithub.Response, error)
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

func (s *githubReleaseService) CreateRelease(ctx context.Context, owner, repo string, release *gogithub.RepositoryRelease) (*gogithub.RepositoryRelease, *gogithub.Response, error) {
	return s.client.Repositories.CreateRelease(ctx, owner, repo, release)
}

func (s *githubReleaseService) UpdateRelease(ctx context.Context, owner, repo string, id int64, release *gogithub.RepositoryRelease) (*gogithub.RepositoryRelease, *gogithub.Response, error) {
	return s.client.Repositories.EditRelease(ctx, owner, repo, id, release)
}

func (s *githubReleaseService) ListReleases(ctx context.Context, owner, repo string, opts *gogithub.ListOptions) ([]*gogithub.RepositoryRelease, *gogithub.Response, error) {
	return s.client.Repositories.ListReleases(ctx, owner, repo, opts)
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

func newGitHubReleaseService(token string) ReleaseService {
	client := gogithub.NewClient(nil).WithAuthToken(token)
	return &githubReleaseService{client: client}
}

// ExecuteCut orchestrates the full release cut flow
func ExecuteCut(opts *CutOptions) (*CutResult, error) {
	if opts == nil {
		opts = DefaultCutOptions()
	}

	repo, err := OpenRepository(opts.RepoPath)
	if err != nil {
		return nil, err
	}

	// initialize GitHub release service if token is available
	if opts.Token != "" && opts.ReleaseAPI == nil {
		opts.ReleaseAPI = newGitHubReleaseService(opts.Token)
	}

	// step 1: validate working tree is clean and on correct branch
	if err := validateWorktree(repo, opts.Branch); err != nil {
		return nil, fmt.Errorf("worktree validation failed: %w", err)
	}

	// step 2: generate or load the release plan
	plan, err := resolvePlan(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve release plan: %w", err)
	}

	if !plan.ReleaseNeeded {
		return nil, fmt.Errorf("no release needed: %s", plan.Reason)
	}

	tagName := plan.NextVersion // already has v prefix from Version.String()

	// step 3: immutability checks
	if err := checkImmutability(repo, opts, tagName); err != nil {
		return nil, fmt.Errorf("immutability check failed: %w", err)
	}

	result := &CutResult{
		TagName: tagName,
		Version: strings.TrimPrefix(plan.NextVersion, "v"),
		Draft:   true,
		DryRun:  opts.DryRun,
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
		fmt.Fprintf(os.Stderr, "dry-run: would create commit, tag, push, and create draft GitHub release\n")
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
	commitSHA, err := createReleaseCommitViaAPI(ctx, repo, opts, plan, owner, repoName)
	if err != nil {
		return nil, fmt.Errorf("failed to create release commit: %w", err)
	}
	result.CommitSHA = commitSHA

	// step 6: create annotated tag via GitHub API (auto-signed/verified)
	if err := createAnnotatedTagViaAPI(ctx, opts, tagName, commitSHA, plan, owner, repoName); err != nil {
		return nil, fmt.Errorf("failed to create tag %s: %w", tagName, err)
	}

	// step 7: update branch ref to point at new commit
	if err := updateBranchRef(ctx, opts, owner, repoName, opts.Branch, commitSHA); err != nil {
		return nil, fmt.Errorf("failed to update branch ref: %w", err)
	}

	// step 8: create draft GitHub release
	releaseURL, releaseID, err := createDraftRelease(repo, opts, plan)
	if err != nil {
		return nil, fmt.Errorf("failed to create draft release: %w", err)
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

	// detached HEAD: check if HEAD SHA matches the tip of the expected branch.
	// Try local branch first, then remote refs (CI checkouts often lack local branches).
	branchRef, err := repo.Reference(plumbing.NewBranchReferenceName(expectedBranch), true)
	if err != nil {
		// try remote refs (e.g., refs/remotes/origin/main)
		remotes, remoteErr := repo.Remotes()
		if remoteErr == nil {
			for _, remote := range remotes {
				remoteRef, refErr := repo.Reference(
					plumbing.NewRemoteReferenceName(remote.Config().Name, expectedBranch), true)
				if refErr == nil {
					branchRef = remoteRef
					break
				}
			}
		}
		if branchRef == nil {
			return fmt.Errorf("expected branch %q but on %q (branch not found locally or in remotes)", expectedBranch, currentBranch)
		}
	}

	if head.Hash() != branchRef.Hash() {
		return fmt.Errorf("expected branch %q but on %q", expectedBranch, currentBranch)
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
	// check local tags
	if _, err := repo.Tag(tagName); err == nil {
		return fmt.Errorf("tag %s already exists locally", tagName)
	}

	// check remote tags via ls-remote (non-fatal if remote unavailable)
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

// createReleaseCommitViaAPI creates a commit via GitHub's Git Data API (auto-signed/verified)
func createReleaseCommitViaAPI(ctx context.Context, repo *git.Repository, opts *CutOptions, plan *ReleasePlan, owner, repoName string) (string, error) {
	head, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("failed to get HEAD: %w", err)
	}
	headSHA := head.Hash().String()

	// get the base tree from current HEAD
	headCommit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return "", fmt.Errorf("failed to get HEAD commit: %w", err)
	}
	baseTreeSHA := headCommit.TreeHash.String()

	// read mutated files from worktree
	wt, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to get worktree: %w", err)
	}

	status, err := wt.Status()
	if err != nil {
		return "", fmt.Errorf("failed to get worktree status: %w", err)
	}

	var entries []*gogithub.TreeEntry
	for filePath := range status {
		content, err := os.ReadFile(filepath.Join(opts.RepoPath, filePath))
		if err != nil {
			return "", fmt.Errorf("failed to read mutated file %s: %w", filePath, err)
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
			return "", fmt.Errorf("failed to create tree: %w", err)
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
		return "", fmt.Errorf("failed to create commit via API: %w", err)
	}

	return created.GetSHA(), nil
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

// createDraftRelease creates a draft GitHub release via the API
func createDraftRelease(repo *git.Repository, opts *CutOptions, plan *ReleasePlan) (string, int64, error) {
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
		Draft:                gogithub.Ptr(true),
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

// ToJSON serializes the cut result to JSON
func (r *CutResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
