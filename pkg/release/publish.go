package release

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	gogithub "github.com/google/go-github/v88/github"
	githelper "github.com/liatrio/autogov/pkg/helper/git"
)

// PublishOptions contains configuration for publishing a draft release
type PublishOptions struct {
	RepoPath  string // path to git repo (for remote detection)
	Tag       string // specific tag to publish (mutually exclusive with Latest and ReleaseID)
	Latest    bool   // find latest draft (mutually exclusive with Tag and ReleaseID)
	ReleaseID int64  // publish by numeric release ID — works with GitHub App tokens
	// Note: --tag and --latest require a user token; GitHub App tokens cannot discover
	// draft releases via list/search endpoints. Use --release-id for App token workflows.
	Token      string         // GitHub token (required)
	DryRun     bool           // preview only, don't publish
	ReleaseAPI ReleaseService // optional; created from Token if nil
}

// PublishResult captures the outcome of a release publish
type PublishResult struct {
	TagName    string `json:"tag_name"`
	ReleaseURL string `json:"release_url"`
	ReleaseID  int64  `json:"release_id"`
	Published  bool   `json:"published"` // always true on success
	DryRun     bool   `json:"dry_run"`
}

// ExecutePublish orchestrates the full release publish flow
func ExecutePublish(opts *PublishOptions) (*PublishResult, error) {
	if opts == nil {
		return nil, fmt.Errorf("PublishOptions cannot be nil")
	}

	// validate options
	if err := validatePublishOptions(opts); err != nil {
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

	// parse owner/repo from git remote
	repo, err := githelper.OpenRepository(opts.RepoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	repoName := githelper.GetRepositoryName(repo)
	parts := strings.SplitN(repoName, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("cannot parse owner/repo from: %s", repoName)
	}
	owner, repoNameOnly := parts[0], parts[1]

	ctx := context.Background()

	// find the draft release (by tag or latest)
	release, err := findDraftRelease(ctx, opts, owner, repoNameOnly)
	if err != nil {
		return nil, err
	}

	// verify the git tag exists on the remote before publishing
	// skip tag verification when using --release-id (trust the release record)
	if opts.ReleaseID == 0 {
		if err := verifyTagExists(repo, opts, release.GetTagName()); err != nil {
			return nil, err
		}
	}

	result := &PublishResult{
		TagName:   release.GetTagName(),
		ReleaseID: release.GetID(),
		DryRun:    opts.DryRun,
		Published: false,
	}

	// dry-run: return result without publishing; caller handles output
	if opts.DryRun {
		return result, nil
	}

	// publish the release (flip draft → false)
	published, err := publishRelease(ctx, opts, owner, repoNameOnly, release)
	if err != nil {
		return nil, fmt.Errorf("failed to publish release: %w", err)
	}

	result.Published = true
	result.ReleaseURL = published.GetHTMLURL()

	return result, nil
}

// validatePublishOptions checks that options are valid
func validatePublishOptions(opts *PublishOptions) error {
	if opts.Token == "" {
		return fmt.Errorf("GitHub token required for publish (set GITHUB_TOKEN)")
	}

	// count how many selection modes are specified
	modes := 0
	if opts.Tag != "" {
		modes++
	}
	if opts.Latest {
		modes++
	}
	if opts.ReleaseID != 0 {
		modes++
	}

	if modes > 1 {
		return fmt.Errorf("--tag, --latest, and --release-id are mutually exclusive")
	}

	if modes == 0 {
		return fmt.Errorf("one of --tag, --latest, or --release-id must be specified")
	}

	return nil
}

// findDraftRelease finds a draft release by tag, latest, or release ID
func findDraftRelease(ctx context.Context, opts *PublishOptions, owner, repo string) (*gogithub.RepositoryRelease, error) {
	if opts.ReleaseID != 0 {
		return findDraftReleaseByID(ctx, opts, owner, repo)
	}
	if opts.Tag != "" {
		return findDraftReleaseByTag(ctx, opts, owner, repo)
	}
	return findLatestDraftRelease(ctx, opts, owner, repo)
}

// findDraftReleaseByID fetches a release directly by numeric ID.
// This works with GitHub App tokens that cannot list/search draft releases.
func findDraftReleaseByID(ctx context.Context, opts *PublishOptions, owner, repo string) (*gogithub.RepositoryRelease, error) {
	rel, resp, err := opts.ReleaseAPI.GetRelease(ctx, owner, repo, opts.ReleaseID)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get release ID %d: %w", opts.ReleaseID, err)
	}
	if rel == nil {
		return nil, fmt.Errorf("release ID %d not found", opts.ReleaseID)
	}
	if !rel.GetDraft() {
		return nil, fmt.Errorf("release ID %d (%s) is already published (immutable)", opts.ReleaseID, rel.GetTagName())
	}
	return rel, nil
}

// findDraftReleaseByTag finds a draft release matching the given tag.
// Tries GetReleaseByTag first (works with tokens that have push access),
// then falls back to ListReleases for broader compatibility.
func findDraftReleaseByTag(ctx context.Context, opts *PublishOptions, owner, repo string) (*gogithub.RepositoryRelease, error) {
	// try GetReleaseByTag first — returns drafts if the token has push access
	rel, resp, err := opts.ReleaseAPI.GetReleaseByTag(ctx, owner, repo, opts.Tag)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil && rel != nil {
		if !rel.GetDraft() {
			return nil, fmt.Errorf("release %s is already published (immutable)", opts.Tag)
		}
		return rel, nil
	}

	// fall back to ListReleases (drafts may not appear for some token types)
	const maxPages = 10
	listOpts := &gogithub.ListOptions{PerPage: 50}

	for attempt := 0; attempt < maxPages; attempt++ {
		releases, resp, err := opts.ReleaseAPI.ListReleases(ctx, owner, repo, listOpts)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list releases: %w", err)
		}

		for _, release := range releases {
			if release.GetTagName() == opts.Tag {
				if !release.GetDraft() {
					return nil, fmt.Errorf("release %s is already published (immutable)", opts.Tag)
				}
				return release, nil
			}
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	return nil, fmt.Errorf("no draft release found for tag %s", opts.Tag)
}

// findLatestDraftRelease finds the first draft release in the list
func findLatestDraftRelease(ctx context.Context, opts *PublishOptions, owner, repo string) (*gogithub.RepositoryRelease, error) {
	const maxPages = 10
	listOpts := &gogithub.ListOptions{PerPage: 50}

	for attempt := 0; attempt < maxPages; attempt++ {
		releases, resp, err := opts.ReleaseAPI.ListReleases(ctx, owner, repo, listOpts)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list releases: %w", err)
		}

		for _, release := range releases {
			if release.GetDraft() {
				return release, nil
			}
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	return nil, fmt.Errorf("no draft releases found (use --tag to specify)")
}

// verifyTagExists confirms the git tag exists on the remote before publishing.
// Non-fatal on network failures: logs a warning and proceeds.
func verifyTagExists(repo *git.Repository, opts *PublishOptions, tagName string) error {
	remote, err := repo.Remote("origin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not access remote for tag verification: %v\n", err)
		return nil
	}

	listOpts := &git.ListOptions{}
	if opts.Token != "" {
		listOpts.Auth = &http.BasicAuth{Username: "x-access-token", Password: opts.Token}
	}

	refs, err := remote.List(listOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not verify remote tag %s (skipping): %v\n", tagName, err)
		return nil
	}

	tagRef := plumbing.NewTagReferenceName(tagName)
	for _, ref := range refs {
		if ref.Name() == tagRef {
			return nil
		}
	}

	return fmt.Errorf("tag %s does not exist on remote", tagName)
}

// publishRelease flips draft → false via GitHub API
func publishRelease(ctx context.Context, opts *PublishOptions, owner, repo string, release *gogithub.RepositoryRelease) (*gogithub.RepositoryRelease, error) {
	update := &gogithub.RepositoryRelease{
		Draft: gogithub.Ptr(false), // flip to published
	}

	published, resp, err := opts.ReleaseAPI.UpdateRelease(ctx, owner, repo, release.GetID(), update)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}

	return published, nil
}

// ToJSON serializes the publish result to JSON
func (r *PublishResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
