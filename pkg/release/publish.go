package release

import (
	"context"
	"encoding/json"
	"fmt"

	gogithub "github.com/google/go-github/v82/github"
)

// PublishOptions contains configuration for publishing a draft release
type PublishOptions struct {
	RepoPath   string         // path to git repo (for remote detection)
	Tag        string         // specific tag to publish (mutually exclusive with Latest)
	Latest     bool           // find latest draft (mutually exclusive with Tag)
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
		opts.ReleaseAPI = newGitHubReleaseService(opts.Token)
	}

	// parse owner/repo from git remote
	repo, err := OpenRepository(opts.RepoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	repoName := GetRepositoryName(repo)
	owner, repoNameOnly, err := parseOwnerRepoFromName(repoName)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	// find the draft release (by tag or latest)
	release, err := findDraftRelease(ctx, opts, owner, repoNameOnly)
	if err != nil {
		return nil, err
	}

	result := &PublishResult{
		TagName:   release.GetTagName(),
		ReleaseID: release.GetID(),
		DryRun:    opts.DryRun,
		Published: false,
	}

	// dry-run: show what would happen
	if opts.DryRun {
		fmt.Printf("dry-run: would publish release %s (ID: %d)\n", result.TagName, result.ReleaseID)
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

	if opts.Tag != "" && opts.Latest {
		return fmt.Errorf("--tag and --latest are mutually exclusive")
	}

	if opts.Tag == "" && !opts.Latest {
		return fmt.Errorf("either --tag or --latest must be specified")
	}

	return nil
}

// findDraftRelease finds a draft release by tag or latest
func findDraftRelease(ctx context.Context, opts *PublishOptions, owner, repo string) (*gogithub.RepositoryRelease, error) {
	if opts.Tag != "" {
		return findDraftReleaseByTag(ctx, opts, owner, repo)
	}

	return findLatestDraftRelease(ctx, opts, owner, repo)
}

// findDraftReleaseByTag looks up a specific tag and verifies it's a draft
func findDraftReleaseByTag(ctx context.Context, opts *PublishOptions, owner, repo string) (*gogithub.RepositoryRelease, error) {
	release, resp, err := opts.ReleaseAPI.GetReleaseByTag(ctx, owner, repo, opts.Tag)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("release not found for tag %s: %w", opts.Tag, err)
	}

	if !release.GetDraft() {
		return nil, fmt.Errorf("release %s is already published (immutable)", opts.Tag)
	}

	return release, nil
}

// findLatestDraftRelease finds the first draft release in the list
func findLatestDraftRelease(ctx context.Context, opts *PublishOptions, owner, repo string) (*gogithub.RepositoryRelease, error) {
	listOpts := &gogithub.ListOptions{PerPage: 50}
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

	return nil, fmt.Errorf("no draft releases found (use --tag to specify)")
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

// parseOwnerRepoFromName extracts owner and repo from "owner/repo" string
func parseOwnerRepoFromName(repoName string) (string, string, error) {
	parts := splitOwnerRepo(repoName)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("cannot parse owner/repo from: %s", repoName)
	}
	return parts[0], parts[1], nil
}

// splitOwnerRepo splits "owner/repo" into parts
func splitOwnerRepo(repoName string) []string {
	// simple split on "/"
	result := []string{}
	start := 0
	for i := 0; i < len(repoName); i++ {
		if repoName[i] == '/' {
			if i > start {
				result = append(result, repoName[start:i])
			}
			start = i + 1
		}
	}
	if start < len(repoName) {
		result = append(result, repoName[start:])
	}
	return result
}

// ToJSON serializes the publish result to JSON
func (r *PublishResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
