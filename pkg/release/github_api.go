package release

import (
	"context"
	"fmt"
	"sort"
	"strings"

	gogithub "github.com/google/go-github/v88/github"
	"github.com/liatrio/autogov/pkg/helper/version"
)

// rawCommit holds commit data returned by the GitHub Compare API.
type rawCommit struct {
	SHA        string
	Message    string
	ParentSHAs []string
}

// listTagsFromAPI fetches all tags from GitHub API, sorts by semver (descending),
// and returns the sorted list of tag names. Page limit: 10 pages (500 tags max).
func listTagsFromAPI(ctx context.Context, svc ReleaseService, owner, repo string) ([]string, error) {
	const maxPages = 10
	opts := &gogithub.ListOptions{PerPage: 50}

	var allTags []*gogithub.RepositoryTag
	for attempt := 0; attempt < maxPages; attempt++ {
		tags, resp, err := svc.ListTags(ctx, owner, repo, opts)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list tags (page %d): %w", attempt+1, err)
		}
		allTags = append(allTags, tags...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		if attempt == maxPages-1 {
			return nil, fmt.Errorf("tag limit exceeded: more than %d pages of tags", maxPages)
		}
		opts.Page = resp.NextPage
	}

	// filter to valid semver tags, sort descending
	type tagEntry struct {
		name    string
		version *version.Version
	}
	var semverTags []tagEntry
	for _, t := range allTags {
		name := t.GetName()
		ver, err := version.ParseVersion(name)
		if err != nil {
			continue // skip non-semver tags
		}
		semverTags = append(semverTags, tagEntry{name: name, version: ver})
	}

	sort.Slice(semverTags, func(i, j int) bool {
		return !semverTags[i].version.LessThan(semverTags[j].version) // descending
	})

	names := make([]string, len(semverTags))
	for i, t := range semverTags {
		names[i] = t.name
	}
	return names, nil
}

// errTruncated is returned when the GitHub Compare API truncates the commit list.
var errTruncated = fmt.Errorf("compare API response truncated (>250 commits)")

// getCommitsFromAPI fetches commits between base (tag name or SHA) and head (SHA)
// using the GitHub Compare API, then filters to first-parent commits only.
// Returns errTruncated if the response is truncated (more than 250 commits).
func getCommitsFromAPI(ctx context.Context, svc ReleaseService, owner, repo, base, head string) ([]rawCommit, error) {
	comparison, resp, err := svc.CompareCommits(ctx, owner, repo, base, head, &gogithub.ListOptions{})
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to compare commits (%s...%s): %w", base, head, err)
	}

	// GitHub Compare API returns at most 250 commits; detect truncation
	if comparison.GetTotalCommits() > len(comparison.Commits) {
		return nil, fmt.Errorf("%w: %d total, %d returned for %s...%s",
			errTruncated, comparison.GetTotalCommits(), len(comparison.Commits), base, head)
	}

	return filterFirstParent(comparison.Commits, head), nil
}

// filterFirstParent filters commits to only those on the first-parent chain from head.
// The GitHub Compare API returns all commits between base and head (chronological order).
// We walk backwards from head following first parents to simulate git --first-parent.
func filterFirstParent(commits []*gogithub.RepositoryCommit, headSHA string) []rawCommit {
	// build SHA → commit map
	bysha := make(map[string]*gogithub.RepositoryCommit, len(commits))
	for _, c := range commits {
		bysha[c.GetSHA()] = c
	}

	// walk first-parent chain from head back to base
	var chain []rawCommit
	current := headSHA
	for {
		c, ok := bysha[current]
		if !ok {
			break // reached base or a commit not in the response
		}
		msg := ""
		if c.Commit != nil {
			msg = c.Commit.GetMessage()
		}
		var parentSHAs []string
		for _, p := range c.Parents {
			parentSHAs = append(parentSHAs, p.GetSHA())
		}
		chain = append(chain, rawCommit{
			SHA:        c.GetSHA(),
			Message:    msg,
			ParentSHAs: parentSHAs,
		})
		if len(parentSHAs) == 0 {
			break
		}
		current = parentSHAs[0] // follow first parent only
	}

	// chain is head→base order; reverse to chronological (base→head)
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// getBranchTipFromAPI fetches the tip commit SHA of a branch via the GitHub API.
func getBranchTipFromAPI(ctx context.Context, svc ReleaseService, owner, repo, branch string) (string, error) {
	b, resp, err := svc.GetBranch(ctx, owner, repo, branch, 0)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return "", fmt.Errorf("failed to get branch %q: %w", branch, err)
	}
	if b == nil || b.Commit == nil {
		return "", fmt.Errorf("branch %q has no commits", branch)
	}
	return b.Commit.GetSHA(), nil
}

// parseRawCommits converts a slice of rawCommit to version.ParsedCommit.
// Used for API-mode commit parsing; mirrors ParseCommits for go-git commits.
func parseRawCommits(commits []rawCommit) []version.ParsedCommit {
	var parsed []version.ParsedCommit
	for _, c := range commits {
		pc := version.ParseConventionalCommit(c.SHA, c.Message)
		if pc == nil {
			lines := strings.SplitN(c.Message, "\n", 2)
			subject := strings.TrimSpace(lines[0])
			body := ""
			if len(lines) > 1 {
				body = strings.TrimSpace(lines[1])
			}
			pc = &version.ParsedCommit{
				Hash:    c.SHA,
				Type:    "other",
				Subject: subject,
				Body:    body,
				Raw:     c.Message,
			}
		}
		parsed = append(parsed, *pc)
	}
	return parsed
}
