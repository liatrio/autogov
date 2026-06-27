package predicate

import (
	"context"

	gh "github.com/google/go-github/v88/github"
)

// ReviewService abstracts the GitHub REST calls the source-review predicate
// needs, so NewSourceReview is unit-testable without a live API (mirrors
// ReleaseService in pkg/release/cut.go). All methods are REST-only; v0.1
// adds no GraphQL/githubv4 dependency (see the source-review design).
type ReviewService interface {
	// ListPullRequestsWithCommit returns pull requests associated with a commit
	// SHA. Documented quirk (go-github v88): if the SHA is not present in the
	// repository's default branch, the result includes ONLY open pull requests —
	// so a release-branch/tag build can return zero merged PRs even though the
	// change was reviewed. NewSourceReview treats that as incompleteness, not a
	// definitive direct push.
	ListPullRequestsWithCommit(ctx context.Context, owner, repo, sha string, opts *gh.ListOptions) ([]*gh.PullRequest, *gh.Response, error)
	// ListReviews lists all reviews on a pull request (paginated).
	ListReviews(ctx context.Context, owner, repo string, number int, opts *gh.ListOptions) ([]*gh.PullRequestReview, *gh.Response, error)
	// GetBranchProtection returns classic branch protection. Needs admin /
	// Administration:read; a 404 means no protection (not an error condition).
	GetBranchProtection(ctx context.Context, owner, repo, branch string) (*gh.Protection, *gh.Response, error)
	// ListRulesForBranch returns the repository rules (rulesets) active for a
	// branch. Readable without admin — the no-admin path to the required-review
	// threshold.
	ListRulesForBranch(ctx context.Context, owner, repo, branch string, opts *gh.ListOptions) (*gh.BranchRules, *gh.Response, error)
	// GetRuleset returns a repository ruleset (incl. org/enterprise parents when
	// includesParents). Needs Administration:read; a 403/404 is best-effort — the
	// producer omits bypass actors rather than failing the attestation.
	GetRuleset(ctx context.Context, owner, repo string, rulesetID int64, includesParents bool) (*gh.RepositoryRuleset, *gh.Response, error)
}

// githubReviewService is the live ReviewService backed by a go-github client.
type githubReviewService struct {
	client *gh.Client
}

// NewGitHubReviewService wraps a go-github client as a ReviewService.
func NewGitHubReviewService(client *gh.Client) ReviewService {
	return &githubReviewService{client: client}
}

func (s *githubReviewService) ListPullRequestsWithCommit(ctx context.Context, owner, repo, sha string, opts *gh.ListOptions) ([]*gh.PullRequest, *gh.Response, error) {
	return s.client.PullRequests.ListPullRequestsWithCommit(ctx, owner, repo, sha, opts)
}

func (s *githubReviewService) ListReviews(ctx context.Context, owner, repo string, number int, opts *gh.ListOptions) ([]*gh.PullRequestReview, *gh.Response, error) {
	return s.client.PullRequests.ListReviews(ctx, owner, repo, number, opts)
}

func (s *githubReviewService) GetBranchProtection(ctx context.Context, owner, repo, branch string) (*gh.Protection, *gh.Response, error) {
	return s.client.Repositories.GetBranchProtection(ctx, owner, repo, branch)
}

func (s *githubReviewService) ListRulesForBranch(ctx context.Context, owner, repo, branch string, opts *gh.ListOptions) (*gh.BranchRules, *gh.Response, error) {
	return s.client.Repositories.ListRulesForBranch(ctx, owner, repo, branch, opts)
}

func (s *githubReviewService) GetRuleset(ctx context.Context, owner, repo string, rulesetID int64, includesParents bool) (*gh.RepositoryRuleset, *gh.Response, error) {
	return s.client.Repositories.GetRuleset(ctx, owner, repo, rulesetID, includesParents)
}
