package predicate

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	gh "github.com/google/go-github/v89/github"
)

// ReviewService abstracts the GitHub REST calls the source-review predicate
// needs, so NewSourceReview is unit-testable without a live API (mirrors
// ReleaseService in pkg/release/cut.go). All methods are REST-only; v0.1
// adds no GraphQL/githubv4 dependency (see the source-review design).
type ReviewService interface {
	// ListPullRequestsWithCommit returns pull requests associated with a commit
	// SHA. Documented quirk (go-github v89): if the SHA is not present in the
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

	// GetRulesetHistory returns the VERSION HISTORY of a ruleset, newest first,
	// for the SLSA Source-L3 continuity walk. go-github v89 binds NEITHER ruleset
	// history endpoint, so this is issued via the raw client. It tries the
	// repo-scoped endpoint first; if that 404s (the id belongs to an ORG/parent
	// ruleset that is only visible through includesParents on the repo), it falls
	// back to the org-scoped endpoint. A 403/404 on BOTH surfaces as an error so
	// continuity fails CLOSED (unreadable history is NEVER read as "no changes").
	// Paginates via the Link header (resp.NextPage).
	GetRulesetHistory(ctx context.Context, owner, repo string, rulesetID int64, opts *gh.ListOptions) ([]*RulesetVersion, *gh.Response, error)
	// GetRulesetVersion returns the full ruleset STATE at one historical version
	// (enforcement, conditions, rules, bypass actors). Like GetRulesetHistory it
	// is issued via the raw client with a repo→org fallback, and any 403/404
	// surfaces as an error so the continuity walk fails closed.
	GetRulesetVersion(ctx context.Context, owner, repo string, rulesetID, versionID int64) (*RulesetVersionState, *gh.Response, error)

	// ListCommits maps a continuity start TIME to a start COMMIT producer-side (the
	// verifier never calls GitHub). Called with SHA=branch + Since=start; the oldest
	// returned commit at-or-after the start time is the approximate start revision
	// R0. Paginated truncation (>cap pages) is treated as unresolvable -> fail closed.
	ListCommits(ctx context.Context, owner, repo string, opts *gh.CommitsListOptions) ([]*gh.RepositoryCommit, *gh.Response, error)
	// GetRepository returns the repository (for its default branch), so the
	// continuity walk can decide whether a ruleset version that targets only
	// "~DEFAULT_BRANCH" actually covers the artifact's protected branch. Unreadable
	// -> the default branch is unknown -> a "~DEFAULT_BRANCH"-only version fails
	// closed.
	GetRepository(ctx context.Context, owner, repo string) (*gh.Repository, *gh.Response, error)
	// GetPullRequest returns a single pull request. It exists to read merged_by:
	// the ListPullRequestsWithCommit list endpoint does NOT populate that field
	// (verified live — it returns merged_by:null for a known-merged PR), so the
	// merger identity requires this supplemental single-PR GET. Best-effort and
	// evidence-only in NewSourceReview (a failure never degrades the attestation).
	GetPullRequest(ctx context.Context, owner, repo string, number int) (*gh.PullRequest, *gh.Response, error)
}

// RulesetVersion is one entry in a ruleset's version history. created_at is NOT
// load-bearing for continuity — the per-version STATE (fetched via
// GetRulesetVersion) is. UpdatedAt is the time the version became effective and
// is what the walk uses for the per-leg start time.
type RulesetVersion struct {
	VersionID int64
	Actor     RulesetActor
	UpdatedAt time.Time
}

// RulesetActor identifies who created a ruleset version (recorded as evidence;
// not gated). A missing/typeless actor is tolerated — it never relaxes a leg.
type RulesetActor struct {
	ID   int64
	Type string
}

// RulesetVersionState is the full enforced state of a ruleset at a historical
// version, the unit the continuity walk inspects. Enforcement is the raw string
// so an UNKNOWN/missing value is treated as NON-active (never default-to-active).
// Rules is the typed ruleset rules object (nil when absent -> a rule is NOT
// present, never default-to-satisfied). BypassActors is judged narrow-vs-wide by
// the walk exactly like the live bypass list.
type RulesetVersionState struct {
	Enforcement  string
	Conditions   *gh.RepositoryRulesetConditions
	Rules        *gh.RepositoryRulesetRules
	BypassActors []*gh.BypassActor
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

func (s *githubReviewService) ListCommits(ctx context.Context, owner, repo string, opts *gh.CommitsListOptions) ([]*gh.RepositoryCommit, *gh.Response, error) {
	return s.client.Repositories.ListCommits(ctx, owner, repo, opts)
}

func (s *githubReviewService) GetRepository(ctx context.Context, owner, repo string) (*gh.Repository, *gh.Response, error) {
	return s.client.Repositories.Get(ctx, owner, repo)
}

// GetPullRequest reads a single pull request to recover merged_by, which the
// ListPullRequestsWithCommit list endpoint does NOT populate (verified live: it
// returns merged_by:null for a known-merged PR).
func (s *githubReviewService) GetPullRequest(ctx context.Context, owner, repo string, number int) (*gh.PullRequest, *gh.Response, error) {
	return s.client.PullRequests.Get(ctx, owner, repo, number)
}

// rawRulesetVersion is the wire shape of one ruleset-history entry
// (GET .../rulesets/{id}/history). Decoded locally because go-github v89 binds
// no type for it.
type rawRulesetVersion struct {
	VersionID int64 `json:"version_id"`
	Actor     struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
	} `json:"actor"`
	UpdatedAt *gh.Timestamp `json:"updated_at"`
}

// rawRulesetVersionState is the wire shape of one historical ruleset version
// (GET .../rulesets/{id}/history/{version_id}). The `state` object is the full
// ruleset (same shape as GetRuleset), so its sub-objects reuse go-github types.
type rawRulesetVersionState struct {
	State struct {
		Enforcement  string                          `json:"enforcement"`
		Conditions   *gh.RepositoryRulesetConditions `json:"conditions"`
		Rules        *gh.RepositoryRulesetRules      `json:"rules"`
		BypassActors []*gh.BypassActor               `json:"bypass_actors"`
	} `json:"state"`
}

func (s *githubReviewService) GetRulesetHistory(ctx context.Context, owner, repo string, rulesetID int64, opts *gh.ListOptions) ([]*RulesetVersion, *gh.Response, error) {
	repoURL := fmt.Sprintf("repos/%s/%s/rulesets/%d/history", owner, repo, rulesetID)
	orgURL := fmt.Sprintf("orgs/%s/rulesets/%d/history", owner, rulesetID)

	versions, resp, err := s.getRulesetHistoryAt(ctx, addPage(repoURL, opts), rulesetID)
	// Only fall back to the org-scoped endpoint on the FIRST page: a 404 there means
	// the id is an org/parent ruleset not addressable at repo scope. A 404 on a
	// LATER page of a repo-scoped history is a genuine read failure (or out-of-range
	// page) and MUST surface as an error — never silently re-scoped to org (which
	// could stitch a different ruleset's pages and mask an unreadable repo history).
	if isNotFound(resp) && isFirstPage(opts) {
		return s.getRulesetHistoryAt(ctx, addPage(orgURL, opts), rulesetID)
	}
	return versions, resp, err
}

// isFirstPage reports whether opts addresses the first page (page 0 or 1).
func isFirstPage(opts *gh.ListOptions) bool {
	return opts == nil || opts.Page <= 1
}

func (s *githubReviewService) getRulesetHistoryAt(ctx context.Context, url string, rulesetID int64) ([]*RulesetVersion, *gh.Response, error) {
	req, err := s.client.NewRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build ruleset-history request for %d: %w", rulesetID, err)
	}
	var raw []*rawRulesetVersion
	resp, err := s.client.Do(req, &raw)
	if err != nil {
		return nil, resp, fmt.Errorf("get ruleset %d history: %w", rulesetID, err)
	}
	out := make([]*RulesetVersion, 0, len(raw))
	for _, v := range raw {
		if v == nil {
			continue
		}
		rv := &RulesetVersion{VersionID: v.VersionID}
		rv.Actor = RulesetActor{ID: v.Actor.ID, Type: v.Actor.Type}
		if v.UpdatedAt != nil {
			rv.UpdatedAt = v.UpdatedAt.UTC()
		}
		out = append(out, rv)
	}
	return out, resp, nil
}

func (s *githubReviewService) GetRulesetVersion(ctx context.Context, owner, repo string, rulesetID, versionID int64) (*RulesetVersionState, *gh.Response, error) {
	repoURL := fmt.Sprintf("repos/%s/%s/rulesets/%d/history/%d", owner, repo, rulesetID, versionID)
	orgURL := fmt.Sprintf("orgs/%s/rulesets/%d/history/%d", owner, rulesetID, versionID)

	state, resp, err := s.getRulesetVersionAt(ctx, repoURL, rulesetID, versionID)
	if isNotFound(resp) {
		return s.getRulesetVersionAt(ctx, orgURL, rulesetID, versionID)
	}
	return state, resp, err
}

func (s *githubReviewService) getRulesetVersionAt(ctx context.Context, url string, rulesetID, versionID int64) (*RulesetVersionState, *gh.Response, error) {
	req, err := s.client.NewRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build ruleset-version request for %d/%d: %w", rulesetID, versionID, err)
	}
	var raw rawRulesetVersionState
	resp, err := s.client.Do(req, &raw)
	if err != nil {
		return nil, resp, fmt.Errorf("get ruleset %d version %d: %w", rulesetID, versionID, err)
	}
	return &RulesetVersionState{
		Enforcement:  raw.State.Enforcement,
		Conditions:   raw.State.Conditions,
		Rules:        raw.State.Rules,
		BypassActors: raw.State.BypassActors,
	}, resp, nil
}

// addPage appends the page + per_page query params to a raw endpoint when
// paginating (NewRequest takes the full URL string, so they are encoded here).
// per_page MUST be carried or the server falls back to its small default (30),
// silently shrinking how far back a clean history can be proven (and forcing the
// page cap to bite earlier).
func addPage(rawURL string, opts *gh.ListOptions) string {
	if opts == nil {
		return rawURL
	}
	q := url.Values{}
	if opts.Page > 0 {
		q.Set("page", strconv.Itoa(opts.Page))
	}
	if opts.PerPage > 0 {
		q.Set("per_page", strconv.Itoa(opts.PerPage))
	}
	if len(q) == 0 {
		return rawURL
	}
	return rawURL + "?" + q.Encode()
}

// isNotFound reports whether a response is an HTTP 404 (used to fall back from
// the repo-scoped history endpoint to the org-scoped one for a parent ruleset).
func isNotFound(resp *gh.Response) bool {
	return resp != nil && resp.Response != nil && resp.StatusCode == http.StatusNotFound
}
