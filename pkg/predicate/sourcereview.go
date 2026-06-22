package predicate

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	gh "github.com/google/go-github/v88/github"
	ghclient "github.com/liatrio/autogov/pkg/github"
)

// SourceReviewPredicateTypeURI is the custom autogov source-review predicate
// type. It records the human PR-review/approval evidence for the source
// revision that produced an artifact (SLSA source-track / two-person review).
// No in-toto or SLSA standard predicate exists for source review — SLSA's
// source track leaves it vendor-specific and gittuf/liatr.io both namespace
// their own — so this mirrors the metadata/code-scan precedent. Kept at v0.1
// until the GitHub review mapping soaks; the URI is permanent once published.
const SourceReviewPredicateTypeURI = "https://autogov.dev/attestation/source-review/v0.1"

// GitHub pull request review states (REST Reviews endpoint). The real enum is
// CHANGES_REQUESTED (not the docs' "REQUEST_CHANGES"). COMMENTED and PENDING are
// non-opinionated and ignored.
const (
	reviewStateApproved         = "APPROVED"
	reviewStateChangesRequested = "CHANGES_REQUESTED"
	reviewStateDismissed        = "DISMISSED"
)

// userTypeBot is the User.Type value for GitHub App bot accounts. Note it does
// NOT catch a machine/service account typed "User"; association is the
// orthogonal signal for those (carried per-approver for a future min_association
// knob).
const userTypeBot = "Bot"

// caps that bound untrusted GitHub free-text in a signed, public attestation.
// Prefixed sr* to avoid colliding with the code-scan caps in the same package.
const (
	srMaxStringLen    = 512  // login, url, repo, ref
	srMaxSHALen       = 64   // commit SHAs (sha-1 40, sha-256 64)
	srMaxTimestampLen = 64   // RFC3339
	srMaxApprovers    = 1000 // backstop; distinct human approvers never approach this
)

// SourceReviewPR captures the pull request whose merge produced the source
// revision. Omitted entirely when no merged PR is resolved.
type SourceReviewPR struct {
	Number         int    `json:"number"`
	URL            string `json:"url,omitempty"`
	Author         string `json:"author,omitempty"`
	MergedAt       string `json:"mergedAt,omitempty"`
	MergeCommitSha string `json:"mergeCommitSha,omitempty"`
}

// SourceReviewApprover is one distinct reviewer whose latest opinionated review
// state is APPROVED (the PR author is never included). stale and isBot are
// recorded so the gate can recompute/verify the count rather than trust a
// producer-asserted summary boolean.
type SourceReviewApprover struct {
	Login       string `json:"login"`
	Association string `json:"association,omitempty"`
	SubmittedAt string `json:"submittedAt,omitempty"`
	CommitID    string `json:"commitId,omitempty"`
	Stale       bool   `json:"stale"`
	IsBot       bool   `json:"isBot"`
}

// SourceReviewSummary is always populated, even when approvers[] is omitted, so
// an operator can gate without the approver list. The booleans are EVIDENCE,
// never gate inputs: pass/fail derives only from the numeric counts (see the
// gating policy). distinctApprovers is the STRICTEST count (author, stale,
// dismissed, changes-requested, and bot reviewers excluded).
type SourceReviewSummary struct {
	Approvals            int  `json:"approvals"`
	DistinctApprovers    int  `json:"distinctApprovers"`
	ChangesRequested     int  `json:"changesRequested"`
	RequiredApprovals    int  `json:"requiredApprovals"`
	RequirementMet       bool `json:"requirementMet"`
	SelfApprovalExcluded bool `json:"selfApprovalExcluded"`
	// CodeownerReviewMet is tri-state: a nil pointer (JSON null) means "not
	// authoritatively determinable" — REST-only cannot reliably evaluate
	// CODEOWNERS, so v0.1 always leaves it null. The gate treats null as
	// undetermined and fails closed when codeowner review is required.
	CodeownerReviewMet *bool `json:"codeownerReviewMet"`
}

// SourceReviewBranchProtection records the review controls discovered on the
// target branch (best-effort; omitted when none is visible). Evidence for the
// required count; the gate bars on its own configured min_approvals.
type SourceReviewBranchProtection struct {
	RequireReviews               bool `json:"requireReviews"`
	RequiredApprovingReviewCount int  `json:"requiredApprovingReviewCount"`
	DismissStaleReviews          bool `json:"dismissStaleReviews"`
	RequireCodeownerReview       bool `json:"requireCodeownerReview"`
	// RequireLastPushApproval records GitHub's "last push must be approved by
	// someone other than the pusher" control. v0.1 enforces the on-head-commit
	// half via staleness (an approval not on the PR head does not count); the
	// "approver != last pusher" nuance requires push authorship not fetched here,
	// so it is recorded as evidence and left for a future version.
	RequireLastPushApproval bool `json:"requireLastPushApproval"`
}

// SourceReview is the predicate portion of an autogov source-review attestation
// (https://autogov.dev/attestation/source-review/v0.1).
type SourceReview struct {
	// subject-binding fields, not part of the predicate body
	Type        ArtifactType `json:"-"`
	SubjectName string       `json:"-"`
	SubjectPath string       `json:"-"`
	Digest      string       `json:"-"`

	SourceRepository string          `json:"sourceRepository"`
	SourceRevision   string          `json:"sourceRevision"`
	Ref              string          `json:"ref,omitempty"`
	PullRequest      *SourceReviewPR `json:"pullRequest,omitempty"`

	Summary SourceReviewSummary `json:"summary"`

	// ApproversIncluded is true when approvers[] is authoritative (every
	// qualifying reviewer is present). The gate may recompute over approvers[]
	// only when this is true; otherwise it must use the summary counts and fail
	// closed if a per-reviewer filter it cannot satisfy is requested.
	ApproversIncluded bool                   `json:"approversIncluded"`
	Approvers         []SourceReviewApprover `json:"approvers,omitempty"`

	BranchProtection *SourceReviewBranchProtection `json:"branchProtection,omitempty"`

	// ReviewDecision is reserved for an optional best-effort GraphQL enrichment
	// (pullRequest.reviewDecision). It is INFORMATIONAL ONLY and never a basis for
	// PASS. v0.1 adds no GraphQL client, so it is always empty here.
	ReviewDecision string `json:"reviewDecision,omitempty"`

	Configuration []ResourceDescriptor `json:"configuration"`

	// ReviewToolingComplete is false when the review evidence could not be fully
	// gathered (PRs/reviews unfetchable, or no merged PR resolved — which covers
	// both a genuine direct push and the ListPullRequestsWithCommit default-branch
	// quirk). Mirrors code-scan's invocation.executionSuccessful: the gate fails
	// this closed by default.
	ReviewToolingComplete bool `json:"reviewToolingComplete"`
}

// SourceReviewOptions contains options for creating a source-review predicate.
type SourceReviewOptions struct {
	Type             ArtifactType
	SubjectName      string
	SubjectPath      string
	Digest           string
	Owner            string
	Repo             string
	CommitSHA        string // the canonical source revision (merge/squash commit on the target branch)
	Ref              string // target branch ref of the artifact build
	PRNumber         int    // optional disambiguation hint; 0 = auto-discover from the commit
	IncludeApprovers bool   // default on; embeds the per-approver list
	ConfigURI        string
}

// NewSourceReview builds a source-review predicate from GitHub review evidence,
// implementing the locked review algorithm + GATE SEMANTICS. svc is injected for
// testability.
func NewSourceReview(ctx context.Context, svc ReviewService, opts SourceReviewOptions) (*SourceReview, error) {
	if opts.Owner == "" || opts.Repo == "" {
		return nil, fmt.Errorf("owner and repo are required")
	}
	if opts.CommitSHA == "" {
		return nil, fmt.Errorf("commit SHA is required")
	}

	queriedSHA := truncateRunes(opts.CommitSHA, srMaxSHALen)

	c := &SourceReview{
		Type:                  opts.Type,
		SubjectName:           opts.SubjectName,
		SubjectPath:           opts.SubjectPath,
		Digest:                opts.Digest,
		SourceRepository:      truncateRunes(fmt.Sprintf("https://github.com/%s/%s", opts.Owner, opts.Repo), srMaxStringLen),
		SourceRevision:        queriedSHA,
		Ref:                   truncateRunes(normalizeRef(opts.Ref), srMaxStringLen),
		Configuration:         []ResourceDescriptor{},
		ApproversIncluded:     opts.IncludeApprovers,
		ReviewToolingComplete: true,
	}
	if opts.IncludeApprovers {
		c.Approvers = []SourceReviewApprover{}
	}
	if opts.ConfigURI != "" {
		c.Configuration = append(c.Configuration, ResourceDescriptor{URI: truncateRunes(opts.ConfigURI, srMaxStringLen)})
	}

	// step 1: resolve the PR whose merge produced the queried source revision.
	prs, err := listPRsWithCommit(ctx, svc, opts.Owner, opts.Repo, queriedSHA)
	if err != nil {
		// cannot enumerate PRs -> blind -> incompleteness (fail closed downstream).
		c.ReviewToolingComplete = false
		return c, nil
	}

	selected := selectMergedPR(prs, queriedSHA, opts.PRNumber)
	if selected == nil {
		// No merged PR matched. EITHER a genuine unreviewed direct push OR the
		// documented ListPullRequestsWithCommit default-branch quirk (a
		// release-branch/tag build whose SHA is not on the default branch returns
		// ONLY open PRs). REST cannot cheaply distinguish the two, so we mirror
		// code-scan's incomplete-vs-definitive handling and treat it as
		// incompleteness rather than a false hard fail. The gate fails this closed
		// by default (fail_on_incomplete_review), so an unreviewed direct push is
		// still rejected without spuriously failing legitimate release builds.
		c.ReviewToolingComplete = false
		return c, nil
	}

	prAuthorID := selected.GetUser().GetID()
	prHeadSHA := selected.GetHead().GetSHA()
	prBaseRef := selected.GetBase().GetRef()
	if c.Ref == "" {
		c.Ref = truncateRunes(prBaseRef, srMaxStringLen)
	}
	c.PullRequest = &SourceReviewPR{
		Number:         selected.GetNumber(),
		URL:            truncateRunes(selected.GetHTMLURL(), srMaxStringLen),
		Author:         truncateRunes(selected.GetUser().GetLogin(), srMaxStringLen),
		MergedAt:       formatTimestamp(selected.GetMergedAt()),
		MergeCommitSha: truncateRunes(selected.GetMergeCommitSHA(), srMaxSHALen),
	}

	// step 8 (fetched before staleness in step 4, which needs dismissStale):
	// branch protection + rulesets are best-effort. A 404 / no-admin just leaves
	// the threshold unknown; it does NOT make the result incomplete, because the
	// gate bars on its own min_approvals, not on requiredApprovals (evidence only).
	dismissStale, requiredApprovals, bp := fetchReviewControls(ctx, svc, opts.Owner, opts.Repo, prBaseRef)
	if bp != nil {
		c.BranchProtection = bp
	}

	// step 2: reviews -> latest opinionated review per user.id.
	reviews, err := listReviews(ctx, svc, opts.Owner, opts.Repo, selected.GetNumber())
	if err != nil {
		// we have the PR but cannot read its reviews -> blind on the core evidence.
		c.ReviewToolingComplete = false
		return c, nil
	}
	latest := latestOpinionatedPerUser(reviews)

	// steps 3-6: classify each reviewer's latest opinionated state.
	var approvers []SourceReviewApprover
	changesRequested := 0
	selfApproved := false
	for _, r := range latest {
		uid := r.GetUser().GetID()
		state := strings.ToUpper(r.GetState())
		// step 3: a self-approval is never counted and never blocks.
		if uid == prAuthorID {
			if state == reviewStateApproved {
				selfApproved = true
			}
			continue
		}
		isBot := r.GetUser().GetType() == userTypeBot
		switch state {
		case reviewStateApproved:
			// step 4: staleness. When the branch does NOT dismiss stale reviews, an
			// approval on a commit other than the PR head is stale. NEVER compare
			// commit_id to the artifact's source revision — for squash/rebase merges
			// they always differ (false stale). Compare to the PR head SHA only. An
			// absent commit_id cannot be confirmed to be on the head, so it is treated
			// as stale (fail closed) rather than as a fresh approval.
			stale := !dismissStale && r.GetCommitID() != prHeadSHA
			approvers = append(approvers, SourceReviewApprover{
				Login:       truncateRunes(r.GetUser().GetLogin(), srMaxStringLen),
				Association: normalizeAssociation(r.GetAuthorAssociation()),
				SubmittedAt: formatTimestamp(r.GetSubmittedAt()),
				CommitID:    truncateRunes(r.GetCommitID(), srMaxSHALen),
				Stale:       stale,
				IsBot:       isBot,
			})
		case reviewStateChangesRequested:
			// GATE SEMANTICS (a): an outstanding CHANGES_REQUESTED blocks regardless
			// of approval count. Counted after the self/bot reduction; a later
			// DISMISSED clears it (handled by the latest-state reduction). Staleness
			// is intentionally NOT applied — a standing change request blocks even
			// after head movement (GitHub keeps it blocking until dismissed).
			if !isBot {
				changesRequested++
			}
		case reviewStateDismissed:
			// step 5: DISMISSED never counts and never resurrects an earlier APPROVED.
		}
	}

	// deterministic order for a reproducible signed artifact.
	sortApprovers(approvers)
	if len(approvers) > srMaxApprovers {
		approvers = approvers[:srMaxApprovers]
	}

	// step 7 / GATE SEMANTICS (b): the producer ALWAYS computes distinctApprovers
	// at the STRICTEST filtering (author, stale, dismissed, changes-requested, and
	// bot reviewers excluded). There are no producer-side loosening knobs; the
	// policy can only tighten this further, never loosen it.
	distinct := 0
	for _, a := range approvers {
		if !a.Stale && !a.IsBot {
			distinct++
		}
	}

	c.Summary = SourceReviewSummary{
		Approvals:            len(approvers),
		DistinctApprovers:    distinct,
		ChangesRequested:     changesRequested,
		RequiredApprovals:    requiredApprovals,
		RequirementMet:       distinct >= requiredApprovals,
		SelfApprovalExcluded: selfApproved,
		CodeownerReviewMet:   nil, // tri-state null in v0.1 (REST-only; no CODEOWNERS authority)
	}
	if opts.IncludeApprovers {
		if approvers == nil {
			approvers = []SourceReviewApprover{}
		}
		c.Approvers = approvers
	}

	return c, nil
}

// listPRsWithCommit paginates ListPullRequestsWithCommit for a SHA.
func listPRsWithCommit(ctx context.Context, svc ReviewService, owner, repo, sha string) ([]*gh.PullRequest, error) {
	const maxPages = 10
	opts := &gh.ListOptions{PerPage: 100}
	var all []*gh.PullRequest
	for attempt := 0; attempt < maxPages; attempt++ {
		prs, resp, err := svc.ListPullRequestsWithCommit(ctx, owner, repo, sha, opts)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list pull requests for commit %s: %w", sha, err)
		}
		all = append(all, prs...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		if attempt == maxPages-1 {
			return nil, fmt.Errorf("pull request pagination exceeded %d pages", maxPages)
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

// selectMergedPR picks the pull request whose merge produced the queried SHA.
// The merge_commit_sha == queried-SHA binding (plus a non-zero mergedAt) is
// MANDATORY on every path: it is what ties the captured reviews to the attested
// sourceRevision (works for merge, squash, and rebase merges). prNumber is only a
// disambiguator among PRs that already match — never an override, so a caller
// cannot bind a well-reviewed PR's approvals to an arbitrary/unreviewed commit.
func selectMergedPR(prs []*gh.PullRequest, sha string, prNumber int) *gh.PullRequest {
	for _, p := range prs {
		if p == nil {
			continue
		}
		if p.GetMergeCommitSHA() != sha || p.GetMergedAt().IsZero() {
			continue
		}
		if prNumber > 0 && p.GetNumber() != prNumber {
			continue
		}
		return p
	}
	return nil
}

// fetchReviewControls reads the review controls on the target branch from
// classic branch protection (needs admin) and rulesets (no admin), best-effort.
// Returns whether stale reviews are dismissed, the required approving-review
// count (max of both sources), and the discovered controls (nil when none).
func fetchReviewControls(ctx context.Context, svc ReviewService, owner, repo, branch string) (bool, int, *SourceReviewBranchProtection) {
	if branch == "" {
		return false, 0, nil
	}

	var bpCount, rsCount int
	dismissStale := false
	requireReviews := false
	requireCodeowner := false
	requireLastPush := false
	have := false

	prot, resp, err := svc.GetBranchProtection(ctx, owner, repo, branch)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil && prot != nil {
		if rpr := prot.GetRequiredPullRequestReviews(); rpr != nil {
			have = true
			requireReviews = true
			bpCount = rpr.RequiredApprovingReviewCount
			if rpr.DismissStaleReviews {
				dismissStale = true
			}
			if rpr.RequireCodeOwnerReviews {
				requireCodeowner = true
			}
			if rpr.RequireLastPushApproval {
				requireLastPush = true
			}
		}
	}

	rules, resp2, err2 := svc.ListRulesForBranch(ctx, owner, repo, branch, &gh.ListOptions{})
	if resp2 != nil {
		_ = resp2.Body.Close()
	}
	if err2 == nil && rules != nil {
		for _, r := range rules.PullRequest {
			if r == nil {
				continue
			}
			have = true
			requireReviews = true
			p := r.GetParameters()
			if p.RequiredApprovingReviewCount > rsCount {
				rsCount = p.RequiredApprovingReviewCount
			}
			if p.DismissStaleReviewsOnPush {
				dismissStale = true
			}
			if p.RequireCodeOwnerReview {
				requireCodeowner = true
			}
			if p.RequireLastPushApproval {
				requireLastPush = true
			}
		}
	}

	required := max(bpCount, rsCount)
	if !have {
		return dismissStale, required, nil
	}
	return dismissStale, required, &SourceReviewBranchProtection{
		RequireReviews:               requireReviews,
		RequiredApprovingReviewCount: required,
		DismissStaleReviews:          dismissStale,
		RequireCodeownerReview:       requireCodeowner,
		RequireLastPushApproval:      requireLastPush,
	}
}

// listReviews paginates ListReviews for a pull request.
func listReviews(ctx context.Context, svc ReviewService, owner, repo string, number int) ([]*gh.PullRequestReview, error) {
	const maxPages = 20
	opts := &gh.ListOptions{PerPage: 100}
	var all []*gh.PullRequestReview
	for attempt := 0; attempt < maxPages; attempt++ {
		revs, resp, err := svc.ListReviews(ctx, owner, repo, number, opts)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list reviews for PR #%d: %w", number, err)
		}
		all = append(all, revs...)
		if resp == nil || resp.NextPage == 0 {
			break
		}
		if attempt == maxPages-1 {
			return nil, fmt.Errorf("review pagination exceeded %d pages for PR #%d", maxPages, number)
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

// latestOpinionatedPerUser reduces reviews to the latest opinionated review
// (APPROVED, CHANGES_REQUESTED, or DISMISSED) per user.id. Grouping by id (not
// login) and taking the latest by submitted-at resolves a
// COMMENT->APPROVE->CHANGES_REQUESTED sequence to its final state.
func latestOpinionatedPerUser(reviews []*gh.PullRequestReview) map[int64]*gh.PullRequestReview {
	latest := map[int64]*gh.PullRequestReview{}
	for _, r := range reviews {
		if r == nil || r.GetUser() == nil {
			continue
		}
		if !isOpinionated(strings.ToUpper(r.GetState())) {
			continue
		}
		uid := r.GetUser().GetID()
		if cur, ok := latest[uid]; !ok || reviewLater(r, cur) {
			latest[uid] = r
		}
	}
	return latest
}

// isOpinionated reports whether a review state carries a verdict.
func isOpinionated(state string) bool {
	switch state {
	case reviewStateApproved, reviewStateChangesRequested, reviewStateDismissed:
		return true
	default:
		return false
	}
}

// reviewLater reports whether a is more recent than b (submitted-at, then id).
func reviewLater(a, b *gh.PullRequestReview) bool {
	at, bt := a.GetSubmittedAt().Time, b.GetSubmittedAt().Time
	if at.Equal(bt) {
		return a.GetID() > b.GetID()
	}
	return at.After(bt)
}

// sortApprovers orders approvers deterministically (login, submittedAt, commitId).
func sortApprovers(approvers []SourceReviewApprover) {
	sort.SliceStable(approvers, func(i, j int) bool {
		a, b := approvers[i], approvers[j]
		if a.Login != b.Login {
			return a.Login < b.Login
		}
		if a.SubmittedAt != b.SubmittedAt {
			return a.SubmittedAt < b.SubmittedAt
		}
		return a.CommitID < b.CommitID
	})
}

// formatTimestamp renders a GitHub timestamp as bounded UTC RFC3339, or "".
func formatTimestamp(ts gh.Timestamp) string {
	if ts.IsZero() {
		return ""
	}
	return truncateRunes(ts.UTC().Format(time.RFC3339), srMaxTimestampLen)
}

// normalizeRef strips a refs/heads/ prefix so the predicate ref is a branch name.
func normalizeRef(ref string) string {
	return strings.TrimPrefix(ref, "refs/heads/")
}

// normalizeAssociation constrains the untrusted author_association to the known
// GitHub enum (mirrors code-scan's normalizeLevel). An unrecognized or absent
// value yields "" so the field is omitted rather than failing schema validation
// if GitHub ever returns a new value. Evidence only — never gated in v0.1.
func normalizeAssociation(s string) string {
	switch strings.ToUpper(s) {
	case "OWNER", "MEMBER", "COLLABORATOR", "CONTRIBUTOR",
		"FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "MANNEQUIN", "NONE":
		return strings.ToUpper(s)
	default:
		return ""
	}
}

// Generate produces the JSON representation of the source-review predicate.
func (c *SourceReview) Generate() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// GenerateSourceReview generates and validates a source-review attestation
// predicate, fetching review evidence from the GitHub API.
func GenerateSourceReview(opts SourceReviewOptions, outputFile string) error {
	client, err := ghclient.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create GitHub client: %w", err)
	}

	c, err := NewSourceReview(context.Background(), NewGitHubReviewService(client), opts)
	if err != nil {
		return err
	}

	output, err := c.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate predicate: %w", err)
	}

	if err := ValidateSourceReview(output); err != nil {
		return fmt.Errorf("failed to validate source-review: %w", err)
	}

	return writeOutput(output, outputFile)
}
