package hushspec

import (
	"strings"
	"testing"
)

// Governance metadata parity (core spec 2.5). Every warning and error asserted
// here is produced verbatim by the Rust, TypeScript and Python validators too
// -- the wording is the contract, not an implementation detail.

const governanceRules = "rules:\n  egress:\n    allow: [\"api.example.com\"]\n    default: block\n"

type governanceResult struct {
	valid    bool
	warnings []string
	messages string
}

// checkGovernance rejects a document either at parse (structural problems the
// raw pass catches) or in Validate; both paths collapse into one result.
func checkGovernance(t *testing.T, metadata string) governanceResult {
	t.Helper()
	spec, err := Parse("hushspec: \"0.2.0\"\nname: governed\nmetadata:\n" + metadata + governanceRules)
	if err != nil {
		return governanceResult{valid: false, messages: err.Error()}
	}
	result := Validate(spec)
	messages := make([]string, 0, len(result.Errors))
	for _, e := range result.Errors {
		messages = append(messages, e.Message)
	}
	return governanceResult{
		valid:    result.IsValid(),
		warnings: result.Warnings,
		messages: strings.Join(messages, "\n"),
	}
}

func hasWarning(result governanceResult, want string) bool {
	for _, w := range result.warnings {
		if w == want {
			return true
		}
	}
	return false
}

func TestGovernanceSeparationOfDuties(t *testing.T) {
	result := checkGovernance(t, "  author: \"security@example.com\"\n  approved_by: \"  Security@Example.com \"\n  approval_date: \"2024-03-15\"\n")
	if !result.valid {
		t.Fatalf("expected a valid document, got errors: %s", result.messages)
	}
	want := "author and approved_by are the same identity 'security@example.com': separation of duties requires a different approver"
	if !hasWarning(result, want) {
		t.Fatalf("missing SoD warning, got %v", result.warnings)
	}
}

func TestGovernanceDistinctApproverIsClean(t *testing.T) {
	result := checkGovernance(t, "  author: \"security@example.com\"\n  approved_by: \"ciso@example.com\"\n  approval_date: \"2024-03-15\"\n")
	if len(result.warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", result.warnings)
	}
}

func TestGovernanceApprovedStateNeedsAnApprover(t *testing.T) {
	result := checkGovernance(t, "  lifecycle_state: approved\n")
	if !hasWarning(result, "lifecycle_state is 'approved' but no approved_by is set") {
		t.Fatalf("missing unapproved-state warning, got %v", result.warnings)
	}
}

func TestGovernanceOverdueReview(t *testing.T) {
	result := checkGovernance(t, "  next_review_date: \"2020-01-01\"\n")
	if !hasWarning(result, "policy next_review_date '2020-01-01' is in the past") {
		t.Fatalf("missing overdue-review warning, got %v", result.warnings)
	}

	future := checkGovernance(t, "  next_review_date: \"2099-01-01\"\n")
	if len(future.warnings) != 0 {
		t.Fatalf("a future review date should be clean, got %v", future.warnings)
	}
}

func TestGovernanceChangelogOrder(t *testing.T) {
	ascending := checkGovernance(t, "  changelog:\n"+
		"    - version: \"1\"\n      date: \"2024-01-01\"\n      summary: \"first\"\n"+
		"    - version: \"2\"\n      date: \"2024-07-01\"\n      summary: \"second\"\n")
	if !hasWarning(ascending, "changelog entries are not in descending version/date order at entry 1") {
		t.Fatalf("missing changelog-order warning, got %v", ascending.warnings)
	}

	descending := checkGovernance(t, "  changelog:\n"+
		"    - version: \"2\"\n      date: \"2024-07-01\"\n      summary: \"second\"\n"+
		"    - version: \"1\"\n      date: \"2024-01-01\"\n      summary: \"first\"\n")
	if !descending.valid || len(descending.warnings) != 0 {
		t.Fatalf("a newest-first changelog should be clean, got %v / %s", descending.warnings, descending.messages)
	}
}

func TestGovernanceChangelogStructure(t *testing.T) {
	unknown := checkGovernance(t, "  changelog:\n    - version: \"1\"\n      date: \"2024-01-01\"\n      summary: \"first\"\n      reason: \"nope\"\n")
	if unknown.valid {
		t.Fatal("an unknown key inside a changelog entry must be rejected")
	}

	incomplete := checkGovernance(t, "  changelog:\n    - version: \"1\"\n")
	if incomplete.valid {
		t.Fatal("a changelog entry without date/summary must be rejected")
	}
	if !strings.Contains(incomplete.messages, "metadata.changelog[0]: missing field `date`") {
		t.Fatalf("expected the missing-date message, got %s", incomplete.messages)
	}
}

func TestGovernanceDateFormat(t *testing.T) {
	for _, value := range []string{"2026-13-45", "2023-02-29", "2024-1-01", "01/02/2026"} {
		result := checkGovernance(t, "  expiry_date: \""+value+"\"\n")
		if result.valid {
			t.Fatalf("%q must be rejected as a date", value)
		}
		if !strings.Contains(result.messages, "is not an ISO 8601 date") {
			t.Fatalf("%q: expected an ISO 8601 date error, got %s", value, result.messages)
		}
	}

	leap := checkGovernance(t, "  expiry_date: \"2024-02-29\"\n")
	if !leap.valid {
		t.Fatalf("a leap day in a leap year must be accepted, got %s", leap.messages)
	}
}

func TestGovernanceSupersedes(t *testing.T) {
	self := checkGovernance(t, "  policy_version: 4\n  supersedes: \"4\"\n")
	if self.valid {
		t.Fatal("a policy must not supersede its own version")
	}
	if !strings.Contains(self.messages, "metadata.supersedes '4' is the policy's own policy_version") {
		t.Fatalf("unexpected message: %s", self.messages)
	}

	previous := checkGovernance(t, "  policy_version: 4\n  supersedes: \"3\"\n")
	if !previous.valid {
		t.Fatalf("superseding the previous version must be accepted, got %s", previous.messages)
	}
}

func TestGovernanceOwnerAndReviewers(t *testing.T) {
	result := checkGovernance(t, "  owner: \"platform-security@example.com\"\n  reviewers:\n    - \"appsec@example.com\"\n")
	if !result.valid {
		t.Fatalf("owner and reviewers must be accepted, got %s", result.messages)
	}
}
