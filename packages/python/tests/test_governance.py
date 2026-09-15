"""Governance metadata parity (core spec 2.5).

Every warning and error asserted here is produced verbatim by every SDK --
the wording is the contract, not an implementation detail.
"""

from __future__ import annotations

from dataclasses import dataclass

from hushspec import parse, validate


RULES = 'rules:\n  egress:\n    allow: ["api.example.com"]\n    default: block\n'


@dataclass
class Checked:
    valid: bool
    warnings: list[str]
    messages: str


def check(metadata: str) -> Checked:
    """A document is rejected either at parse (structural problems the raw pass
    catches) or by ``validate``; both paths collapse into one result here."""
    ok, result = parse(f'hushspec: "0.2.0"\nname: governed\nmetadata:\n{metadata}{RULES}')
    if not ok:
        return Checked(valid=False, warnings=[], messages=str(result))
    validation = validate(result)
    return Checked(
        valid=validation.is_valid,
        warnings=list(validation.warnings),
        messages="\n".join(error.message for error in validation.errors),
    )


class TestSeparationOfDuties:
    def test_author_equal_to_approver_warns(self):
        result = check(
            '  author: "security@example.com"\n'
            '  approved_by: "  Security@Example.com "\n'
            '  approval_date: "2024-03-15"\n'
        )
        assert result.valid
        assert (
            "author and approved_by are the same identity 'security@example.com': "
            "separation of duties requires a different approver" in result.warnings
        )

    def test_distinct_approver_does_not_warn(self):
        result = check(
            '  author: "security@example.com"\n'
            '  approved_by: "ciso@example.com"\n'
            '  approval_date: "2024-03-15"\n'
        )
        assert result.warnings == []


class TestLifecycleAndReview:
    def test_approved_without_approver_warns(self):
        result = check("  lifecycle_state: approved\n")
        assert "lifecycle_state is 'approved' but no approved_by is set" in result.warnings

    def test_overdue_review_warns(self):
        result = check('  next_review_date: "2020-01-01"\n')
        assert "policy next_review_date '2020-01-01' is in the past" in result.warnings

    def test_future_review_does_not_warn(self):
        assert check('  next_review_date: "2099-01-01"\n').warnings == []


class TestChangelog:
    def test_ascending_changelog_warns(self):
        result = check(
            "  changelog:\n"
            '    - version: "1"\n      date: "2024-01-01"\n      summary: "first"\n'
            '    - version: "2"\n      date: "2024-07-01"\n      summary: "second"\n'
        )
        assert (
            "changelog entries are not in descending version/date order at entry 1"
            in result.warnings
        )

    def test_descending_changelog_is_clean(self):
        result = check(
            "  changelog:\n"
            '    - version: "2"\n      date: "2024-07-01"\n      summary: "second"\n'
            '    - version: "1"\n      date: "2024-01-01"\n      summary: "first"\n'
        )
        assert result.valid
        assert result.warnings == []

    def test_unknown_key_in_entry_is_rejected(self):
        result = check(
            "  changelog:\n"
            '    - version: "1"\n      date: "2024-01-01"\n'
            '      summary: "first"\n      reason: "nope"\n'
        )
        assert not result.valid

    def test_missing_required_entry_fields_are_rejected(self):
        result = check('  changelog:\n    - version: "1"\n')
        assert not result.valid
        assert "metadata.changelog[0].date is required" in result.messages


class TestDates:
    def test_impossible_dates_are_rejected(self):
        for value in ("2026-13-45", "2023-02-29", "2024-1-01", "01/02/2026"):
            result = check(f'  expiry_date: "{value}"\n')
            assert not result.valid, value
            assert "is not an ISO 8601 date" in result.messages

    def test_leap_day_in_a_leap_year_is_accepted(self):
        assert check('  expiry_date: "2024-02-29"\n').valid


class TestLineage:
    def test_superseding_own_version_is_rejected(self):
        result = check('  policy_version: 4\n  supersedes: "4"\n')
        assert not result.valid
        assert "metadata.supersedes '4' is the policy's own policy_version" in result.messages

    def test_superseding_the_previous_version_is_accepted(self):
        assert check('  policy_version: 4\n  supersedes: "3"\n').valid

    def test_owner_and_reviewers_are_accepted(self):
        result = check(
            '  owner: "platform-security@example.com"\n'
            '  reviewers:\n    - "appsec@example.com"\n'
        )
        assert result.valid
