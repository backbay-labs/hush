import pytest

from hushspec.conditions import (
    Condition,
    RuntimeContext,
    TimeWindowCondition,
    evaluate_condition,
    evaluate_with_context,
)
from hushspec.evaluate import Decision, EvaluationAction
from hushspec.rules import DefaultAction, EgressRule, ToolAccessRule, Rules
from hushspec.schema import HushSpec



# Helpers



def ctx_with_env(env: str) -> RuntimeContext:
    return RuntimeContext(environment=env)


def ctx_with_time(time: str) -> RuntimeContext:
    return RuntimeContext(current_time=time)


def ctx_with_user_role(role: str) -> RuntimeContext:
    return RuntimeContext(user={"role": role})


def make_egress_spec() -> HushSpec:
    return HushSpec(
        hushspec="0.1.0",
        name="conditional-test",
        rules=Rules(
            egress=EgressRule(
                enabled=True,
                allow=["api.openai.com"],
                default=DefaultAction.BLOCK,
            )
        ),
    )


def make_tool_access_spec() -> HushSpec:
    return HushSpec(
        hushspec="0.1.0",
        name="conditional-tool-test",
        rules=Rules(
            tool_access=ToolAccessRule(
                enabled=True,
                allow=["deploy"],
                block=["danger_tool"],
                default=DefaultAction.BLOCK,
            )
        ),
    )



# Context conditions



class TestContextConditions:
    def test_matches_environment(self):
        cond = Condition(context={"environment": "production"})
        assert evaluate_condition(cond, ctx_with_env("production")) is True

    def test_rejects_mismatch(self):
        cond = Condition(context={"environment": "production"})
        assert evaluate_condition(cond, ctx_with_env("staging")) is False

    def test_missing_field_fails_closed(self):
        cond = Condition(context={"user.role": "admin"})
        assert evaluate_condition(cond, RuntimeContext()) is False

    def test_matches_user_role(self):
        cond = Condition(context={"user.role": "admin"})
        assert evaluate_condition(cond, ctx_with_user_role("admin")) is True
        assert evaluate_condition(cond, ctx_with_user_role("viewer")) is False

    def test_array_or_match(self):
        cond = Condition(context={"environment": ["production", "staging"]})
        assert evaluate_condition(cond, ctx_with_env("production")) is True
        assert evaluate_condition(cond, ctx_with_env("staging")) is True
        assert evaluate_condition(cond, ctx_with_env("development")) is False

    def test_scalar_vs_array_membership(self):
        ctx = RuntimeContext(user={"groups": ["engineering", "ml-team"]})
        cond = Condition(context={"user.groups": "ml-team"})
        assert evaluate_condition(cond, ctx) is True



# S1 parity: array-vs-array intersection and number/bool array membership
#
# Rust's `matches_scalar_or_membership`/`match_value` (crates/hushspec/src/
# evaluate.rs) is the cross-SDK reference: expected-array vs actual-array
# matches iff the sets intersect, and expected-array vs actual-scalar matches
# for any scalar type (string/number/bool), not just strings.


class TestArrayMembershipParity:
    def test_array_vs_array_matches_on_intersection(self):
        ctx = RuntimeContext(user={"groups": ["engineering", "ml-team"]})
        cond = Condition(context={"user.groups": ["ml-team", "sales"]})
        assert evaluate_condition(cond, ctx) is True

    def test_array_vs_array_no_intersection_fails(self):
        ctx = RuntimeContext(user={"groups": ["engineering", "ml-team"]})
        cond = Condition(context={"user.groups": ["sales", "support"]})
        assert evaluate_condition(cond, ctx) is False

    def test_array_vs_array_single_shared_element_matches(self):
        ctx = RuntimeContext(user={"groups": ["a", "b", "c"]})
        cond = Condition(context={"user.groups": ["c", "d", "e"]})
        assert evaluate_condition(cond, ctx) is True

    def test_expected_array_matches_actual_number_scalar(self):
        ctx = RuntimeContext(session={"action_count": 2})
        cond = Condition(context={"session.action_count": [1, 2, 3]})
        assert evaluate_condition(cond, ctx) is True
        ctx_miss = RuntimeContext(session={"action_count": 99})
        assert evaluate_condition(cond, ctx_miss) is False

    def test_expected_array_matches_actual_bool_scalar(self):
        ctx = RuntimeContext(request={"interactive": True})
        cond = Condition(context={"request.interactive": [False, True]})
        assert evaluate_condition(cond, ctx) is True
        ctx_miss = RuntimeContext(request={"interactive": False})
        cond_true_only = Condition(context={"request.interactive": [True]})
        assert evaluate_condition(cond_true_only, ctx_miss) is False

    def test_actual_array_matches_expected_number_scalar(self):
        ctx = RuntimeContext(session={"tags": [1, 2, 3]})
        cond = Condition(context={"session.tags": 2})
        assert evaluate_condition(cond, ctx) is True

    def test_actual_array_matches_expected_bool_scalar(self):
        ctx = RuntimeContext(agent={"flags": [False, True]})
        cond = Condition(context={"agent.flags": True})
        assert evaluate_condition(cond, ctx) is True

    def test_bool_is_not_numeric_expected_number_actual_bool(self):
        # bool must never spuriously match a numeric expected, even though
        # bool is a subclass of int in Python.
        ctx = RuntimeContext(user={"flag": True})
        cond = Condition(context={"user.flag": 1})
        assert evaluate_condition(cond, ctx) is False

    def test_bool_is_not_numeric_expected_bool_actual_number(self):
        ctx = RuntimeContext(user={"flag": 1})
        cond = Condition(context={"user.flag": True})
        assert evaluate_condition(cond, ctx) is False



# Time window conditions



class TestTimeWindowConditions:
    def test_matches_during_business_hours(self):
        ctx = ctx_with_time("2026-01-14T10:30:00Z")
        cond = Condition(
            time_window=TimeWindowCondition(
                start="09:00", end="17:00", timezone="UTC"
            )
        )
        assert evaluate_condition(cond, ctx) is True

    def test_rejects_outside_hours(self):
        ctx = ctx_with_time("2026-01-14T20:00:00Z")
        cond = Condition(
            time_window=TimeWindowCondition(
                start="09:00", end="17:00", timezone="UTC"
            )
        )
        assert evaluate_condition(cond, ctx) is False

    def test_day_filter(self):
        # 2026-01-14 is a Wednesday
        ctx = ctx_with_time("2026-01-14T10:00:00Z")

        cond_weekday = Condition(
            time_window=TimeWindowCondition(
                start="09:00",
                end="17:00",
                timezone="UTC",
                days=["mon", "tue", "wed", "thu", "fri"],
            )
        )
        assert evaluate_condition(cond_weekday, ctx) is True

        cond_weekend = Condition(
            time_window=TimeWindowCondition(
                start="09:00",
                end="17:00",
                timezone="UTC",
                days=["sat", "sun"],
            )
        )
        assert evaluate_condition(cond_weekend, ctx) is False

    def test_wraps_midnight(self):
        cond = Condition(
            time_window=TimeWindowCondition(
                start="22:00", end="06:00", timezone="UTC"
            )
        )
        assert evaluate_condition(cond, ctx_with_time("2026-01-14T23:00:00Z")) is True
        assert evaluate_condition(cond, ctx_with_time("2026-01-14T03:00:00Z")) is True
        assert evaluate_condition(cond, ctx_with_time("2026-01-14T10:00:00Z")) is False

    def test_same_start_end_means_all_day(self):
        cond = Condition(
            time_window=TimeWindowCondition(
                start="12:00", end="12:00", timezone="UTC"
            )
        )
        assert evaluate_condition(cond, ctx_with_time("2026-01-14T03:00:00Z")) is True

    def test_supports_minute_offsets(self):
        cond = Condition(
            time_window=TimeWindowCondition(
                start="05:30", end="06:30", timezone="+05:30"
            )
        )
        assert evaluate_condition(cond, ctx_with_time("2026-01-14T00:15:00Z")) is True
        assert evaluate_condition(cond, ctx_with_time("2026-01-14T01:15:00Z")) is False

    def test_uses_dst_for_iana_timezones(self):
        cond = Condition(
            time_window=TimeWindowCondition(
                start="08:30", end="09:30", timezone="America/New_York"
            )
        )
        assert evaluate_condition(cond, ctx_with_time("2026-01-14T13:45:00Z")) is True
        assert evaluate_condition(cond, ctx_with_time("2026-07-14T12:45:00Z")) is True

    def test_wraps_midnight_with_day_filter(self):
        cond = Condition(
            time_window=TimeWindowCondition(
                start="22:00", end="06:00", timezone="UTC", days=["fri"]
            )
        )
        assert evaluate_condition(cond, ctx_with_time("2026-01-17T03:00:00Z")) is True

    def test_invalid_timezone_fails_closed(self):
        cond = Condition(
            time_window=TimeWindowCondition(
                start="09:00", end="17:00", timezone="America/NeYork"
            )
        )
        assert evaluate_condition(cond, ctx_with_time("2026-01-14T13:30:00Z")) is False



# Compound conditions



class TestCompoundConditions:
    def test_all_of_requires_all(self):
        cond = Condition(
            all_of=[
                Condition(context={"environment": "production"}),
                Condition(context={"user.role": "admin"}),
            ]
        )

        full_ctx = RuntimeContext(environment="production", user={"role": "admin"})
        assert evaluate_condition(cond, full_ctx) is True

        # Only environment matches
        assert evaluate_condition(cond, ctx_with_env("production")) is False

    def test_any_of_requires_any(self):
        cond = Condition(
            any_of=[
                Condition(context={"environment": "production"}),
                Condition(context={"environment": "staging"}),
            ]
        )

        assert evaluate_condition(cond, ctx_with_env("production")) is True
        assert evaluate_condition(cond, ctx_with_env("staging")) is True
        assert evaluate_condition(cond, ctx_with_env("development")) is False

    def test_empty_any_of_is_treated_as_unset(self):
        cond = Condition(any_of=[])

        assert evaluate_condition(cond, ctx_with_env("development")) is True

    def test_not_negates(self):
        cond = Condition(not_=Condition(context={"environment": "production"}))

        assert evaluate_condition(cond, ctx_with_env("production")) is False
        assert evaluate_condition(cond, ctx_with_env("staging")) is True

    def test_nested_compound(self):
        # Business hours AND production AND (admin OR sre)
        cond = Condition(
            all_of=[
                Condition(
                    time_window=TimeWindowCondition(
                        start="09:00", end="17:00", timezone="UTC"
                    )
                ),
                Condition(context={"environment": "production"}),
                Condition(
                    any_of=[
                        Condition(context={"user.role": "admin"}),
                        Condition(context={"user.role": "sre"}),
                    ]
                ),
            ]
        )

        ctx = RuntimeContext(
            environment="production",
            current_time="2026-01-14T10:00:00Z",
            user={"role": "admin"},
        )
        assert evaluate_condition(cond, ctx) is True

        ctx_viewer = RuntimeContext(
            environment="production",
            current_time="2026-01-14T10:00:00Z",
            user={"role": "viewer"},
        )
        assert evaluate_condition(cond, ctx_viewer) is False


class TestEdgeCases:
    def test_empty_condition_always_true(self):
        assert evaluate_condition(Condition(), RuntimeContext()) is True

    def test_max_nesting_depth_exceeded(self):
        cond = Condition(context={"environment": "production"})
        for _ in range(12):
            cond = Condition(all_of=[cond])
        assert evaluate_condition(cond, ctx_with_env("production")) is False



# evaluate_with_context



class TestEvaluateWithContext:
    def test_passes_when_condition_met(self):
        spec = make_egress_spec()
        action = EvaluationAction(type="egress", target="api.openai.com")
        ctx = RuntimeContext(environment="production")
        conditions = {"egress": Condition(context={"environment": "production"})}

        result = evaluate_with_context(spec, action, ctx, conditions)
        assert result.decision == Decision.ALLOW

    def test_skips_rule_when_condition_fails(self):
        spec = make_egress_spec()
        action = EvaluationAction(type="egress", target="evil.example.com")
        ctx = RuntimeContext(environment="staging")
        conditions = {"egress": Condition(context={"environment": "production"})}

        # Rule disabled, so allow
        result = evaluate_with_context(spec, action, ctx, conditions)
        assert result.decision == Decision.ALLOW

    def test_enforces_rule_when_condition_met(self):
        spec = make_egress_spec()
        action = EvaluationAction(type="egress", target="evil.example.com")
        ctx = RuntimeContext(environment="production")
        conditions = {"egress": Condition(context={"environment": "production"})}

        result = evaluate_with_context(spec, action, ctx, conditions)
        assert result.decision == Decision.DENY

    def test_no_conditions_behaves_like_evaluate(self):
        spec = make_egress_spec()
        action = EvaluationAction(type="egress", target="evil.example.com")
        ctx = RuntimeContext()
        conditions: dict[str, Condition] = {}

        result = evaluate_with_context(spec, action, ctx, conditions)
        assert result.decision == Decision.DENY

    def test_tool_access_with_time_window(self):
        spec = make_tool_access_spec()
        action = EvaluationAction(type="tool_call", target="deploy")
        conditions = {
            "tool_access": Condition(
                time_window=TimeWindowCondition(
                    start="09:00", end="17:00", timezone="UTC"
                )
            )
        }

        # Inside business hours
        ctx_inside = RuntimeContext(current_time="2026-01-14T10:00:00Z")
        result_inside = evaluate_with_context(spec, action, ctx_inside, conditions)
        assert result_inside.decision == Decision.ALLOW

        # Outside business hours, rule disabled
        ctx_outside = RuntimeContext(current_time="2026-01-14T20:00:00Z")
        result_outside = evaluate_with_context(spec, action, ctx_outside, conditions)
        assert result_outside.decision == Decision.ALLOW

    def test_missing_context_fails_closed(self):
        spec = make_egress_spec()
        action = EvaluationAction(type="egress", target="api.openai.com")
        ctx = RuntimeContext()
        conditions = {"egress": Condition(context={"environment": "production"})}

        # Condition fails, rule disabled, allow
        result = evaluate_with_context(spec, action, ctx, conditions)
        assert result.decision == Decision.ALLOW

    def test_compound_condition(self):
        spec = make_egress_spec()
        action = EvaluationAction(type="egress", target="evil.example.com")
        conditions = {
            "egress": Condition(
                all_of=[
                    Condition(context={"environment": "production"}),
                    Condition(context={"user.role": "admin"}),
                ]
            )
        }

        # Both conditions met
        full_ctx = RuntimeContext(environment="production", user={"role": "admin"})
        result = evaluate_with_context(spec, action, full_ctx, conditions)
        assert result.decision == Decision.DENY

        # Only env matches
        partial_ctx = RuntimeContext(environment="production")
        result2 = evaluate_with_context(spec, action, partial_ctx, conditions)
        assert result2.decision == Decision.ALLOW
