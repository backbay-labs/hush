import pytest

from hushspec import parse, parse_or_raise, validate
from hushspec.conditions import (
    MAX_NESTING_DEPTH,
    Condition,
    RateComparison,
    RateCondition,
    RuntimeContext,
    TimeWindowCondition,
    evaluate_condition,
    evaluate_condition_with_capabilities,
    evaluate_with_context,
    is_capability_identifier,
    timezone_is_known,
    validate_condition,
)
from hushspec.evaluate import Decision, EvaluationAction, evaluate
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

    def test_numbers_compare_exactly(self):
        cond = Condition(context={"custom.ratio": 0.3})
        assert evaluate_condition(cond, RuntimeContext(custom={"ratio": 0.3})) is True
        assert (
            evaluate_condition(
                cond, RuntimeContext(custom={"ratio": 0.30000000000000004})
            )
            is False
        )



# Array-vs-array intersection and number/bool array membership (core spec
# 3.13): an expected array matches an actual array iff the two sets intersect,
# and an expected array matches an actual scalar for any scalar type
# (string/number/bool), not just strings.


class TestArrayMembership:
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

    def test_loads_iana_zones_from_the_tz_database(self):
        # Neither zone is in the hardcoded fixed-offset fallback table, so these
        # assertions only pass if zoneinfo can reach a tz database. That is what
        # the `tzdata` runtime dependency guarantees on Windows and on slim
        # images that ship no /usr/share/zoneinfo -- without it the lookup
        # raises ZoneInfoNotFoundError and the condition fails closed.
        new_york = Condition(
            time_window=TimeWindowCondition(
                start="09:00", end="10:00", timezone="America/New_York"
            )
        )
        # 09:30 in New York, winter (UTC-5) and summer (UTC-4).
        assert evaluate_condition(new_york, ctx_with_time("2026-01-14T14:30:00Z")) is True
        assert evaluate_condition(new_york, ctx_with_time("2026-07-14T13:30:00Z")) is True
        assert evaluate_condition(new_york, ctx_with_time("2026-01-14T09:30:00Z")) is False

        kolkata = Condition(
            time_window=TimeWindowCondition(
                start="09:00", end="10:00", timezone="Asia/Kolkata"
            )
        )
        # 09:30 in Kolkata (UTC+5:30 year-round).
        assert evaluate_condition(kolkata, ctx_with_time("2026-01-14T04:00:00Z")) is True
        assert evaluate_condition(kolkata, ctx_with_time("2026-01-14T09:30:00Z")) is False

    def test_wraps_midnight_with_day_filter(self):
        cond = Condition(
            time_window=TimeWindowCondition(
                start="22:00", end="06:00", timezone="UTC", days=["fri"]
            )
        )
        assert evaluate_condition(cond, ctx_with_time("2026-01-17T03:00:00Z")) is True

    def test_invalid_timezone_keeps_block_active(self):
        # Core spec 3.13: an unresolvable time zone cannot be evaluated, and
        # an unevaluable condition MUST NOT switch a security control off, so
        # the window is treated as satisfied. Validation rejects the zone at
        # parse time.
        cond = Condition(
            time_window=TimeWindowCondition(
                start="09:00", end="17:00", timezone="America/NeYork"
            )
        )
        assert evaluate_condition(cond, ctx_with_time("2026-01-14T13:30:00Z")) is True
        errors = validate_condition(cond, "rules.x.when")
        assert len(errors) == 1, errors
        assert "timezone" in errors[0]



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
        # Core spec 3.13: validation rejects the document; if such a condition
        # still reaches evaluation (out-of-band map) it cannot be evaluated,
        # and an unevaluable condition leaves the block active.
        cond = Condition(context={"environment": "production"})
        for _ in range(12):
            cond = Condition(all_of=[cond])
        assert evaluate_condition(cond, ctx_with_env("production")) is True
        assert validate_condition(cond, "rules.x.when") != []



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


# Core spec 3.13: `when` is a document field, decoded and validated at parse
# and validate time.


class TestConditionDecoding:
    def test_decodes_every_condition_form(self):
        cond = Condition.from_dict(
            {
                "time_window": {
                    "start": "09:00",
                    "end": "17:00",
                    "timezone": "UTC",
                    "days": ["mon"],
                },
                "context": {"environment": "production"},
                "all_of": [{"context": {"user.role": "admin"}}],
                "any_of": [{"context": {"agent.type": "batch"}}],
                "not": {"context": {"environment": "staging"}},
            }
        )
        assert cond.time_window is not None
        assert cond.time_window.days == ["mon"]
        assert cond.all_of is not None and len(cond.all_of) == 1
        assert cond.any_of is not None and len(cond.any_of) == 1
        assert cond.not_ is not None

    def test_rejects_unknown_condition_key(self):
        with pytest.raises(ValueError, match="unknown field `weekday_only`"):
            Condition.from_dict({"weekday_only": True})

    def test_rejects_unknown_time_window_key(self):
        with pytest.raises(ValueError, match="unknown field `tz`"):
            Condition.from_dict({"time_window": {"start": "09:00", "end": "17:00", "tz": "UTC"}})

    def test_round_trips_through_to_dict(self):
        raw = {
            "time_window": {"start": "09:00", "end": "17:00"},
            "not": {"context": {"environment": "staging"}},
        }
        assert Condition.from_dict(raw).to_dict() == raw


class TestValidateCondition:
    def test_accepts_a_well_formed_condition(self):
        cond = Condition.from_dict(
            {
                "time_window": {
                    "start": "22:00",
                    "end": "06:00",
                    "timezone": "America/New_York",
                    "days": ["mon", "fri"],
                }
            }
        )
        assert validate_condition(cond, "rules.egress.when") == []

    def test_reports_each_violation(self):
        cond = Condition.from_dict(
            {
                "time_window": {
                    "start": "25:00",
                    "end": "17:60",
                    "timezone": "+05:30",
                    "days": ["Mon", "funday"],
                }
            }
        )
        errors = validate_condition(cond, "rules.shell_commands.when")
        assert len(errors) == 3, errors
        assert any("time_window.start" in e for e in errors)
        assert any("time_window.end" in e for e in errors)
        assert any("funday" in e for e in errors)

    def test_rejects_an_unknown_timezone(self):
        cond = Condition.from_dict(
            {"time_window": {"start": "09:00", "end": "17:00", "timezone": "Mars/Olympus_Mons"}}
        )
        errors = validate_condition(cond, "rules.egress.when")
        assert len(errors) == 1, errors
        assert "timezone" in errors[0]

    def test_rejects_nesting_past_the_depth_cap(self):
        deep = Condition(context={})
        for _ in range(MAX_NESTING_DEPTH + 1):
            deep = Condition(not_=deep)
        errors = validate_condition(deep, "rules.egress.when")
        assert len(errors) == 1, errors
        assert "nest deeper" in errors[0]

        ok = Condition(context={})
        for _ in range(MAX_NESTING_DEPTH):
            ok = Condition(not_=ok)
        assert validate_condition(ok, "rules.egress.when") == []


class TestTimezoneIsKnown:
    def test_accepts_iana_names_aliases_and_fixed_offsets(self):
        assert timezone_is_known("UTC") is True
        assert timezone_is_known("America/New_York") is True
        assert timezone_is_known("+05:30") is True
        assert timezone_is_known("-08:00") is True
        assert timezone_is_known("JST") is True

    def test_rejects_unknown_zones(self):
        assert timezone_is_known("Mars/Olympus_Mons") is False
        assert timezone_is_known("America/NeYork") is False


class TestDocumentWhenValidation:
    def test_document_condition_gates_its_block(self):
        spec = parse_or_raise(
            'hushspec: "0.2.0"\n'
            "rules:\n"
            "  shell_commands:\n"
            "    when:\n"
            "      context:\n"
            "        environment: production\n"
            '    forbidden_patterns: ["mkfs"]\n'
        )
        assert validate(spec).is_valid
        action = EvaluationAction(type="shell_command", target="mkfs /dev/sda")
        active = evaluate(
            spec,
            EvaluationAction(
                type="shell_command",
                target="mkfs /dev/sda",
                context=RuntimeContext(environment="production"),
            ),
        )
        assert active.decision == Decision.DENY
        inert = evaluate(
            spec,
            EvaluationAction(
                type="shell_command",
                target="mkfs /dev/sda",
                context=RuntimeContext(environment="staging"),
            ),
        )
        assert inert.decision == Decision.ALLOW
        # No context at all: the context predicate is unsatisfied, so the block
        # is inert (a missing field is false, not unevaluable).
        assert evaluate(spec, action).decision == Decision.ALLOW

    def test_unknown_condition_key_is_a_parse_error(self):
        ok, err = parse(
            'hushspec: "0.2.0"\n'
            "rules:\n"
            "  shell_commands:\n"
            "    when:\n"
            "      weekday_only: true\n"
            '    forbidden_patterns: ["mkfs"]\n'
        )
        assert ok is False
        assert "unknown field `weekday_only`" in err

    def test_bad_time_window_is_a_validation_error(self):
        spec = parse_or_raise(
            'hushspec: "0.2.0"\n'
            "rules:\n"
            "  shell_commands:\n"
            "    when:\n"
            "      time_window:\n"
            '        start: "25:00"\n'
            '        end: "06:00"\n'
            '    forbidden_patterns: ["mkfs"]\n'
        )
        result = validate(spec)
        assert not result.is_valid
        assert "rules.shell_commands.when.time_window.start" in str(result.errors[0])


# The `capability` and `rate` leaf predicates (core spec 3.13)


class TestCapabilityPredicate:
    """`capability` reads the effective posture state, and holds without one."""

    CONDITION = Condition(capability="shell")

    def test_holds_when_the_policy_has_no_posture_extension(self):
        # Unevaluable, and an unevaluable condition must never switch a
        # security control off: the block stays active.
        assert evaluate_condition_with_capabilities(
            self.CONDITION, RuntimeContext(), None
        )
        assert evaluate_condition(self.CONDITION, RuntimeContext())

    def test_true_when_the_effective_state_grants_it(self):
        assert evaluate_condition_with_capabilities(
            self.CONDITION, RuntimeContext(), ["tool_call", "shell"]
        )

    def test_false_when_the_effective_state_does_not_grant_it(self):
        assert not evaluate_condition_with_capabilities(
            self.CONDITION, RuntimeContext(), ["tool_call"]
        )

    def test_an_unknown_state_grants_nothing(self):
        # A resolved-but-unknown posture state is an empty grant list, not an
        # absent one, so the predicate is false rather than unevaluable.
        assert not evaluate_condition_with_capabilities(
            self.CONDITION, RuntimeContext(), []
        )

    def test_it_is_a_leaf_inside_all_of_and_not(self):
        nested = Condition(
            all_of=[Condition(not_=Condition(capability="shell"))]
        )
        assert not evaluate_condition_with_capabilities(
            nested, RuntimeContext(), ["shell"]
        )
        assert evaluate_condition_with_capabilities(nested, RuntimeContext(), [])


class TestRatePredicate:
    """`rate` compares an engine-supplied counter; an absent counter holds."""

    GTE = Condition(
        rate=RateCondition(
            counter="shell_commands", threshold=5, comparison=RateComparison.GTE
        )
    )
    LT = Condition(
        rate=RateCondition(
            counter="egress_calls", threshold=100, comparison=RateComparison.LT
        )
    )

    @pytest.mark.parametrize(
        ("count", "expected"), [(4, False), (5, True), (6, True)]
    )
    def test_gte_compares_at_the_threshold(self, count, expected):
        context = RuntimeContext(counters={"shell_commands": count})
        assert evaluate_condition(self.GTE, context) is expected

    @pytest.mark.parametrize(
        ("count", "expected"), [(99, True), (100, False), (101, False)]
    )
    def test_lt_compares_at_the_threshold(self, count, expected):
        context = RuntimeContext(counters={"egress_calls": count})
        assert evaluate_condition(self.LT, context) is expected

    def test_an_absent_counter_is_unevaluable_and_holds(self):
        assert evaluate_condition(self.GTE, RuntimeContext())
        assert evaluate_condition(
            self.GTE, RuntimeContext(counters={"egress_calls": 1})
        )

    def test_counters_decode_from_a_runtime_context_mapping(self):
        context = RuntimeContext.from_dict({"counters": {"shell_commands": 7}})
        assert context.counters == {"shell_commands": 7}
        assert evaluate_condition(self.GTE, context)

    def test_a_counter_that_is_not_a_whole_number_is_dropped(self):
        context = RuntimeContext.from_dict(
            {
                "counters": {
                    "shell_commands": True,
                    "egress_calls": "3",
                    "tool_calls": 2.5,
                    "file_writes": 4.0,
                }
            }
        )
        assert context.counters == {"file_writes": 4}
        # A dropped counter is absent, so the predicate reading it is
        # unevaluable and the block stays active.
        assert evaluate_condition(self.GTE, context)


class TestRateDecoding:
    """Rate shape violations are parse errors (core spec 3.13, code E001)."""

    def test_round_trips_through_to_dict(self):
        raw = {
            "rate": {
                "counter": "tool_calls",
                "threshold": 0,
                "comparison": "lt",
            }
        }
        assert Condition.from_dict(raw).to_dict() == raw

    def test_capability_round_trips_through_to_dict(self):
        assert Condition.from_dict({"capability": "shell"}).to_dict() == {
            "capability": "shell"
        }

    @pytest.mark.parametrize("missing", ["counter", "threshold", "comparison"])
    def test_every_member_is_required(self, missing):
        raw = {"counter": "a", "threshold": 1, "comparison": "gte"}
        del raw[missing]
        with pytest.raises(ValueError, match=f"missing field `{missing}`"):
            Condition.from_dict({"rate": raw})

    def test_an_unknown_comparison_is_rejected(self):
        with pytest.raises(ValueError, match="unknown variant `between`"):
            Condition.from_dict(
                {"rate": {"counter": "a", "threshold": 1, "comparison": "between"}}
            )

    @pytest.mark.parametrize("threshold", [-1, "3", True, 1.5])
    def test_a_threshold_that_is_not_a_non_negative_integer_is_rejected(
        self, threshold
    ):
        with pytest.raises(ValueError, match="invalid type"):
            Condition.from_dict(
                {"rate": {"counter": "a", "threshold": threshold, "comparison": "gte"}}
            )

    def test_an_unknown_rate_member_is_rejected(self):
        with pytest.raises(ValueError, match="unknown field `window`"):
            Condition.from_dict(
                {
                    "rate": {
                        "counter": "a",
                        "threshold": 1,
                        "comparison": "gte",
                        "window": "1m",
                    }
                }
            )


class TestIdentifierGrammar:
    """`segment(.segment)*`, `segment = [a-z][a-z0-9_]*` (core spec 3.13)."""

    @pytest.mark.parametrize(
        "name", ["shell", "a", "tool_call", "a.b", "net.egress.http2", "x_1.y_2"]
    )
    def test_accepts(self, name):
        assert is_capability_identifier(name)

    @pytest.mark.parametrize(
        "name",
        [
            "",
            ".",
            "a.",
            ".a",
            "a..b",
            "Shell",
            "Shell-Access",
            "9lives",
            "_leading",
            "has space",
            "a.B",
        ],
    )
    def test_rejects(self, name):
        assert not is_capability_identifier(name)

    def test_a_bad_capability_name_is_a_constraint_violation(self):
        errors = validate_condition(
            Condition(capability="Shell-Access"), "rules.tool_access.when"
        )
        assert len(errors) == 1
        assert "is not a capability identifier" in errors[0]

    def test_a_bad_counter_name_is_a_constraint_violation(self):
        errors = validate_condition(
            Condition(
                rate=RateCondition(
                    counter="9lives", threshold=1, comparison=RateComparison.GTE
                )
            ),
            "rules.shell_commands.when",
        )
        assert len(errors) == 1
        assert "is not a counter identifier" in errors[0]

    def test_leaf_predicates_do_not_add_nesting(self):
        # `capability` and `rate` are leaves: a condition at the depth cap
        # carrying one is still accepted (core spec 3.13).
        condition = Condition(capability="shell")
        for _ in range(MAX_NESTING_DEPTH):
            condition = Condition(not_=condition)
        assert validate_condition(condition, "rules.tool_access.when") == []


class TestConditionsAgainstThePostureState:
    """End to end: the block's `when` sees the state the posture guard uses."""

    POLICY = (
        'hushspec: "0.2.0"\n'
        "rules:\n"
        "  tool_access:\n"
        "    when:\n"
        "      capability: shell\n"
        "    block: [deploy]\n"
        "    default: allow\n"
        "extensions:\n"
        "  posture:\n"
        "    initial: standard\n"
        "    states:\n"
        "      standard:\n"
        "        capabilities: [tool_call, shell]\n"
        "      restricted:\n"
        "        capabilities: [tool_call]\n"
        "    transitions: []\n"
    )

    def _decide(self, current):
        from hushspec.evaluate import PostureContext

        spec = parse_or_raise(self.POLICY)
        return evaluate(
            spec,
            EvaluationAction(
                type="tool_call",
                target="deploy",
                posture=PostureContext(current=current),
            ),
        ).decision

    def test_a_granting_state_leaves_the_block_active(self):
        assert self._decide("standard") == Decision.DENY

    def test_a_non_granting_state_makes_the_block_inert(self):
        assert self._decide("restricted") == Decision.ALLOW


class TestTimezoneOffsetStrictness:
    """A fixed ``+HH:MM`` offset is ASCII digits and nothing else.

    A zone the engine cannot resolve leaves the rule block active (core spec
    3.13). Accepting an offset another engine refuses would resolve the zone
    here, evaluate the window, and let it switch the block off.
    """

    def test_a_plain_offset_resolves(self):
        assert timezone_is_known("+09:30")
        assert timezone_is_known("-05:00")

    def test_an_offset_with_inner_whitespace_is_unknown(self):
        assert not timezone_is_known("+ 9")
        assert not timezone_is_known("+09: 30")

    def test_an_offset_with_an_underscore_separator_is_unknown(self):
        assert not timezone_is_known("+1_2")

    def test_a_non_ascii_digit_offset_is_unknown(self):
        assert not timezone_is_known("+\u0661\u0662")
        assert not timezone_is_known("+\uff10\uff19")

    def test_an_out_of_range_offset_is_unknown(self):
        assert not timezone_is_known("+24:00")
        assert not timezone_is_known("+09:60")
