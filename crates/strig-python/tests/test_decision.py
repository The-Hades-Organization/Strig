import pytest

import strig
from conftest import DOC, HOUR, NOW, P1, P2, SPEC, ask, allow, code_of, user


def test_allow_and_default_deny(engine):
    ctx = strig.Context([allow("g")])
    ana = user("ana")
    assert engine.check(ctx, ask(ana, "project.view", P1)) is True
    assert engine.check(ctx, ask(ana, "project.edit", P1)) is False
    decision = engine.decide(ctx, ask(ana, "project.view", P1))
    assert decision["effect"] == "allow"
    assert decision["matched"] == ["g"]
    assert decision["reason"]["grantId"] == "g"


def test_explain_carries_the_trace(engine):
    ctx = strig.Context([allow("g")])
    trace = engine.explain(ctx, ask(user("ana"), "project.view", P1))
    assert trace["decision"]["effect"] == "allow"
    assert trace["effective"] == ["project.view"]
    assert trace["grants"][0]["grant"]["id"] == "g"


def test_check_many_and_explain_many_keep_order(engine):
    ctx = strig.Context([allow("g")])
    ana = user("ana")
    requests = [ask(ana, "project.view", P1), ask(ana, "project.edit", P1), ask(ana, "project.view", P2)]
    assert engine.check_many(ctx, requests) == [True, False, True]
    traces = engine.explain_many(ctx, requests)
    assert [t["decision"]["effect"] for t in traces] == ["allow", "deny", "allow"]


def test_context_incremental_changes():
    ctx = strig.Context()
    assert len(ctx) == 0 and ctx.size == 0
    ctx.add_grant(allow("a"))
    ctx.add_grant(allow("b", "project.edit"))
    assert ctx.size == 2
    assert [g["id"] for g in ctx.grants()] == ["a", "b"]
    assert ctx.remove_grant("a") is True
    assert ctx.remove_grant("a") is False
    ctx.set_grants([allow("c")])
    assert [g["id"] for g in ctx.grants()] == ["c"]
    ctx.set_env({"dept": "eng"})
    with pytest.raises(strig.StrigError) as bad:
        ctx.add_tuple({"nope": 1})
    assert code_of(bad) == "INVALID_INPUT"


def test_validity_window_needs_an_instant_and_fails_closed(engine):
    window = allow("w", validFrom=NOW + HOUR)
    ctx = strig.Context([window])
    request = ask(user("ana"), "project.view", P1)
    assert engine.check(ctx, request) is False, "no instant: a windowed allow is ignored"
    ctx.set_now(NOW)
    assert engine.check(ctx, request) is False
    assert engine.check(ctx, request, now=NOW + HOUR) is True, "now= of the call wins"
    ctx.set_now(NOW + HOUR)
    assert engine.check(ctx, request) is True
    ctx.set_now(None)
    assert engine.check(ctx, request) is False
    assert strig.Context([window], now=NOW + HOUR).size == 1


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1, 0.5, "0", "", [], False, True])
def test_bad_now_is_invalid_argument(engine, bad):
    ctx = strig.Context([allow("g")])
    request = ask(user("ana"), "project.view", P1)
    with pytest.raises(strig.StrigError) as e:
        engine.check(ctx, request, now=bad)
    assert code_of(e) == "INVALID_ARGUMENT"
    with pytest.raises(strig.StrigError) as e:
        ctx.set_now(bad)
    assert code_of(e) == "INVALID_ARGUMENT"
    with pytest.raises(strig.StrigError) as e:
        strig.Context(now=bad)
    assert code_of(e) == "INVALID_ARGUMENT"


def test_non_json_argument_is_invalid_argument(engine):
    ctx = strig.Context()
    for value in (object(), {1, 2}, {1: "x"}, lambda: 0, 2**80):
        with pytest.raises(strig.StrigError) as e:
            engine.check(ctx, value)
        assert code_of(e) == "INVALID_ARGUMENT"


def test_malformed_request_and_spec_have_stable_codes(engine):
    ctx = strig.Context()
    with pytest.raises(strig.StrigError) as e:
        engine.check(ctx, {"permission": "project.view"})
    assert code_of(e) == "INVALID_INPUT"
    with pytest.raises(strig.StrigError) as e:
        strig.Engine({"catalog": "nope"})
    assert code_of(e) == "INVALID_INPUT"
    assert isinstance(e.value, Exception) and e.value.message


def test_deny_wins_and_unknown_permission_denies(engine):
    ctx = strig.Context([allow("a"), allow("d", effect="deny")])
    assert engine.check(ctx, ask(user("ana"), "project.view", P1)) is False
    assert engine.check(strig.Context([allow("a")]), ask(user("ana"), "ghost.perm", P1)) is False


def test_list_who_can_and_access_of(engine):
    ctx = strig.Context([allow("g", subject={"kind": "user", "id": "ana"})])
    listed = engine.list(ctx, user("ana"), "project.view", "project")
    assert listed["kind"] == "project" and listed["permission"] == "project.view"
    assert listed["exact"] is True
    with_ids = engine.list(
        ctx, user("ana"), "project.view", "project", {"resources": [P1, P2]}
    )
    assert with_ids["ids"] is not None
    assert engine.who_can(ctx, "project.view") == [{"type": "user", "id": "ana"}]
    on = engine.who_can_on(ctx, "project.view", P1)
    assert [e["subject"] for e in on["entries"]] == [{"type": "user", "id": "ana"}]
    access = engine.access_of(ctx, P1)
    assert access[0]["permissions"] == ["project.view"]
    checked = engine.check_for(ctx, {"type": "user", "id": "ana"}, "project.view", P1, [user("ana")])
    assert checked["decision"]["effect"] == "allow"
    with pytest.raises(strig.StrigError) as e:
        engine.check_for(ctx, {"type": "user", "id": "ghost"}, "project.view", P1, [])
    assert code_of(e) == "UNKNOWN_SUBJECT"


def test_capabilities_round_trip(engine):
    ctx = strig.Context([allow("g")])
    caps = engine.capabilities(ctx, user("ana"), P1)
    assert [g["id"] for g in caps["grants"]] == ["g"]
    other = strig.Context()
    assert other.load_capabilities(caps) == {"id": "ana", "kind": "user"}
    assert other.size == 1


def test_validate_grant_and_catalog(engine):
    engine.validate_grant(allow("g"))
    with pytest.raises(strig.StrigError):
        engine.validate_grant({"id": "x"})
    assert engine.catalog()["permissions"][0]["key"] == "project.view"


def test_exclusive_lease_preemption_and_expiry():
    spec = {
        **SPEC,
        "roles": [],
    }
    engine = strig.Engine(spec)
    grants = [
        allow("h", "exclusive.hold", target={"kind": "document"}),
        allow("p", "exclusive.preempt", subject={"kind": "user", "id": "chief"}, target={"kind": "document"}),
    ]
    ctx = strig.Context(grants)
    lock = strig.Exclusive({"maxTtlMs": 10 * HOUR})
    lock.validate(engine)
    first = lock.acquire(engine, ctx, user("low"), DOC, {"priority": 1, "ttlMs": HOUR}, NOW)
    assert first["outcome"] == "granted"
    assert first["lease"]["holder"]["id"] == "low"
    assert lock.holder({"kind": "document", "id": "d1"}, NOW)["holder"]["id"] == "low"
    taken = lock.acquire(engine, ctx, user("peer"), DOC, {"priority": 1, "ttlMs": HOUR}, NOW + 1)
    assert taken["outcome"] != "granted"
    renewed = lock.renew(engine, ctx, user("low"), DOC, 2 * HOUR, NOW + 2)
    assert renewed["expiresAt"] == NOW + 2 + 2 * HOUR
    assert lock.expire(NOW + 10 * HOUR)[0]["holder"]["id"] == "low"
    assert lock.holder({"kind": "document", "id": "d1"}, NOW + 10 * HOUR) is None
    with pytest.raises(strig.StrigError) as e:
        strig.Exclusive().validate(strig.Engine({"catalog": {"targetKinds": ["project"], "permissions": []}}))
    assert code_of(e) == "EXCLUSIVE_UNKNOWN_PERMISSION"


def test_why_not_suggests_verified_changes_and_names_the_cause(engine):
    role_grant = allow("r", subject={"kind": "role", "id": "viewer"})
    ctx = strig.Context([role_grant])
    answer = engine.why_not(ctx, ask(user("ana"), "project.view", P1))
    assert answer["cause"] == {"kind": "no_applicable_grant"}
    assert [r["kind"] for r in answer["remedies"]] == ["add_grant", "add_grant", "assign_role"]
    assert answer["remedies"][2]["role"] == "viewer"
    assert "partial" not in answer


def test_why_not_is_none_when_allowed_and_honours_options(engine):
    ctx = strig.Context([allow("g")])
    assert engine.why_not(ctx, ask(user("ana"), "project.view", P1)) is None
    denied = engine.why_not(ctx, ask(user("ana"), "project.edit", P1), options={"maxRemedies": 1})
    assert len(denied["remedies"]) == 1 and denied["partial"] is True
    with pytest.raises(strig.StrigError) as error:
        engine.why_not(ctx, ask(user("ana"), "project.edit", P1), options={"bogus": 1})
    assert code_of(error) == "INVALID_INPUT"
