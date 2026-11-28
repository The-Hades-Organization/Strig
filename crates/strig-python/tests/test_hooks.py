import pytest

import strig
from conftest import NOW, P1, SPEC, allow, ask, code_of, user

ANA = user("ana", attrs={"dept": "eng"})
VIEW = ask(ANA, "project.view", P1)


def call_grant(func, args=(), **extra):
    return allow("c", condition={"op": "call", "func": func, "args": list(args)}, **extra)


def test_call_condition_function_decides_and_a_raise_does_not_grant():
    seen = []

    def same(args):
        seen.append(args)
        if args[0] == "boom":
            raise ValueError("falhou")
        return args[0] == args[1]

    engine = strig.Engine(SPEC, conditions={"same": same, "not_bool": lambda args: "sim"})

    def ctx(func, args):
        return strig.Context([call_grant(func, args)])

    assert engine.check(ctx("same", ["eng", "eng"]), VIEW) is True
    assert engine.check(ctx("same", ["eng", "ops"]), VIEW) is False
    assert seen[0] == ["eng", "eng"]
    attrs = strig.Context([call_grant("same", [{"attr": "subject.dept"}, "eng"])])
    assert engine.check(attrs, VIEW) is True, "operands arrive resolved"

    thrown = ctx("same", ["boom", "x"])
    assert engine.check(thrown, VIEW) is False
    assert "falhou" in str(engine.explain(thrown, VIEW))
    assert engine.check(ctx("not_bool", []), VIEW) is False

    deny = strig.Context([allow("a"), {**call_grant("same", ["boom", "x"]), "id": "d", "effect": "deny"}])
    assert engine.check(deny, VIEW) is False, "a deny whose condition errors still denies"


def test_override_shows_in_trace_respects_except_and_a_raise_denies():
    requests = []

    def evaluate(request):
        requests.append(request)
        who = request["subject"]["id"]
        if who == "root":
            return "allowed"
        if who == "banned":
            return "denied"
        if who == "bad":
            raise RuntimeError("indisponível")
        return None

    engine = strig.Engine(SPEC, overrides=[{"name": "frozen", "except": ["project.edit"], "evaluate": evaluate}])
    empty = strig.Context()

    def as_(who, permission="project.view"):
        return ask(user(who), permission, P1)

    assert engine.check(empty, as_("root")) is True
    assert engine.check(empty, as_("banned")) is False
    assert engine.check(empty, as_("bad")) is False
    assert engine.check(strig.Context([allow("g")]), as_("plain")) is True, "abstaining leaves it to the grants"
    assert engine.check(empty, as_("root", "project.edit")) is False, "except: not even consulted"
    assert engine.decide(empty, as_("banned"))["reason"] == {"kind": "override", "name": "frozen"}
    assert engine.explain(empty, as_("root"))["overrides"] == [{"name": "frozen", "outcome": "allowed"}]
    assert engine.explain(empty, as_("root", "project.edit"))["overrides"][0]["outcome"] == "excepted"
    assert requests[0]["permission"] == "project.view"


def test_wrong_override_answer_denies():
    engine = strig.Engine(SPEC, overrides=[{"name": "odd", "evaluate": lambda request: "maybe"}])
    assert engine.check(strig.Context([allow("g")]), VIEW) is False


def governance_input(mutation, names, current=None):
    return {
        "actor": user("root"),
        "current": [allow("r", subject={"kind": "role", "id": "editor"})] if current is None else current,
        "mutation": mutation,
        "invariants": [{"kind": "custom", "name": n} for n in names],
        "audit": {"level": "forensic"},
        "now": NOW,
    }


def test_custom_invariant_refuses_suggests_and_audits():
    rank = {"viewer": 1, "editor": 2, "owner": 3}
    in_use = {"editor"}

    def env_role_within_global(proposal):
        mutation = proposal["mutation"]
        if "assign_role" not in mutation:
            return None
        subject, role = mutation["assign_role"]["subject"], mutation["assign_role"]["role"]
        if (role.get("scope") or {}).get("kind") != "environment":
            return None
        top = max([0] + [rank.get(r["role"], 0) for r in subject.get("roles", []) if not r.get("scope")])
        if rank.get(role["role"], 0) <= top:
            return None
        return {
            "message": f"o papel {role['role']} no ambiente excede o global ({top})",
            "suggestion": {"assign_role": {"subject": subject, "role": {"role": "viewer", "scope": role["scope"]}}},
        }

    def role_in_use(proposal):
        mutation = proposal["mutation"]
        if "remove" not in mutation:
            return None
        grant = next((g for g in proposal["before"] if g["id"] == mutation["remove"]["id"]), None)
        if grant and grant["subject"]["kind"] == "role" and grant["subject"]["id"] in in_use:
            return f"o papel {grant['subject']['id']} está em uso"
        return None

    def boom(proposal):
        raise RuntimeError("cadastro fora do ar")

    engine = strig.Engine(
        SPEC,
        invariants={"env_role_within_global": env_role_within_global, "role_in_use": role_in_use, "boom": boom},
    )
    zed = user("zed", roles=[{"role": "viewer"}])
    env = {"kind": "environment", "id": "prod"}

    over = engine.apply(
        governance_input({"assign_role": {"subject": zed, "role": {"role": "owner", "scope": env}}}, ["env_role_within_global"])
    )
    assert over["ok"] is False
    assert over["violations"][0]["invariant"] == "env_role_within_global"
    assert "excede o global" in over["violations"][0]["message"]
    assert over["audit"]["outcome"] == "rejected"
    assert over["violations"][0]["suggestion"] == {
        "kind": "assign_role",
        "subjectId": "zed",
        "role": {"role": "viewer", "scope": env},
    }
    within = engine.apply(
        governance_input({"assign_role": {"subject": zed, "role": {"role": "viewer", "scope": env}}}, ["env_role_within_global"])
    )
    assert within["ok"] is True

    used = engine.apply(governance_input({"remove": {"id": "r"}}, ["role_in_use"]))
    assert used["ok"] is False and used["violations"][0]["message"] == "o papel editor está em uso"
    in_use.discard("editor")
    assert engine.apply(governance_input({"remove": {"id": "r"}}, ["role_in_use"]))["ok"] is True

    thrown = engine.apply(governance_input({"remove": {"id": "r"}}, ["boom"]))
    assert thrown["ok"] is False
    assert thrown["violations"][0]["invariant"] == "boom"
    assert "cadastro fora do ar" in thrown["violations"][0]["message"]

    with pytest.raises(strig.StrigError) as e:
        engine.apply(governance_input({"remove": {"id": "r"}}, ["nao_existe"]))
    assert code_of(e) == "UNKNOWN_INVARIANT"


def test_declarative_invariant_and_plain_apply():
    engine = strig.Engine(SPEC)
    done = engine.apply({"actor": user("root"), "current": [], "mutation": {"add": allow("g1")}, "audit": {"level": "standard"}, "now": NOW})
    assert done["ok"] is True
    assert [g["id"] for g in done["grants"]] == ["g1"]


def test_callbacks_cannot_reenter_the_engine_or_change_a_context():
    ctx = strig.Context([call_grant("probe")])
    other = strig.Context()
    outcomes = []
    state = {"in_use": "passed"}

    def probe(args):
        attempts = [lambda: engine.check(ctx, VIEW), lambda: other.add_grant(allow("x")), lambda: other.set_now(1)]
        for attempt in attempts:
            try:
                attempt()
                outcomes.append("passed")
            except strig.StrigError as error:
                outcomes.append(error.code)
        try:
            ctx.add_grant(allow("y"))
        except Exception:
            state["in_use"] = "refused"
        return True

    engine = strig.Engine(SPEC, conditions={"probe": probe})
    assert engine.check(ctx, VIEW) is True
    assert outcomes == ["REENTRANT_CALL"] * 3
    assert other.size == 0
    assert state["in_use"] == "refused"
    assert ctx.size == 1
    ctx.add_grant(allow("later"))
    assert ctx.size == 2
    assert engine.check(ctx, VIEW) is True


def test_malformed_hooks_are_invalid_argument():
    for kwargs in (
        {"conditions": {"x": "nope"}},
        {"conditions": "nope"},
        {"overrides": [{"name": "x"}]},
        {"overrides": [{"evaluate": lambda r: None}]},
        {"overrides": ["nope"]},
        {"invariants": {"x": 3}},
        {"audit_sink": "nope"},
    ):
        with pytest.raises(strig.StrigError) as e:
            strig.Engine(SPEC, **kwargs)
        assert code_of(e) == "INVALID_ARGUMENT", kwargs
    strig.Engine(SPEC, conditions=None)
    strig.Engine(SPEC)
