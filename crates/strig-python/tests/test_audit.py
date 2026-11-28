import pytest

import strig
from conftest import NOW, SPEC, allow, code_of, user

ACTOR = user("root", attrs={"email": "root@example.com"})


def request(ident, audit=None, **extra):
    return {
        "actor": ACTOR,
        "current": [],
        "mutation": {"add": allow(ident, extra.pop("permission", "project.view"))},
        "audit": audit or {"level": "forensic"},
        "now": NOW,
        **extra,
    }


def failing_sink(state, taken):
    def sink(record):
        if state["down"]:
            raise OSError("log fora do ar")
        taken.append(record)

    return sink


def test_without_a_sink_the_record_is_returned_and_written():
    out = strig.Engine(SPEC).apply(request("g1"))
    assert out["ok"] is True
    assert out["auditStatus"] == "written"
    assert isinstance(out["audit"]["hash"], str)


def test_sink_that_raises_refuses_in_closed_and_proceeds_in_open_then_flushes():
    state, taken = {"down": True}, []
    engine = strig.Engine(SPEC, audit_sink=failing_sink(state, taken))

    refused = engine.apply(request("g1"))
    assert refused["ok"] is False
    assert refused["violations"][0]["invariant"] == "audit"
    assert "log fora do ar" in refused["violations"][0]["message"]
    assert engine.audit_stats()["pending"] == 0

    first = engine.apply(request("g1", {"level": "forensic", "failMode": "open"}))
    assert first["ok"] is True and first["auditStatus"] == "pending"
    assert engine.audit_stats()["pending"] == 1 and taken == []
    second = engine.apply(request("g2", {"level": "forensic", "failMode": "open", "prevHash": first["audit"]["hash"]}))
    assert second["auditStatus"] == "pending"

    state["down"] = False
    stats = engine.flush_audit()
    assert stats["pending"] == 0 and stats["writtenLate"] == 2
    assert [r["object"] for r in taken] == ["g1", "g2"]
    assert taken[1]["prev_hash"] == taken[0]["hash"]


def test_fail_mode_precedence_call_then_permission_then_default():
    def down(record):
        raise OSError("fora")

    engine = strig.Engine(
        SPEC,
        audit_sink=down,
        audit_policy={"failMode": "closed", "permissions": {"project.edit": "open"}},
    )

    def run(permission, mode=None):
        audit = {"level": "standard"}
        if mode:
            audit["failMode"] = mode
        return engine.apply(request("g", audit, permission=permission))["ok"]

    assert run("project.view") is False
    assert run("project.edit") is True
    assert run("project.edit", "closed") is False
    assert run("project.view", "open") is True


def test_full_retry_queue_drops_warns_and_the_written_chain_verifies():
    state, taken, dropped = {"down": True}, [], []
    engine = strig.Engine(
        SPEC,
        audit_sink=failing_sink(state, taken),
        on_audit_drop=dropped.append,
        audit_policy={"failMode": "open", "capacity": 1, "baseDelayMs": 0},
    )
    prev, statuses = None, []
    for ident in ("g1", "g2", "g3"):
        audit = {"level": "forensic"}
        if prev:
            audit["prevHash"] = prev
        out = engine.apply(request(ident, audit))
        statuses.append(out["auditStatus"])
        if out["auditStatus"] != "dropped":
            prev = out["audit"]["hash"]
    assert statuses == ["pending", "dropped", "dropped"]
    assert len(dropped) == 2 and engine.audit_stats()["dropped"] == 2
    state["down"] = False
    engine.flush_audit()
    assert len(taken) == 1
    assert strig.verify_audit_chain(taken) == {"ok": True, "head": taken[0]["hash"]}


def test_redaction_masks_before_writing_and_before_the_hash():
    taken = []
    engine = strig.Engine(
        SPEC,
        audit_sink=taken.append,
        audit_redact=lambda record: {**record, "object": "redigido:" + str(record["object"])},
    )
    out = engine.apply(
        request(
            "g1",
            {"level": "forensic", "redact": {"keys": ["email", "ip"], "mask": "***"}},
            meta={"ip": "203.0.113.42", "reason": "x"},
        )
    )
    assert out["ok"] is True
    record = taken[0]
    assert record["object"] == "redigido:g1"
    assert record["meta"]["ip"] == "***" and record["meta"]["reason"] == "x"
    assert record["actor_detail"]["attrs"]["email"] == "***"
    assert "203.0.113.42" not in str(taken) and "root@example.com" not in str(taken)
    assert strig.verify_audit_chain(taken)["ok"] is True

    def vault_down(record):
        raise PermissionError("sem acesso ao cofre")

    broken = strig.Engine(
        SPEC, audit_sink=lambda record: None, audit_redact=vault_down, audit_policy={"failMode": "open"}
    ).apply(request("g1"))
    assert broken["ok"] is False, "a failing redaction refuses even in open"
    assert "sem acesso ao cofre" in broken["violations"][0]["message"]


def test_verify_audit_chain_with_anchors():
    records = []
    engine = strig.Engine(SPEC, audit_sink=records.append)
    prev = None
    for ident in ("g1", "g2", "g3"):
        audit = {"level": "forensic"}
        if prev:
            audit["prevHash"] = prev
        prev = engine.apply(request(ident, audit))["audit"]["hash"]
    head = records[2]["hash"]
    assert strig.verify_audit_chain(records, {"head": head}) == {"ok": True, "head": head}
    cut = strig.verify_audit_chain(records[:2], {"head": head})
    assert cut["ok"] is False and cut["code"] == "HEAD_MISMATCH"
    assert strig.verify_audit_chain(records[1:], {"start": records[0]["hash"], "head": head})["ok"] is True
    assert strig.verify_audit_chain(records[1:], {"start": "aa"})["code"] == "ANCHOR_MISMATCH"
    edited = [{**r, "object": "x"} if i == 1 else r for i, r in enumerate(records)]
    tampered = strig.verify_audit_chain(edited)
    assert tampered["code"] == "TAMPERED" and tampered["index"] == 1
    assert isinstance(strig.audit_estimate("forensic", 3), float)


def test_sink_cannot_reenter_the_engine():
    seen = {}

    def sink(record):
        try:
            engine.apply(request("inner"))
        except strig.StrigError as error:
            seen["code"] = error.code

    engine = strig.Engine(SPEC, audit_sink=sink)
    assert engine.apply(request("g1"))["ok"] is True
    assert seen["code"] == "REENTRANT_CALL"


def test_audit_policy_must_be_well_formed():
    with pytest.raises(strig.StrigError) as e:
        strig.Engine(SPEC, audit_policy={"failMode": "sometimes"})
    assert code_of(e) == "INVALID_INPUT"


def test_propose_without_an_approval_policy_applies_at_once():
    engine = strig.Engine(SPEC)
    out = engine.propose({**request("g1", {"level": "standard"}), "id": "r1"})
    assert out["ok"] is True
