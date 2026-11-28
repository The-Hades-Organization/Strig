import pytest

import strig

NOW = 1_700_000_000_000
HOUR = 3_600_000

SPEC = {
    "catalog": {
        "targetKinds": ["project", "document"],
        "broadTargets": ["org"],
        "permissions": [
            {"key": "project.view", "targets": ["project"]},
            {"key": "project.edit", "targets": ["project"]},
            {"key": "exclusive.hold", "targets": ["document"]},
            {"key": "exclusive.preempt", "targets": ["document"]},
        ],
    },
}

P1 = strig.scope_from_string("project:p1/org:o1")
P2 = strig.scope_from_string("project:p2/org:o1")
DOC = strig.scope_from_string("document:d1/project:p1/org:o1")


def user(ident, **extra):
    return {"kind": "user", "id": ident, **extra}


def allow(ident, permission="project.view", subject=None, target=None, **extra):
    return {
        "id": ident,
        "subject": subject or {"kind": "any"},
        "permission": permission,
        "target": target or {"kind": "project"},
        "effect": "allow",
        **extra,
    }


def ask(subject, permission, resource):
    return {"subject": subject, "permission": permission, "resource": resource}


def code_of(excinfo):
    return excinfo.value.code


@pytest.fixture
def spec():
    return SPEC


@pytest.fixture
def engine():
    return strig.Engine(SPEC)
