import pytest

import strig
from strig import dsl

BLOCKS = "language blocks\n\ntarget_kinds = [org]\n\npermission org.read {\n  targets = [org]\n}\n"


def test_compile_then_print_round_trips_and_builds_an_engine():
    policy = dsl.compile(BLOCKS)
    assert policy["catalog"]["permissions"] == [{"key": "org.read", "targets": ["org"]}]
    assert dsl.print(policy, "blocks") == BLOCKS
    engine = strig.Engine(policy)
    assert engine.catalog()["permissions"][0]["key"] == "org.read"


def test_convert_format_and_is_formatted():
    rules = dsl.convert(BLOCKS, "rules")
    assert rules.startswith("language rules")
    assert dsl.compile(rules) == dsl.compile(BLOCKS)
    assert dsl.is_formatted(BLOCKS) is True
    assert dsl.format(BLOCKS) == BLOCKS
    assert dsl.is_formatted("language blocks\n\n\n\ntarget_kinds = [org]\n\npermission org.read { targets = [org] }\n") is False


def test_syntax_error_is_dsl_parse_with_position():
    with pytest.raises(strig.DslError) as e:
        dsl.compile("language blocks\n\npermission {", file="a.strig")
    assert e.value.code == "DSL_PARSE"
    first = e.value.diagnostics[0]
    assert first["file"] == "a.strig" and first["line"] >= 1
    assert isinstance(e.value, strig.StrigError)


def test_invalid_policy_is_validate_and_bad_arguments_are_invalid_argument():
    with pytest.raises(strig.DslError) as e:
        dsl.compile("language blocks\n\npermission org.read {\n  targets = [org]\n}\n")
    assert e.value.code == "DSL_VALIDATE"
    with pytest.raises(strig.DslError) as e:
        dsl.convert(BLOCKS, "yaml")
    assert e.value.code == "INVALID_ARGUMENT"
    with pytest.raises(strig.DslError) as e:
        dsl.compile(1)  # type: ignore[arg-type]
    assert e.value.code == "INVALID_ARGUMENT"


def test_load_project_merges_sources_and_reports_conflicts():
    a = "language blocks\n\ntarget_kinds = [org]\n\npermission org.read {\n  targets = [org]\n}\n"
    b = "language blocks\n\npermission org.write {\n  targets = [org]\n}\n"
    merged = dsl.load_project([{"path": "a.strig", "text": a}, {"path": "b.strig", "text": b}])
    assert [p["key"] for p in merged["catalog"]["permissions"]] == ["org.read", "org.write"]
    with pytest.raises(strig.DslError) as e:
        dsl.load_project([{"path": "a.strig", "text": a}, {"path": "b.strig", "text": a}])
    assert e.value.code == "DSL_CONFLICT"
    assert any(isinstance(d.get("related"), dict) for d in e.value.diagnostics)
    with pytest.raises(strig.DslError) as e:
        dsl.load_project([{"path": "a.strig", "text": a}, {"path": "a.strig", "text": b}])
    assert e.value.code == "DSL_DUPLICATE_SOURCE"


def test_load_project_dir_reads_files_and_reports_io(tmp_path):
    (tmp_path / "a.strig").write_text(BLOCKS)
    assert dsl.load_project_dir(str(tmp_path)) == dsl.compile(BLOCKS)
    with pytest.raises(strig.DslError) as e:
        dsl.load_project_dir(str(tmp_path / "missing"))
    assert e.value.code == "DSL_IO"
