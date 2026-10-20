import pytest
from builders import ast_json

from ftest.cond import AstError, conjuncts, evaluate, parse, render


def test_render_round_trips_falco_syntax():
    text = (
        'spawned_process and (proc.name in (bash, sh) or proc.cmdline contains "a b") and not fd.name exists'
    )
    assert render(parse(ast_json(text))) == text


def test_render_quotes_values_that_are_not_bare_strings():
    node = parse(ast_json('proc.cmdline = "sh -c" and proc.name in ("x,y", and)'))
    assert render(node) == 'proc.cmdline = "sh -c" and proc.name in ("x,y", "and")'


def test_render_elides_long_lists_only_when_asked():
    node = parse(ast_json("proc.name in (a, b, c, d)"))
    assert render(node, max_items=2) == "proc.name in (a, b, ... +2)"
    assert render(node) == "proc.name in (a, b, c, d)"


def test_field_args_and_transformers_render():
    node = parse(
        {
            "type": "check",
            "op": "=",
            "lhs": {
                "type": "transformer",
                "name": "tolower",
                "args": [{"type": "field", "field": "proc.aname", "arg": "2"}],
            },
            "rhs": {"type": "value", "value": "bash"},
        }
    )
    assert render(node) == "tolower(proc.aname[2]) = bash"


def test_evaluate_uses_leaf_ids():
    node = parse(ast_json("a.x = 1 and (b.x = 2 or not c.x = 3)", ids=True))
    assert evaluate(node, [True, False, False]) is True
    assert evaluate(node, [True, False, True]) is False
    assert evaluate(node, [False, True, True]) is False


def test_evaluate_rejects_raw_conditions():
    with pytest.raises(AstError):
        evaluate(parse(ast_json("spawned_process")), [])


def test_conjuncts_flatten_nested_ands():
    node = parse(ast_json("(a.x = 1 and b.x = 2) and c.x = 3"))
    assert [render(c) for c in conjuncts(node)] == ["a.x = 1", "b.x = 2", "c.x = 3"]


def test_parse_reports_the_path_of_bad_nodes():
    with pytest.raises(AstError, match=r"\$\.children\[1\]"):
        parse({"type": "and", "children": [ast_json("a.x = 1"), {"type": "bogus"}]})
