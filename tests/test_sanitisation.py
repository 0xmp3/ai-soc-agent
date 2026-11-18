import UTILITIES


def test_a_string_field_list_is_not_split_into_characters():
    # models drift and send "a,b" instead of ["a","b"]; joining a string would
    # produce "a, ,, b"
    context = UTILITIES.sanitize_query_context({"fields": "TimeGenerated,DeviceName"})
    assert context["fields"] == "TimeGenerated, DeviceName"


def test_an_array_field_list_is_joined():
    context = UTILITIES.sanitize_query_context({"fields": ["TimeGenerated", "DeviceName"]})
    assert context["fields"] == "TimeGenerated, DeviceName"


def test_missing_scoping_keys_are_filled_with_empty_strings():
    context = UTILITIES.sanitize_query_context({"fields": ["TimeGenerated"]})
    assert context["caller"] == ""
    assert context["device_name"] == ""
    assert context["user_principal_name"] == ""


def test_quotes_are_stripped_so_a_literal_cannot_be_closed():
    assert '"' not in UTILITIES.sanitize_literal('web-01" | where 1==1 //')


def test_backslashes_are_stripped():
    assert "\\" not in UTILITIES.sanitize_literal("web-01\\")


def test_newlines_and_semicolons_are_stripped():
    cleaned = UTILITIES.sanitize_literal("web\n01;\r02")
    assert "\n" not in cleaned and "\r" not in cleaned and ";" not in cleaned


def test_ordinary_values_survive_untouched():
    for value in ("web-01", "linux-target-1", "a@b.com"):
        assert UTILITIES.sanitize_literal(value) == value


def test_threats_are_appended_to_jsonl(tmp_path, capsys):
    log = tmp_path / "_threats.jsonl"
    UTILITIES.append_threats_to_jsonl([{"title": "a"}, {"title": "b"}], filename=str(log))
    UTILITIES.append_threats_to_jsonl([{"title": "c"}], filename=str(log))

    lines = log.read_text(encoding="utf-8").splitlines()
    assert [__import__("json").loads(line)["title"] for line in lines] == ["a", "b", "c"]
