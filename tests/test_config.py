import json

from src import config


def test_valid_config_is_loaded(tmp_path):
    path = tmp_path / "targets.json"
    expected = {
        "targets": [{"ip": "1.1.1.1", "name": "reference"}],
        "domains": {"clean": ["example.com"], "blocked": ["blocked.example"]},
    }
    path.write_text(json.dumps(expected), encoding="utf-8")

    assert config.load(str(path)) == expected


def test_invalid_config_fails_closed(tmp_path):
    path = tmp_path / "targets.json"
    path.write_text('{"targets": []}', encoding="utf-8")

    try:
        config.load(str(path))
    except ValueError as exc:
        assert "invalid probe configuration" in str(exc)
    else:
        raise AssertionError("invalid configuration must not issue probes against fallback targets")


def test_overlapping_domain_hypotheses_are_rejected(tmp_path):
    path = tmp_path / "targets.json"
    path.write_text(json.dumps({
        "targets": [{"ip": "1.1.1.1", "name": "reference"}],
        "domains": {"clean": ["Example.com"], "blocked": ["example.com."]},
    }), encoding="utf-8")
    try:
        config.load(str(path))
    except ValueError as exc:
        assert "overlap" in str(exc)
    else:
        raise AssertionError("overlapping comparison groups must be rejected")
