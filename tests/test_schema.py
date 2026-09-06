import json
from pathlib import Path

import jsonschema

from src import report


SCHEMA = json.loads((Path(__file__).parents[1] / "schema.json").read_text(encoding="utf-8"))


def test_schema_itself_is_valid_draft_2020_12():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)


def test_generated_probe_report_matches_schema():
    payload = report.generate("203.0.113.1", {}, profile="test", samples=3)
    jsonschema.Draft202012Validator(SCHEMA).validate(payload)


def test_minimal_tunnel_diagnosis_matches_schema():
    payload = {
        "schema_version": "1.0",
        "timestamp": "2026-08-31T00:00:00Z",
        "environment": {},
        "endpoint": None,
        "config": None,
        "log": None,
        "pcap": None,
        "clash_api": None,
        "active_checks": None,
        "data_needed_for_localization": [],
    }
    jsonschema.Draft202012Validator(SCHEMA).validate(payload)
