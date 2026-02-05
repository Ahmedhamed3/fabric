# Sysmon EventID Coverage Checklist (7/8/10/12/13/14)

This checklist tracks end-to-end support for Sysmon EventIDs 7, 8, 10, 12, 13, and 14, across detection, parsing, mapping, pipeline output, samples, and tests.

| EventID | Evidence Type | Detection | Parsing | Mapping | Pipeline | Samples | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 7 | Image load (module activity) | `app/plugins/sysmon/detect.py` score_events | `app/plugins/sysmon/parse.py` `_extract_fields` | `app/plugins/sysmon/map_to_ocsf.py` `map_sysmon_eventid7_to_ocsf` | `app/plugins/sysmon/pipeline.py` `convert_sysmon_events_to_ocsf_jsonl` | `samples/sysmon_7_8_10_12_13_14.ndjson` | `tests/test_sysmon_eid_7_8_10_12_13_14_end_to_end.py` |
| 8 | CreateRemoteThread (process inject) | `app/plugins/sysmon/detect.py` score_events | `app/plugins/sysmon/parse.py` `_extract_fields` | `app/plugins/sysmon/map_to_ocsf.py` `map_sysmon_eventid8_to_ocsf` | `app/plugins/sysmon/pipeline.py` `convert_sysmon_events_to_ocsf_jsonl` | `samples/sysmon_7_8_10_12_13_14.ndjson` | `tests/test_sysmon_eid_7_8_10_12_13_14_end_to_end.py` |
| 10 | Process access (process open) | `app/plugins/sysmon/detect.py` score_events | `app/plugins/sysmon/parse.py` `_extract_fields` | `app/plugins/sysmon/map_to_ocsf.py` `map_sysmon_eventid10_to_ocsf` | `app/plugins/sysmon/pipeline.py` `convert_sysmon_events_to_ocsf_jsonl` | `samples/sysmon_7_8_10_12_13_14.ndjson` | `tests/test_sysmon_eid_7_8_10_12_13_14_end_to_end.py` |
| 12 | Registry key create/delete | `app/plugins/sysmon/detect.py` score_events | `app/plugins/sysmon/parse.py` `_extract_fields` | `app/plugins/sysmon/map_to_ocsf.py` `map_sysmon_eventid12_to_ocsf` | `app/plugins/sysmon/pipeline.py` `convert_sysmon_events_to_ocsf_jsonl` | `samples/sysmon_7_8_10_12_13_14.ndjson` | `tests/test_sysmon_eid_7_8_10_12_13_14_end_to_end.py` |
| 13 | Registry value set | `app/plugins/sysmon/detect.py` score_events | `app/plugins/sysmon/parse.py` `_extract_fields` | `app/plugins/sysmon/map_to_ocsf.py` `map_sysmon_eventid13_to_ocsf` | `app/plugins/sysmon/pipeline.py` `convert_sysmon_events_to_ocsf_jsonl` | `samples/sysmon_7_8_10_12_13_14.ndjson` | `tests/test_sysmon_eid_7_8_10_12_13_14_end_to_end.py` |
| 14 | Registry key/value rename | `app/plugins/sysmon/detect.py` score_events | `app/plugins/sysmon/parse.py` `_extract_fields` | `app/plugins/sysmon/map_to_ocsf.py` `map_sysmon_eventid14_to_ocsf` | `app/plugins/sysmon/pipeline.py` `convert_sysmon_events_to_ocsf_jsonl` | `samples/sysmon_7_8_10_12_13_14.ndjson` | `tests/test_sysmon_eid_7_8_10_12_13_14_end_to_end.py` |

Notes:
- Samples intentionally omit common fields (e.g., User, ProcessGuid, ProcessId) to validate mapper resilience and ensure outputs are still produced while preserving `unmapped.original_event`.
- Tests run the full conversion path via `app/conversion.py` to ensure end-to-end support.
