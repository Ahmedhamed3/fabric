from __future__ import annotations

import argparse
from pathlib import Path

from app.normalizers.elastic_to_ocsf.io_ndjson import convert_events, read_raw_events, write_ndjson
from app.normalizers.elastic_to_ocsf.validator import OcsfSchemaLoader


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Elastic RawEvent → OCSF converter (Phase 2)")
    parser.add_argument("--input", dest="input_path", required=True, help="RawEvent NDJSON input path")
    parser.add_argument("--output", dest="output_path", required=True, help="OCSF NDJSON output path")
    parser.add_argument(
        "--report",
        dest="report_path",
        help="Mapping report NDJSON path (default: <output>.report.ndjson)",
    )
    parser.add_argument("--limit", type=int, default=None, help="Limit number of input events processed")
    parser.add_argument("--strict", action="store_true", help="Drop invalid OCSF events")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv or __import__("sys").argv[1:])
    input_path = Path(args.input_path)
    output_path = Path(args.output_path)
    report_path = Path(args.report_path) if args.report_path else output_path.with_suffix(".report.ndjson")

    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    raw_events = read_raw_events(input_path)
    outputs = []
    reports = []
    count = 0
    for ocsf_event, report in convert_events(raw_events, schema_loader=schema_loader, strict=args.strict):
        if args.limit is not None and count >= args.limit:
            break
        count += 1
        if ocsf_event is not None:
            outputs.append(ocsf_event)
        reports.append(report)
    write_ndjson(output_path, outputs)
    write_ndjson(report_path, reports)


if __name__ == "__main__":
    main()
