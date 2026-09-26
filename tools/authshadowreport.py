#!/usr/bin/env python3
"""Summarize MilterGuard authentication shadow JSON logs from stdin."""

import argparse
import collections
import json
import math
import sys


METHODS = ("spf", "dkim", "dmarc")


def percentile(values, percentile_value):
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile_value * len(ordered)) - 1)
    return ordered[index]


def summarize(lines):
    records = []
    invalid_lines = 0
    for line in lines:
        try:
            record = json.loads(line)
        except (TypeError, ValueError):
            invalid_lines += 1
            continue
        if record.get("msg") == "authentication shadow comparison":
            records.append(record)

    errors = collections.Counter()
    method_comparisons = collections.Counter()
    method_differences = collections.Counter()
    detail_differences = collections.Counter()
    internal_reasons = collections.Counter()
    durations = []
    completed = 0
    with_reference = 0
    semantic_matches = 0
    semantic_differences = 0
    detail_difference_records = 0

    for record in records:
        if record.get("completed") is True:
            completed += 1
        if record.get("shadow_error"):
            errors[str(record["shadow_error"])] += 1
        compared = int(record.get("compared_methods") or 0)
        if compared:
            with_reference += 1
            if record.get("completed") is True and record.get("matched") is True:
                semantic_matches += 1
            elif record.get("completed") is True:
                semantic_differences += 1
        if record.get("detail_differences"):
            detail_difference_records += 1
        duration = record.get("duration_ms")
        if isinstance(duration, int) and duration >= 0:
            durations.append(duration)
        for method in METHODS:
            detail = record.get(method) or {}
            if detail.get("compared") is True:
                method_comparisons[method] += 1
            if method in (record.get("differences") or []):
                method_differences[method] += 1
            if method in (record.get("detail_differences") or []):
                detail_differences[method] += 1
            for reason in detail.get("internal_reasons") or []:
                internal_reasons[str(reason)] += 1

    latency = {
        "median": percentile(durations, 0.50),
        "p95": percentile(durations, 0.95),
        "max": max(durations) if durations else None,
    }
    return {
        "records": len(records),
        "completed": completed,
        "shadow_errors": dict(sorted(errors.items())),
        "with_trusted_reference": with_reference,
        "without_trusted_reference": len(records) - with_reference,
        "semantic_matches": semantic_matches,
        "semantic_differences": semantic_differences,
        "detail_difference_records": detail_difference_records,
        "method_comparisons": dict(sorted(method_comparisons.items())),
        "method_differences": dict(sorted(method_differences.items())),
        "method_detail_differences": dict(sorted(detail_differences.items())),
        "internal_reasons": dict(sorted(internal_reasons.items())),
        "latency_ms": latency,
        "ignored_non_json_lines": invalid_lines,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Summarize authentication shadow comparison JSON records from stdin."
    )
    parser.parse_args()
    json.dump(summarize(sys.stdin), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
