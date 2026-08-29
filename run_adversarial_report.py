"""Run the AEGIS adversarial evaluation matrix and print the report.

    uv run python run_adversarial_report.py
    uv run python run_adversarial_report.py --json

Twenty-five attacks across eight classes, every one assuming the reasoning layer is fully
captured. This is not a test of whether a model refuses attacks — a model that refuses is
pleasant and proves nothing, because the next model will not. It measures what the
deterministic control plane does when the model and the data are hostile.

Deterministic and offline: injected clock, simulated enterprise, scripted models, no
credentials and no network. Two runs produce the same report.

The fleet comes from ``tests.fleet``, for the same reason ``run_benchmark.py`` takes it from
there: the matrix should measure the declared organizational configuration the rest of the
suite asserts against, not one written to be easy to defend.

Exit code is 0 when every attack was contained and 1 when any was not, so this can gate a
build the way the benchmark does.
"""

from __future__ import annotations

import argparse
import json
import sys

from tests.fleet import (
    BUSINESS_IMPACT,
    COMMANDER,
    DIAGNOSTIC,
    REMEDIATION,
    SECURITY,
    build_registry,
    fixed_clock,
)

from aegis.enterprise import PAYMENT_API_RECOVERED
from aegis.evaluation.adversarial import (
    AdversarialFixture,
    render_report,
    report_json,
    run_matrix,
)

ADVERSARIAL_FLEET = {
    "commander": COMMANDER,
    "diagnostic": DIAGNOSTIC,
    "security": SECURITY,
    "business-impact": BUSINESS_IMPACT,
    "remediation": REMEDIATION,
}


def build_fixture() -> AdversarialFixture:
    """The organizational configuration the matrix attacks."""
    return AdversarialFixture(
        registry=build_registry(),
        agents=ADVERSARIAL_FLEET,
        expected_state=PAYMENT_API_RECOVERED,
        clock=fixed_clock,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print the machine-readable report")
    args = parser.parse_args(argv)

    results = run_matrix(build_fixture())
    summary = report_json(results)
    print(json.dumps(summary, indent=2, sort_keys=True) if args.json else render_report(results))
    return 0 if summary["contained"] == summary["attacks"] else 1


if __name__ == "__main__":
    sys.exit(main())
