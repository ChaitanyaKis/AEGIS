"""Parts 22, 23 and 27: search that narrows, an export that is evidence, and latency.

**Search narrows.** A query cannot reach an incident the control center was not given,
cannot merge two incidents, and cannot produce a record an operator could not have read by
opening the incident directly. And an ``UNKNOWN`` field matches neither ``TRUE`` nor
``FALSE`` -- a filter is a question about a known value, and "nobody could tell" is not an
answer to it.

**An export is evidence.** Deterministic to the byte, carrying its own audit verdict, and
free of anything that could be a secret. Read months later by somebody without the system
that produced it.

**Latency is measured, not optimised.** Generous ceilings that catch an accidental
quadratic without being flaky, and no caching anywhere -- a cached projection is a stale one,
and stale governance state is exactly what this package must not show.
"""

from __future__ import annotations

import json
import time

import pytest

from aegis.control_center import (
    EXPORT_FORMAT_VERSION,
    FORBIDDEN_CONTENT,
    UNKNOWABLE_FIELDS,
    IncidentQuery,
    Tri,
    capture_incident,
    export_incident,
    export_json,
    project_incident,
    search,
    unknown_for,
)
from aegis.core.domain import from_json, to_json

from .conftest import capture


@pytest.fixture
def catalogue(projection, denied, escalated):
    """Three genuinely different projections to search over."""
    from aegis.control_center import IncidentProjection

    others = []
    for orchestrator, run in (denied, escalated):
        others.append(project_incident(capture(orchestrator, run)))
    # Distinct ids, since all three share one incident id in the fixtures.
    renamed: list[IncidentProjection] = [projection]
    for index, other in enumerate(others, start=1):
        renamed.append(other.model_copy(update={"incident_id": f"INC-OTHER-{index}"}))
        object.__setattr__(renamed[-1], "_input", other._input)
    return tuple(renamed)


class TestSearchNarrows:
    def test_an_unfiltered_query_returns_what_the_caller_already_held(self, catalogue) -> None:
        assert len(search(catalogue, IncidentQuery())) == len(catalogue)

    def test_every_supplied_filter_narrows(self, catalogue) -> None:
        everything = search(catalogue, IncidentQuery())
        narrowed = search(catalogue, IncidentQuery(resolved=Tri.TRUE))
        assert set(narrowed) <= set(everything)

    def test_results_are_ordered_and_deterministic(self, catalogue) -> None:
        first = search(catalogue, IncidentQuery())
        assert first == search(catalogue, IncidentQuery())
        assert [p.incident_id for p in first] == sorted(p.incident_id for p in first)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("state", "RESOLVED"),
            ("policy_decision", "REQUIRE_APPROVAL"),
            ("capability", "production.rollback"),
            ("resource", "service:payment-api"),
            ("severity", "CRITICAL"),
        ],
    )
    def test_a_filter_matches_only_the_exact_value(self, catalogue, field, value) -> None:
        matched = search(catalogue, IncidentQuery(**{field: value}))
        for projection in matched:
            assert value in to_json(projection)

    def test_a_filter_on_a_value_nobody_has_returns_nothing(self, catalogue) -> None:
        assert search(catalogue, IncidentQuery(state="NOT-A-STATE")) == ()

    def test_an_unknown_field_matches_neither_true_nor_false(self, catalogue) -> None:
        """The rule that matters. An operator searching for unverified executions must not
        silently miss the ones nobody could check -- which are the ones that matter most."""
        true_matches = set(search(catalogue, IncidentQuery(verified=Tri.TRUE)))
        false_matches = set(search(catalogue, IncidentQuery(verified=Tri.FALSE)))
        unknown_matches = set(search(catalogue, IncidentQuery(verified=Tri.UNKNOWN)))
        assert not (true_matches & false_matches)
        assert not (unknown_matches & true_matches)
        assert not (unknown_matches & false_matches)

    def test_unknown_for_names_exactly_that_set(self, catalogue) -> None:
        """Exposed as its own question, because a control center that hid unknowns would
        make it unaskable."""
        found = unknown_for(catalogue, "agents_restricted")
        assert set(found) == {p for p in catalogue if p.summary.agents_restricted is Tri.UNKNOWN}

    def test_unknown_for_refuses_a_field_outside_the_closed_set(self, catalogue) -> None:
        """A caller-supplied string must not become an attribute name."""
        with pytest.raises(ValueError, match="not a tri-state summary field"):
            unknown_for(catalogue, "__class__")

    def test_the_closed_set_is_what_the_summary_actually_holds(self) -> None:
        from aegis.control_center import IncidentSummary

        assert set(IncidentSummary.model_fields) >= UNKNOWABLE_FIELDS

    def test_a_query_reports_which_filters_it_applies(self) -> None:
        query = IncidentQuery(state="RESOLVED", verified=Tri.TRUE)
        assert query.specified == ("state", "verified")

    def test_search_reaches_nothing_it_was_not_given(self, catalogue, projection) -> None:
        """The isolation property, stated for search: a query is a filter over a caller's
        own collection, never a lookup into a wider store."""
        assert projection not in search(catalogue[1:], IncidentQuery())


class TestTheForensicExport:
    def test_it_is_deterministic_to_the_byte(self, projection) -> None:
        assert export_json(projection) == export_json(projection)

    def test_two_projections_of_the_same_input_export_identically(self, data) -> None:
        assert export_json(project_incident(data)) == export_json(project_incident(data))

    def test_it_round_trips(self, projection) -> None:
        from aegis.control_center import IncidentExport

        document = export_json(projection)
        assert to_json(from_json(IncidentExport, document)) == document

    def test_it_carries_its_own_format_version(self, projection) -> None:
        assert export_incident(projection).format_version == EXPORT_FORMAT_VERSION

    def test_the_audit_verdict_travels_inside_the_document(self, data) -> None:
        """Part 17. An export of a corrupted trail says so, in the artifact, where a reader
        cannot miss it."""
        from .conftest import corrupt

        export = export_incident(project_incident(corrupt(data)))
        assert export.audit.trust.value == "UNTRUSTED"
        assert export.audit.first_invalid_index is not None
        assert not export.complete

    @pytest.mark.parametrize("forbidden", sorted(FORBIDDEN_CONTENT))
    def test_no_forbidden_field_name_appears(self, projection, forbidden: str) -> None:
        assert f'"{forbidden}"' not in export_json(projection).lower()

    def test_no_key_material_appears(self, projection) -> None:
        """Swept over the rendered document rather than the field names, because a leak
        that arrived as a *value* would pass a schema check and still be a leak."""
        rendered = export_json(projection)
        for suspicious in ("BEGIN PRIVATE", "hmac", "-----BEGIN"):
            assert suspicious not in rendered

    def test_it_contains_every_section_part_23_requires(self, projection) -> None:
        export = export_incident(projection)
        for section in (
            "summary",
            "timeline",
            "causal_chain",
            "governance",
            "lifecycle",
            "breakers",
            "agents",
            "memory",
            "a2a",
            "security",
            "audit",
            "sources",
        ):
            assert getattr(export, section) is not None, section

    def test_ids_timestamps_and_evidence_survive(self, projection) -> None:
        document = json.loads(export_json(projection))
        assert document["incident_id"] == projection.incident_id
        assert document["timeline"]["entries"]
        assert any(entry["evidence_refs"] for entry in document["timeline"]["entries"])

    def test_no_prompt_or_response_text_is_reconstructed(self, projection) -> None:
        """``model.decision`` records digests, never text. There is nothing to reconstruct
        from, and Part 23 forbids inventing it."""
        rendered = export_json(projection).lower()
        for word in ("system_prompt", "prompt_text", "response_text", "you are the"):
            assert word not in rendered

    def test_an_export_of_a_crashed_run_is_still_a_document(self, resolved) -> None:
        orchestrator, run = resolved
        crashed = project_incident(
            capture(orchestrator, None, incident_id=run.incident.incident_id)
        )
        export = export_incident(crashed)
        assert not export.complete
        assert export.summary.executed is Tri.UNKNOWN


class TestPerformance:
    """Part 27. Ceilings generous enough not to be flaky, tight enough to catch a
    quadratic. Nothing here is optimised for, and nothing is cached."""

    def test_projecting_is_fast_enough(self, data) -> None:
        started = time.perf_counter()
        for _ in range(20):
            project_incident(data)
        elapsed = time.perf_counter() - started
        assert elapsed < 5.0, f"20 projections took {elapsed:.2f}s"

    def test_exporting_is_fast_enough(self, projection) -> None:
        started = time.perf_counter()
        for _ in range(20):
            export_json(projection)
        elapsed = time.perf_counter() - started
        assert elapsed < 5.0, f"20 exports took {elapsed:.2f}s"

    def test_a_large_trail_does_not_go_quadratic(self, data) -> None:
        """Ten times the records must not take a hundred times the work.

        Deterministic synthetic data: the same records repeated, so the only thing that
        changes is how many there are.
        """
        small = data.model_copy(update={"audit_records": data.audit_records})
        large = data.model_copy(update={"audit_records": data.audit_records * 10})

        def measure(payload) -> float:
            started = time.perf_counter()
            project_incident(payload)
            return time.perf_counter() - started

        measure(small)  # warm the import path so the first call is not the outlier
        ratio = (measure(large) + 1e-6) / (measure(small) + 1e-6)
        assert ratio < 40, f"ten times the records cost {ratio:.1f} times the work"

    def test_searching_is_linear_enough(self, catalogue) -> None:
        started = time.perf_counter()
        for _ in range(200):
            search(catalogue, IncidentQuery(resolved=Tri.TRUE))
        assert time.perf_counter() - started < 5.0

    def test_nothing_is_cached(self) -> None:
        """Part 27's constraint, structurally. A cached projection is a stale one, and
        stale governance state on an operator's screen is the failure this package exists to
        avoid. There is no cache to invalidate because there is no cache."""
        import ast
        import pathlib

        for path in sorted(pathlib.Path("src/aegis/control_center").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    assert "cache" not in node.id.lower(), f"{path.name}: {node.id}"
                if isinstance(node, ast.Attribute):
                    assert "cache" not in node.attr.lower(), f"{path.name}: {node.attr}"

    def test_capture_is_a_pure_function_of_its_sources(self, resolved) -> None:
        """Two captures of an unchanged system produce the same value, which is what makes
        caching unnecessary as well as forbidden."""
        orchestrator, run = resolved
        first = capture_incident(orchestrator, run, clock=lambda: run.incident.created_at)
        second = capture_incident(orchestrator, run, clock=lambda: run.incident.created_at)
        assert first == second
