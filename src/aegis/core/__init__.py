"""AEGIS deterministic control plane.

Zone C of the trust model (``claude.md`` section 4): authoritative. Everything that
decides — policy, risk, blast radius, capability resolution, approval, incident state
transitions, verification and audit — lives here, and nothing here may delegate a
decision to an LLM.

Currently populated:

* :mod:`aegis.core.domain` — the typed domain contracts
* :mod:`aegis.core.capabilities` — the in-process capability registry
* :mod:`aegis.core.dependencies` — the declared resource dependency graph
* :mod:`aegis.core.assessment` — the blast-radius and risk engines, and the pipeline
  that turns a proposal into an authoritatively assessed action
* :mod:`aegis.core.policy` — the deterministic policy engine
* :mod:`aegis.core.approval` — time-bounded, single-use human approval artifacts
* :mod:`aegis.core.verification` — establishing that the enterprise actually changed
* :mod:`aegis.core.incidents` — the deterministic incident state machine
* :mod:`aegis.core.audit` — append-only, tamper-evident application history
"""
