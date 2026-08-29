"""Adapters to external platforms (``claude.md`` section 18).

The dependency-inversion boundary between AEGIS and anything it does not own: Gemini,
ADK, Agent Runtime, Agent Registry, Agent Identity, Agent Gateway, Model Armor, Memory
Bank and Agent Observability. The control plane depends on interfaces defined near its
own components, never on a vendor SDK directly.

Two standing rules for this package:

* A fallback exists for engineering resilience, not to imply that an integration is
  configured. Never fabricate a platform response.
* Each real integration carries an implementation/evidence record (section 28.20)
  stating what was actually verified in this project's environment.

Currently populated:

* :mod:`aegis.integrations.provider` — provider-neutral call telemetry and the recording
  wrapper. Knows nothing about any vendor.
* :mod:`aegis.integrations.replay` — a second, offline provider that replays raw response
  text through the real validation path.
* :mod:`aegis.integrations.gemini` — the Gemini provider. The **only** module in AEGIS
  permitted to import ``google``, asserted structurally by test.

Deliberately not re-exported here. ``from aegis.integrations import *`` must not be able to
drag a vendor SDK into a deterministic import graph, so each provider is imported by its
own module path or not at all.
"""
