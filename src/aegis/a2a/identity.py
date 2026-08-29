"""Who an agent actually is, as distinct from who a message says it is.

The single most important thing A2A does. A message carries ``sender_agent_id`` because a
recipient needs to know where to reply — not because that field is evidence of anything. The
sender is established by the **transport boundary**, from the accountable agent record the
application wired up, and the declared field is then compared against it.

    declared sender  (model-influenced, in the message)
    accountable agent (authoritative, from the wiring)
                    ↓
              must be equal, exactly

A Commander that writes ``sender_agent_id="remediation"`` has not become remediation. It
has written a mismatch, and a mismatch is a rejection.

Why a directory rather than a registry import
---------------------------------------------

The delegation matrix and the specialist roster are declared in
:mod:`aegis.orchestration.delegation`, and this package must not import orchestration
(Part 20). So both are **injected**: the application passes the same matrix and the same
set of registered ids that the rest of AEGIS uses. There is exactly one delegation policy;
it simply travels down the dependency arrow instead of being reached for up it.

Every lookup is exact. An agent id is a dictionary key — never an attribute name, a module
path or anything that becomes a callable — so an invented name can only ever produce
"unknown agent", and a whitespace-padded one cannot even be constructed
(:data:`~aegis.a2a.contracts.ExactId`).
"""

from __future__ import annotations

from collections.abc import Mapping, Set
from types import MappingProxyType

__all__ = ["AgentDirectory"]


class AgentDirectory:
    """The authoritative answer to "does this agent exist, and may it talk to that one".

    Args:
        agents: Every agent id that exists, exactly as registered.
        matrix: Permitted communication edges, sender id to the set of recipient ids.
            Injected rather than imported so this package stays independent of
            orchestration; the application passes the one real matrix.

    Both are copied and frozen at construction. Nothing here mutates after that, and there
    is no method that adds an agent, adds an edge, or widens anyone's reach — an agent that
    could extend the matrix at runtime would be an agent that could grant itself a
    correspondent.
    """

    def __init__(self, agents: Set[str], matrix: Mapping[str, frozenset[str]]) -> None:
        self._agents = frozenset(agents)
        self._matrix = MappingProxyType({key: frozenset(value) for key, value in matrix.items()})

    @property
    def agents(self) -> frozenset[str]:
        return self._agents

    def knows(self, agent_id: str) -> bool:
        """Whether this exact id is a registered agent. No normalisation, no fuzzy match."""
        return agent_id in self._agents

    def permits(self, sender: str, recipient: str) -> bool:
        """Whether the matrix has an edge. Exact match on both ends.

        An agent absent from the matrix may talk to nobody, so a specialist — whose row is
        empty by construction — can never reach another specialist (Part 3).
        """
        return recipient in self._matrix.get(sender, frozenset())

    def recipients_for(self, sender: str) -> tuple[str, ...]:
        """Who this agent may reach, sorted, restricted to agents that exist."""
        return tuple(sorted(self._matrix.get(sender, frozenset()) & self._agents))

    def binds(self, declared_sender: str, accountable_agent_id: str) -> bool:
        """Whether a declared sender matches the agent actually sending.

        The comparison the whole identity model reduces to. Exact string equality: no
        case folding, no stripping, no aliasing. Each of those would be a way for a
        model-supplied string to become a different agent's identity.
        """
        return declared_sender == accountable_agent_id

    def __contains__(self, agent_id: object) -> bool:
        return agent_id in self._agents

    def __repr__(self) -> str:
        return f"{type(self).__name__}({len(self._agents)} agents, {len(self._matrix)} rows)"
