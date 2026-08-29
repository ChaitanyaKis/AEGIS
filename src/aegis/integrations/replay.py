"""A second provider: replays raw response *text* through the real validation path.

Why this exists, and why it is not the scripted test model
----------------------------------------------------------

:class:`~aegis.agents.deterministic.ScriptedCommanderModel` hands back
:class:`~aegis.agents.decisions.CommanderDecision` objects that were built in Python and
have therefore already satisfied the contract. It is the right tool for "make the Commander
propose exactly this", and the wrong tool for "prove the boundary rejects that", because
the text never goes through a parser.

This provider takes **strings**, exactly as a provider hands them over, and runs them
through :func:`~aegis.agents.model.parse_decision` — the same function the Gemini provider
calls, on the same code path. So a captured Gemini response, a hand-written adversarial
one, and a real live response are all validated identically, and an adversarial case is
testable offline without pretending a network call happened.

It also satisfies Part 9 concretely: three unrelated implementations —
:class:`~aegis.agents.deterministic.DeterministicCommanderModel`, this, and
:class:`~aegis.integrations.gemini.GeminiCommanderModel` — drive the same Commander through
the same interface, and no Commander or orchestration code knows which one it holds.

Authority: none. Replaying a captured response that says "I have approved this" produces a
decision that says so in prose and changes nothing, because there is no field for approval
and no engine on the other side of this class.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from aegis.agents.model import (
    MalformedModelOutput,
    ModelError,
    ModelOutput,
    ModelRequest,
    parse_decision,
    parse_finding,
)

__all__ = ["CaptureEntry", "ReplayModelClient", "load_capture", "write_capture"]


class CaptureEntry:
    """One recorded provider exchange: what the request digested to, and what came back.

    Not a domain contract, because a capture is a test fixture rather than an artifact the
    control plane reasons about. Plain JSON so a capture file can be reviewed by eye and
    diffed in a pull request.
    """

    __slots__ = ("note", "request_digest", "response_text")

    def __init__(
        self, *, response_text: str, request_digest: str | None = None, note: str | None = None
    ) -> None:
        self.response_text = response_text
        self.request_digest = request_digest
        self.note = note

    def as_json(self) -> dict[str, Any]:
        return {
            "request_digest": self.request_digest,
            "response_text": self.response_text,
            "note": self.note,
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> CaptureEntry:
        text = payload.get("response_text")
        if not isinstance(text, str):
            raise ValueError("a capture entry needs a string 'response_text'")
        return cls(
            response_text=text,
            request_digest=payload.get("request_digest"),
            note=payload.get("note"),
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(bytes={len(self.response_text)}, note={self.note!r})"


class ReplayModelClient:
    """Replays raw provider text, in order, through the real parser.

    Args:
        responses: Each entry is either the raw text a provider returned, a
            :class:`CaptureEntry`, or an exception instance to raise at that step. An
            exception entry is how a captured *failure* is replayed.
        name: Provider name, as it appears in traces and audit records.
        parse: ``"decision"`` for a Commander, ``"finding"`` for a specialist.

    Running past the end of the script raises, so a test cannot accidentally depend on what
    an exhausted replay would have said next. There is no wrap-around, no repeat of the
    last entry and no default — every one of those would be a decision this class invented.
    """

    def __init__(
        self,
        *responses: str | CaptureEntry | BaseException,
        name: str = "replay-provider",
        parse: str = "decision",
    ) -> None:
        if parse not in {"decision", "finding"}:
            raise ValueError(f"parse must be 'decision' or 'finding', got {parse!r}")
        self.name = name
        self._parse = parse_decision if parse == "decision" else parse_finding
        self._entries: tuple[str | CaptureEntry | BaseException, ...] = responses
        self._calls = 0
        self._requests: list[ModelRequest] = []

    @classmethod
    def from_capture(
        cls, path: str | Path, *, name: str = "replay-provider", parse: str = "decision"
    ) -> ReplayModelClient:
        """Build from a capture file written by :func:`write_capture`."""
        entries = load_capture(path)
        return cls(*entries, name=name, parse=parse)

    @property
    def calls(self) -> int:
        """How many times the provider was asked. Lets a test assert on retry behaviour."""
        return self._calls

    @property
    def requests(self) -> tuple[ModelRequest, ...]:
        """Every request received, so a test can assert what the model was actually shown."""
        return tuple(self._requests)

    def decide(self, request: ModelRequest) -> ModelOutput:
        index = self._calls
        self._calls += 1
        self._requests.append(request)
        if index >= len(self._entries):
            raise ModelError(f"replay provider exhausted after {len(self._entries)} responses")
        entry = self._entries[index]
        if isinstance(entry, BaseException):
            raise entry
        text = entry.response_text if isinstance(entry, CaptureEntry) else entry
        if not isinstance(text, str):
            raise MalformedModelOutput(f"replay entry {index} is a {type(entry).__name__}")
        return self._parse(text)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r}, entries={len(self._entries)})"


def write_capture(path: str | Path, entries: Iterable[CaptureEntry]) -> Path:
    """Write a capture file: one JSON object per line.

    Captures hold **response text only**. A request is represented by its digest, never by
    its content — a request carries the incident payload and organizational history, and a
    capture file is exactly the kind of artifact that ends up in a repository.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        for entry in entries:
            handle.write(json.dumps(entry.as_json(), sort_keys=True, ensure_ascii=False) + "\n")
    return target


def load_capture(path: str | Path) -> Sequence[CaptureEntry]:
    """Read a capture file written by :func:`write_capture`."""
    source = Path(path)
    entries: list[CaptureEntry] = []
    for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except ValueError as error:
            raise ValueError(f"{source}:{number} is not JSON: {error}") from error
        if not isinstance(payload, dict):
            raise ValueError(f"{source}:{number} is not a JSON object")
        entries.append(CaptureEntry.from_json(payload))
    return tuple(entries)
