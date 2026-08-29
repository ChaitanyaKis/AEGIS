"""Parts 10, 11 and 12: delivery, deterministic faults, and failing closed.

The transport is the least trusted thing in this package and the most tested. Two properties
run through everything here: it can do anything a network can do to a frame, and none of
those things can produce an authenticated message or an authorized action.
"""

from __future__ import annotations

import ast
import inspect
import pathlib

import pytest

from aegis.a2a.remote import (
    InMemoryRemoteTransport,
    RemoteFault,
    RemoteFrame,
    RemoteRejection,
    RemoteTransport,
    RemoteTransportError,
    RemoteVerdict,
    frame_digest,
)

from .conftest import INCIDENT, frame_for, issue

FORBIDDEN_OPERATIONS = (
    "authoriz",
    "approve",
    "execute",
    "verify_action",
    "resolve_incident",
    "issue_gate",
    "change_risk",
    "permit",
    "allow",
    "deny",
    "policy",
    "grant",
)


class TestTheProtocolIsFourOperations:
    def test_the_protocol_names_exactly_send_receive_acknowledge_reject(self) -> None:
        surface = {name for name in dir(RemoteTransport) if not name.startswith("_")}
        assert surface == {"send", "receive", "acknowledge", "reject"}

    def test_the_in_memory_transport_satisfies_the_protocol(self, remote_transport) -> None:
        assert isinstance(remote_transport, RemoteTransport)

    def test_no_transport_implementation_decides_authority(self) -> None:
        """The Prompt 16 lesson, applied here from the start: a protocol constrains what a
        caller may rely on, not what a class may grow. So the implementations are swept
        too, not only the interface."""
        from aegis.a2a.remote import transport as transport_module

        for name, obj in vars(transport_module).items():
            if not inspect.isclass(obj) or obj.__module__ != transport_module.__name__:
                continue
            methods = {m for m in dir(obj) if not m.startswith("_")}
            offenders = [m for m in methods for word in FORBIDDEN_OPERATIONS if word in m.lower()]
            assert offenders == [], (name, offenders)

    def test_the_transport_module_holds_no_governance_vocabulary(self) -> None:
        """Structural sweep over the code, docstrings blanked -- they state the boundary,
        and the boundary is what must not appear in what runs."""
        tree = ast.parse(
            pathlib.Path("src/aegis/a2a/remote/transport.py").read_text(encoding="utf-8")
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                node.value.value = ""
        code = ast.unparse(tree).lower()
        for word in ("authoriz", "approve", "policy", "verification", "lifecycle", "gate"):
            assert word not in code, word

    def test_the_transport_holds_no_key(self) -> None:
        """An intermediary that could sign would not be an intermediary, it would be a
        peer. Structural: the module imports nothing that can produce a signature."""
        tree = ast.parse(
            pathlib.Path("src/aegis/a2a/remote/transport.py").read_text(encoding="utf-8")
        )
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        assert not any("keys" in name or "identity" in name for name in imported), imported


class TestThereIsNoNetwork:
    def test_the_a2a_package_cannot_import_a_socket(self) -> None:
        """Not a promise -- a property of the source tree. ``tests/a2a/test_failures.py``
        already bans these imports across the whole package, and the remote subpackage is
        swept by the same rule; this asserts it here too so the claim is greppable from the
        file that makes it."""
        for path in sorted(pathlib.Path("src/aegis/a2a/remote").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    names.add((node.module or "").split(".")[0])
                elif isinstance(node, ast.Import):
                    names.update(alias.name.split(".")[0] for alias in node.names)
            assert not (
                names & {"socket", "http", "httpx", "requests", "urllib", "aiohttp", "ssl"}
            ), path.name

    def test_the_transport_has_no_clock_and_no_randomness(self) -> None:
        """Reproducible: two runs produce the same report."""
        tree = ast.parse(
            pathlib.Path("src/aegis/a2a/remote/transport.py").read_text(encoding="utf-8")
        )
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names.add((node.module or "").split(".")[0])
            elif isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
        assert not (names & {"random", "time", "secrets", "datetime"}), names


class TestOrdinaryDelivery:
    def test_a_frame_reaches_its_destination(self, remote_transport, peer_broker, signer):
        frame = frame_for(signer("commander", issue(peer_broker)))
        remote_transport.send(frame)
        assert remote_transport.receive("diagnostic") == (frame,)

    def test_delivery_is_to_the_exact_destination(self, remote_transport, peer_broker, signer):
        remote_transport.send(frame_for(signer("commander", issue(peer_broker))))
        assert remote_transport.receive("diagnostic ") == ()
        assert remote_transport.receive("Diagnostic") == ()
        assert remote_transport.receive("diag") == ()

    def test_acknowledging_clears_the_inbox(self, remote_transport, peer_broker, signer):
        frame = frame_for(signer("commander", issue(peer_broker)))
        remote_transport.send(frame)
        remote_transport.acknowledge(frame_digest(frame))
        assert remote_transport.receive("diagnostic") == ()

    def test_rejecting_clears_the_inbox_and_records_why(
        self, remote_transport, peer_broker, signer
    ):
        frame = frame_for(signer("commander", issue(peer_broker)))
        remote_transport.send(frame)
        remote_transport.reject(
            frame_digest(frame), RemoteVerdict.refuse(RemoteRejection.SIGNATURE_INVALID, "no")
        )
        assert remote_transport.receive("diagnostic") == ()
        assert remote_transport.rejected == (
            (frame_digest(frame), RemoteRejection.SIGNATURE_INVALID),
        )

    def test_carried_frames_are_kept_for_inspection(
        self, remote_transport, peer_broker, signer
    ) -> None:
        """So an evaluator can verify signatures itself instead of asking the boundary
        whether it verified them."""
        frame = frame_for(signer("commander", issue(peer_broker)))
        remote_transport.send(frame)
        assert remote_transport.carried == (frame,)


class TestEveryFaultFailsClosed:
    @pytest.mark.parametrize(
        "fault", [RemoteFault.LOSS, RemoteFault.TIMEOUT, RemoteFault.PEER_UNAVAILABLE]
    )
    def test_a_failed_send_raises_rather_than_returning(self, peer_broker, signer, fault) -> None:
        """A transport that dropped a frame and returned normally would be telling the
        sender a message arrived when it did not, and every layer above would reason from a
        lie. Silence is a worse failure mode than an error."""
        transport = InMemoryRemoteTransport(fault=fault)
        with pytest.raises(RemoteTransportError):
            transport.send(frame_for(signer("commander", issue(peer_broker))))

    @pytest.mark.parametrize(
        "fault", [RemoteFault.LOSS, RemoteFault.TIMEOUT, RemoteFault.PEER_UNAVAILABLE]
    )
    def test_a_failed_send_delivers_nothing(self, peer_broker, signer, fault) -> None:
        transport = InMemoryRemoteTransport(fault=fault)
        with pytest.raises(RemoteTransportError):
            transport.send(frame_for(signer("commander", issue(peer_broker))))
        assert transport.receive("diagnostic") == ()
        assert transport.carried == ()

    def test_an_unreachable_destination_raises(self, peer_broker, signer) -> None:
        transport = InMemoryRemoteTransport(unavailable=frozenset({"diagnostic"}))
        with pytest.raises(RemoteTransportError, match="unreachable"):
            transport.send(frame_for(signer("commander", issue(peer_broker))))

    def test_a_transport_failure_becomes_a_refusal_never_an_empty_message(
        self, gateway, peer_broker, signer, keys
    ) -> None:
        """Part 12's central requirement. A message that was lost and a message that said
        nothing are different facts."""
        from aegis.a2a.remote import RemoteChannel

        gateway.transport = InMemoryRemoteTransport(fault=RemoteFault.LOSS)
        ring, by_agent, _ = keys
        channel = RemoteChannel(gateway, ring, by_agent)
        delivery = channel.carry(
            issue(peer_broker),
            signed_by="commander",
            as_agent="diagnostic",
            expected_incident_id=INCIDENT,
        )
        assert not delivery.authenticated
        assert delivery.verdict.rejection is RemoteRejection.TRANSPORT_FAILURE
        assert delivery.envelope is None
        assert delivery.local is None

    def test_no_transport_failure_produces_an_admission(
        self, gateway, peer_broker, signer, keys
    ) -> None:
        from aegis.a2a.remote import RemoteChannel

        ring, by_agent, _ = keys
        for fault in RemoteFault:
            gateway.transport = InMemoryRemoteTransport(fault=fault)
            channel = RemoteChannel(gateway, ring, by_agent)
            delivery = channel.carry(
                issue(peer_broker, task_id=f"task-{fault.value}"),
                signed_by="commander",
                as_agent="diagnostic",
                expected_incident_id=INCIDENT,
            )
            if fault in {RemoteFault.LOSS, RemoteFault.TIMEOUT, RemoteFault.PEER_UNAVAILABLE}:
                assert not delivery.admitted, fault


class TestTheDeterministicFaults:
    def test_a_delayed_frame_arrives_late_not_never(self, peer_broker, signer) -> None:
        transport = InMemoryRemoteTransport(fault=RemoteFault.DELAY)
        frame = frame_for(signer("commander", issue(peer_broker)))
        transport.send(frame)
        assert transport.pending() == 1
        assert transport.receive("diagnostic") == (frame,)

    def test_a_duplicated_frame_arrives_twice(self, peer_broker, signer) -> None:
        transport = InMemoryRemoteTransport(fault=RemoteFault.DUPLICATE)
        frame = frame_for(signer("commander", issue(peer_broker)))
        transport.send(frame)
        assert transport.receive("diagnostic") == (frame, frame)

    def test_reordering_reverses_arrival_order(self, peer_broker, signer) -> None:
        transport = InMemoryRemoteTransport(fault=RemoteFault.REORDER)
        first = frame_for(signer("commander", issue(peer_broker, task_id="t1")))
        second = frame_for(signer("commander", issue(peer_broker, task_id="t2")))
        transport.send(first)
        transport.send(second)
        assert transport.receive("diagnostic") == (second, first)

    def test_the_faults_are_deterministic(self, peer_broker, signer) -> None:
        """Two transports, same fault, same frames, same result. A benchmark whose faults
        varied between runs would not be a benchmark."""
        frame = frame_for(signer("commander", issue(peer_broker)))
        outcomes = []
        for _ in range(2):
            transport = InMemoryRemoteTransport(fault=RemoteFault.DUPLICATE)
            transport.send(frame)
            outcomes.append(transport.receive("diagnostic"))
        assert outcomes[0] == outcomes[1]

    def test_only_network_conditions_ship_in_the_product(self) -> None:
        """Adversarial rewriting is not a property of a network -- it is the act of an
        attacker, and an attacker is a benchmark control group, not a method on the
        transport."""
        members = {member.name for member in RemoteFault}
        assert members == {
            "NONE",
            "DELAY",
            "DUPLICATE",
            "REORDER",
            "LOSS",
            "TIMEOUT",
            "PEER_UNAVAILABLE",
        }
        for word in ("TAMPER", "FORGE", "REDIRECT", "DOWNGRADE", "STRIP", "REPLAY"):
            assert word not in members


class TestTheRelaySeam:
    def test_a_relay_can_drop(self, peer_broker, signer) -> None:
        transport = InMemoryRemoteTransport(relay=lambda _: ())
        transport.send(frame_for(signer("commander", issue(peer_broker))))
        assert transport.receive("diagnostic") == ()

    def test_a_relay_can_duplicate(self, peer_broker, signer) -> None:
        transport = InMemoryRemoteTransport(relay=lambda frame: (frame, frame))
        transport.send(frame_for(signer("commander", issue(peer_broker))))
        assert len(transport.receive("diagnostic")) == 2

    def test_a_relay_can_rewrite(self, peer_broker, signer) -> None:
        transport = InMemoryRemoteTransport(
            relay=lambda frame: (frame.model_copy(update={"body": "{}"}),)
        )
        transport.send(frame_for(signer("commander", issue(peer_broker))))
        assert transport.receive("diagnostic")[0].body == "{}"

    def test_a_relay_can_readdress(self, peer_broker, signer) -> None:
        transport = InMemoryRemoteTransport(
            relay=lambda frame: (frame.model_copy(update={"destination": "security"}),)
        )
        transport.send(frame_for(signer("commander", issue(peer_broker))))
        assert transport.receive("diagnostic") == ()
        assert len(transport.receive("security")) == 1

    def test_what_the_relay_produced_is_what_is_recorded_as_carried(
        self, peer_broker, signer
    ) -> None:
        """The frames *after* any relay, so a tampered frame appears in its tampered form
        and an evaluator sees what the receiver saw."""
        transport = InMemoryRemoteTransport(
            relay=lambda frame: (frame.model_copy(update={"body": "{}"}),)
        )
        transport.send(frame_for(signer("commander", issue(peer_broker))))
        assert transport.carried[0].body == "{}"


class TestFramesAndHops:
    def test_forwarding_records_the_route_without_touching_the_body(
        self, peer_broker, signer
    ) -> None:
        frame = frame_for(signer("commander", issue(peer_broker)))
        forwarded = frame.forwarded("relay-a")
        assert forwarded.route == ("relay-a",)
        assert forwarded.body == frame.body

    def test_a_frame_is_frozen(self, peer_broker, signer) -> None:
        frame = frame_for(signer("commander", issue(peer_broker)))
        with pytest.raises(ValueError):
            frame.destination = "security"

    def test_an_oversized_body_cannot_be_constructed(self) -> None:
        from aegis.a2a.remote import MAX_REMOTE_FRAME_BYTES

        with pytest.raises(ValueError):
            RemoteFrame(destination="diagnostic", body="x" * (MAX_REMOTE_FRAME_BYTES + 1))


def test_there_is_no_retry_in_the_remote_package() -> None:
    """Retry is the Commander deciding to delegate again, costing a step from the same
    bounded budget every other decision costs one from. A second retry mechanism here would
    be a second budget nobody configured."""
    for path in sorted(pathlib.Path("src/aegis/a2a/remote").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            assert not isinstance(node, ast.While), f"{path.name} contains a while loop"
            if isinstance(node, ast.FunctionDef):
                assert "retry" not in node.name.lower(), f"{path.name}:{node.name}"
