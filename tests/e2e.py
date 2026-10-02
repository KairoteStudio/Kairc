#!/usr/bin/env python3

import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path


MESSAGE = b"kairc private e2e marker"
UNTRUSTED_MESSAGE = b"untrusted peer isolation marker"
SECRET = "8f8db4ed205336260ce773a6bbf8a951457e22e830c3ffd78db54ace0c787abe"
IDENTITY_A = "0a" * 32
IDENTITY_B = "0b" * 32
PUBLIC_A = "43a72e714401762df66b68c26dfbdf2682aaec9f2474eca4613e424a0fbafd3c"
PUBLIC_B = "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a"
IDENTITY_C = "0c" * 32


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def free_ports(count):
    ports = []
    while len(ports) < count:
        port = free_port()
        if port not in ports:
            ports.append(port)
    return ports


def wait_for_port(port, processes):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError(f"kaircd exited early with status {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port {port} did not become ready")


def receive_until(client, marker, timeout=8):
    client.settimeout(0.5)
    received = bytearray()
    deadline = time.monotonic() + timeout
    while marker not in received and time.monotonic() < deadline:
        try:
            block = client.recv(4096)
        except TimeoutError:
            continue
        if not block:
            break
        received.extend(block)
    if marker not in received:
        raise RuntimeError(f"IRC response did not contain {marker!r}: {bytes(received)!r}")
    return bytes(received)


def receive_for(client, duration):
    client.settimeout(0.1)
    received = bytearray()
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        try:
            block = client.recv(4096)
        except TimeoutError:
            continue
        if not block:
            break
        received.extend(block)
    return bytes(received)


def connect_irc(port, nickname, history_marker=None):
    client = socket.create_connection(("127.0.0.1", port), timeout=3)
    client.sendall(
        "CAP LS 302\r\n"
        "CAP REQ :message-tags server-time batch\r\n"
        f"NICK {nickname}\r\nUSER local-user 0 * :Private Real Name\r\nCAP END\r\n"
        "JOIN #private\r\n".encode()
    )
    received = receive_until(client, history_marker or b" 366 ")
    return client, received


def write_config(
    path, irc_port, database, identity_seed, trusted_peer, p2p_port=None, peer_port=None
):
    lines = [
        f"irc_listen = 127.0.0.1:{irc_port}",
        f"p2p_listen = {'127.0.0.1:' + str(p2p_port) if p2p_port else ''}",
        "tor_proxy =",
        f"p2p_identity_seed = {identity_seed}",
        f"trusted_peer = {trusted_peer}",
        "allow_unknown_inbound = false",
        "allow_unknown_outbound = false",
    ]
    if peer_port:
        lines.append(f"peer = tcp://127.0.0.1:{peer_port}")
    lines.extend(
        [
            f"database = {database}",
            "network_id = kairc-e2e",
            "work_bits = 4",
            "retention_hours = 24",
            "pending_limit = 64",
            "pending_per_peer_limit = 16",
            f"channel.#private = {SECRET}",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)


def stop(process):
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def assert_database(path):
    if path.stat().st_mode & 0o077:
        raise RuntimeError(f"database permissions are not private: {oct(path.stat().st_mode)}")
    with sqlite3.connect(path) as database:
        count = database.execute("SELECT count(*) FROM events").fetchone()[0]
        if count < 1:
            raise RuntimeError(f"no replicated event was stored in {path}")
        rows = database.execute("SELECT raw FROM events").fetchall()
    forbidden = (MESSAGE, b"local-user", b"Private Real Name")
    for (raw,) in rows:
        for marker in forbidden:
            if marker in raw:
                raise RuntimeError(f"private material {marker!r} appeared in {path}")


def event_ids(path):
    with sqlite3.connect(path) as database:
        return {row[0] for row in database.execute("SELECT hex(id) FROM events")}


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: e2e.py /path/to/kaircd")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise RuntimeError(f"kaircd was not found at {binary}")

    with tempfile.TemporaryDirectory(prefix="kairc-e2e-") as directory_name:
        directory = Path(directory_name)
        irc_a, irc_b, irc_c, p2p = free_ports(4)
        config_a, config_b, config_c = directory / "a.conf", directory / "b.conf", directory / "c.conf"
        database_a, database_b, database_c = directory / "a.db", directory / "b.db", directory / "c.db"
        write_config(config_a, irc_a, database_a, IDENTITY_A, PUBLIC_B, p2p_port=p2p)
        write_config(config_b, irc_b, database_b, IDENTITY_B, PUBLIC_A, peer_port=p2p)
        # C trusts A, but A deliberately does not trust C. Its signed handshake
        # must never be promoted into an established session.
        write_config(config_c, irc_c, database_c, IDENTITY_C, PUBLIC_A, peer_port=p2p)
        insecure_config = directory / "insecure.conf"
        insecure_config.write_text(config_a.read_text(encoding="utf-8"), encoding="utf-8")
        insecure_config.chmod(0o644)
        insecure_check = subprocess.run(
            [binary, "--config", insecure_config, "--check-config"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if insecure_check.returncode == 0:
            raise RuntimeError("group-readable private-channel configuration was accepted")

        log_a = (directory / "a.log").open("wb")
        log_b = (directory / "b.log").open("wb")
        log_c = (directory / "c.log").open("wb")
        processes = []
        alice = None
        bob = None
        charlie = None
        dave = None
        slow_handshakes = []
        try:
            processes.append(
                subprocess.Popen([binary, "--config", config_a], stdout=log_a, stderr=log_a)
            )
            wait_for_port(p2p, processes)
            # Silent TCP clients stay in the bounded, non-blocking hello queue;
            # they must not occupy all authenticated handshake workers.
            for _ in range(256):
                slow_handshakes.append(
                    socket.create_connection(("127.0.0.1", p2p), timeout=1)
                )
            processes.append(
                subprocess.Popen([binary, "--config", config_b], stdout=log_b, stderr=log_b)
            )
            processes.append(
                subprocess.Popen([binary, "--config", config_c], stdout=log_c, stderr=log_c)
            )
            wait_for_port(irc_a, processes)
            wait_for_port(irc_b, processes)
            wait_for_port(irc_c, processes)
            alice, _ = connect_irc(irc_a, "alice")
            bob, _ = connect_irc(irc_b, "bob")
            dave, _ = connect_irc(irc_c, "dave")
            time.sleep(0.25)
            alice.sendall(b"PRIVMSG #private :" + MESSAGE + b"\r\n")
            received = receive_until(bob, b"PRIVMSG #private :" + MESSAGE)
            if b"@time=" not in received:
                raise RuntimeError("live replicated message had no IRCv3 server-time tag")
            if b"local-user" in received or b"Private Real Name" in received:
                raise RuntimeError("IRC USER metadata crossed the P2P boundary")
            charlie, replay = connect_irc(irc_b, "charlie", MESSAGE)
            required_replay_markers = (
                b" BATCH +",
                b" kairc/replay #private",
                b"@batch=",
                b";time=",
                b";kairc.io/replay=1 ",
            )
            for marker in required_replay_markers:
                if marker not in replay:
                    raise RuntimeError(
                        f"canonical history replay omitted {marker!r}: {replay!r}"
                    )
            dave.sendall(b"PRIVMSG #private :" + UNTRUSTED_MESSAGE + b"\r\n")
            if UNTRUSTED_MESSAGE in receive_for(alice, 1.0):
                raise RuntimeError("an untrusted peer identity crossed the P2P allowlist")
        finally:
            if alice is not None:
                alice.close()
            if bob is not None:
                bob.close()
            if charlie is not None:
                charlie.close()
            if dave is not None:
                dave.close()
            for slow_handshake in slow_handshakes:
                slow_handshake.close()
            for process in reversed(processes):
                stop(process)
            log_a.close()
            log_b.close()
            log_c.close()

        for process in processes:
            if process.returncode != 0:
                raise RuntimeError(f"kaircd stopped with status {process.returncode}")
        assert_database(database_a)
        assert_database(database_b)
        assert_database(database_c)
        ids_a = event_ids(database_a)
        ids_b = event_ids(database_b)
        ids_c = event_ids(database_c)
        if ids_a != ids_b or ids_a & ids_c:
            raise RuntimeError("trusted peers did not converge or an untrusted event replicated")

    print("three-node authenticated P2P IRC integration test passed")


if __name__ == "__main__":
    main()
