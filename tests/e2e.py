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
SECRET = "8f8db4ed205336260ce773a6bbf8a951457e22e830c3ffd78db54ace0c787abe"


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


def connect_irc(port, nickname):
    client = socket.create_connection(("127.0.0.1", port), timeout=3)
    client.sendall(
        f"NICK {nickname}\r\nUSER local-user 0 * :Private Real Name\r\n"
        "JOIN #private\r\n".encode()
    )
    receive_until(client, b" 366 ")
    return client


def write_config(path, irc_port, database, p2p_port=None, peer_port=None):
    lines = [
        f"irc_listen = 127.0.0.1:{irc_port}",
        f"p2p_listen = {'127.0.0.1:' + str(p2p_port) if p2p_port else ''}",
        "tor_proxy =",
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


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: e2e.py /path/to/kaircd")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise RuntimeError(f"kaircd was not found at {binary}")

    with tempfile.TemporaryDirectory(prefix="kairc-e2e-") as directory_name:
        directory = Path(directory_name)
        irc_a, irc_b, p2p = free_ports(3)
        config_a, config_b = directory / "a.conf", directory / "b.conf"
        database_a, database_b = directory / "a.db", directory / "b.db"
        write_config(config_a, irc_a, database_a, p2p_port=p2p)
        write_config(config_b, irc_b, database_b, peer_port=p2p)
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
        processes = []
        alice = None
        bob = None
        try:
            processes.append(
                subprocess.Popen([binary, "--config", config_a], stdout=log_a, stderr=log_a)
            )
            processes.append(
                subprocess.Popen([binary, "--config", config_b], stdout=log_b, stderr=log_b)
            )
            wait_for_port(irc_a, processes)
            wait_for_port(irc_b, processes)
            alice = connect_irc(irc_a, "alice")
            bob = connect_irc(irc_b, "bob")
            time.sleep(0.25)
            alice.sendall(b"PRIVMSG #private :" + MESSAGE + b"\r\n")
            received = receive_until(bob, b"PRIVMSG #private :" + MESSAGE)
            if b"local-user" in received or b"Private Real Name" in received:
                raise RuntimeError("IRC USER metadata crossed the P2P boundary")
        finally:
            if alice is not None:
                alice.close()
            if bob is not None:
                bob.close()
            for process in reversed(processes):
                stop(process)
            log_a.close()
            log_b.close()

        for process in processes:
            if process.returncode != 0:
                raise RuntimeError(f"kaircd stopped with status {process.returncode}")
        assert_database(database_a)
        assert_database(database_b)

    print("two-node encrypted P2P IRC integration test passed")


if __name__ == "__main__":
    main()
