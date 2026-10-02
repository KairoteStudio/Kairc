#!/usr/bin/env python3

import select
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


SECRET = "7d" * 32
IDENTITY_A = "1a" * 32
IDENTITY_B = "1b" * 32
IDENTITY_D = "1d" * 32
PUBLIC_A = "64c30815ff26d5c4aff8e11274a38ed6dd0553049da4c10372a9575b7a776909"
ONION_B = "b" * 56 + ".onion"
MESSAGE = b"discovered onion peer survived bootstrap loss"


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


def receive_exact(connection, size):
    data = bytearray()
    while len(data) < size:
        block = connection.recv(size - len(data))
        if not block:
            raise OSError("truncated SOCKS5 request")
        data.extend(block)
    return bytes(data)


class LoopbackSocks5:
    def __init__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(64)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self._accept, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stopping.set()
        self.listener.close()
        self.thread.join(timeout=2)

    def _accept(self):
        while not self.stopping.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    def _handle(self, client):
        target = None
        try:
            client.settimeout(10)
            if receive_exact(client, 3) != b"\x05\x01\x00":
                return
            client.sendall(b"\x05\x00")
            header = receive_exact(client, 5)
            if header[:4] != b"\x05\x01\x00\x03":
                return
            receive_exact(client, header[4])  # Remote onion hostname; never resolve locally.
            port = int.from_bytes(receive_exact(client, 2), "big")
            target = socket.create_connection(("127.0.0.1", port), timeout=5)
            client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            client.settimeout(None)
            target.settimeout(None)
            sockets = [client, target]
            while not self.stopping.is_set():
                readable, _, _ = select.select(sockets, [], [], 0.2)
                for source in readable:
                    block = source.recv(65536)
                    if not block:
                        return
                    destination = target if source is client else client
                    destination.sendall(block)
        except OSError:
            pass
        finally:
            client.close()
            if target is not None:
                target.close()


def write_config(
    path,
    irc_port,
    database,
    identity_seed,
    proxy_port,
    p2p_port=None,
    bootstrap_port=None,
    bootstrap_identity=None,
    advertised_port=None,
):
    lines = [
        f"irc_listen = 127.0.0.1:{irc_port}",
        f"p2p_listen = {'127.0.0.1:' + str(p2p_port) if p2p_port else ''}",
        f"tor_proxy = 127.0.0.1:{proxy_port}",
        f"p2p_identity_seed = {identity_seed}",
        "allow_unknown_inbound = true",
        "allow_unknown_outbound = false",
        "peer_discovery = open",
    ]
    if bootstrap_port:
        lines.append(
            f"bootstrap_peer = {bootstrap_identity}@tcp://127.0.0.1:{bootstrap_port}"
        )
    if advertised_port:
        lines.append(f"advertise_peer = tor://{ONION_B}:{advertised_port}")
    lines.extend(
        [
            f"database = {database}",
            "network_id = kairc-discovery-e2e",
            "work_bits = 4",
            "retention_hours = 24",
            "pending_limit = 64",
            "pending_per_peer_limit = 16",
            f"channel.#private = {SECRET}",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)


def wait_for_port(port, processes):
    deadline = time.monotonic() + 10
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


def wait_for_peer_record(database, processes):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError(f"kaircd exited early with status {process.returncode}")
        if database.exists():
            try:
                with sqlite3.connect(database) as connection:
                    count = connection.execute("SELECT count(*) FROM peer_records").fetchone()[0]
                if count:
                    return
            except sqlite3.Error:
                pass
        time.sleep(0.05)
    raise RuntimeError("signed peer record did not reach the bootstrap/discovery node")


def connect_irc(port, nickname):
    client = socket.create_connection(("127.0.0.1", port), timeout=3)
    client.sendall(
        f"NICK {nickname}\r\nUSER local 0 * :Local User\r\nJOIN #private\r\n".encode()
    )
    receive_until(client, b" 366 ")
    return client


def receive_until(client, marker, timeout=10):
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


def stop(process):
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=12)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: discovery_e2e.py /path/to/kaircd")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise RuntimeError(f"kaircd was not found at {binary}")

    proxy = LoopbackSocks5()
    proxy.start()
    with tempfile.TemporaryDirectory(prefix="kairc-discovery-e2e-") as directory_name:
        directory = Path(directory_name)
        irc_a, irc_b, irc_d, p2p_a, p2p_b = free_ports(5)
        database_a = directory / "a.db"
        database_b = directory / "b.db"
        database_d = directory / "d.db"
        config_a = directory / "a.conf"
        config_b = directory / "b.conf"
        config_d = directory / "d.conf"
        write_config(config_a, irc_a, database_a, IDENTITY_A, proxy.port, p2p_port=p2p_a)
        write_config(
            config_b,
            irc_b,
            database_b,
            IDENTITY_B,
            proxy.port,
            p2p_port=p2p_b,
            bootstrap_port=p2p_a,
            bootstrap_identity=PUBLIC_A,
            advertised_port=p2p_b,
        )
        write_config(
            config_d,
            irc_d,
            database_d,
            IDENTITY_D,
            proxy.port,
            bootstrap_port=p2p_a,
            bootstrap_identity=PUBLIC_A,
        )

        logs = [(directory / name).open("wb") for name in ("a.log", "b.log", "d.log")]
        processes = []
        bob = None
        dana = None
        try:
            processes.append(
                subprocess.Popen([binary, "--config", config_a], stdout=logs[0], stderr=logs[0])
            )
            wait_for_port(p2p_a, processes)
            processes.append(
                subprocess.Popen([binary, "--config", config_b], stdout=logs[1], stderr=logs[1])
            )
            wait_for_port(p2p_b, processes)
            wait_for_peer_record(database_a, processes)
            time.sleep(2)  # Let A verify B through its signed onion endpoint.

            processes.append(
                subprocess.Popen([binary, "--config", config_d], stdout=logs[2], stderr=logs[2])
            )
            wait_for_port(irc_b, processes)
            wait_for_port(irc_d, processes)
            wait_for_peer_record(database_d, processes)
            bob = connect_irc(irc_b, "bob")
            dana = connect_irc(irc_d, "dana")
            time.sleep(1)

            stop(processes[0])  # The bootstrap may disappear after discovery.
            dana.sendall(b"PRIVMSG #private :" + MESSAGE + b"\r\n")
            receive_until(bob, b"PRIVMSG #private :" + MESSAGE)
        finally:
            if bob is not None:
                bob.close()
            if dana is not None:
                dana.close()
            for process in reversed(processes):
                stop(process)
            for log in logs:
                log.close()
            proxy.stop()

        for process in processes:
            if process.returncode != 0:
                raise RuntimeError(f"kaircd stopped with status {process.returncode}")

    print("signed onion peer discovery integration test passed")


if __name__ == "__main__":
    main()
