from __future__ import annotations

import argparse
import http.server
import socket
import ssl
import threading
import time
from collections.abc import Callable

import requests

FIXTURE_IP = "198.18.0.10"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"offline robinhood policy fixture\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _tcp_echo(port: int) -> None:
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen()
        while True:
            connection, _address = listener.accept()
            with connection:
                connection.sendall(b"fixture")


def _udp_echo(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("0.0.0.0", port))
        while True:
            payload, address = listener.recvfrom(4096)
            listener.sendto(payload or b"fixture", address)


def serve(cert: str, key: str) -> None:
    for target in (
        lambda: _tcp_echo(853),
        lambda: _tcp_echo(11434),
        lambda: _udp_echo(53),
        lambda: _udp_echo(443),
    ):
        threading.Thread(target=target, daemon=True).start()

    server = http.server.ThreadingHTTPServer(("0.0.0.0", 443), _Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def _must_fail(label: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except (OSError, requests.RequestException):
        return
    raise AssertionError(f"bypass unexpectedly succeeded: {label}")


def _direct_tcp(address: str, port: int) -> None:
    with socket.create_connection((address, port), timeout=1):
        pass


def _udp_round_trip(address: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        client.sendto(b"probe", (address, port))
        client.recvfrom(1024)


def probe(ca: str) -> None:
    response = requests.get("https://api.robinhood.com/health", timeout=5, verify=ca)
    response.raise_for_status()
    if response.text != "offline robinhood policy fixture\n":
        raise AssertionError("allowed fixture returned unexpected content")

    _must_fail("other host through proxy", lambda: requests.get("https://discord.com/", timeout=2))
    _must_fail("allowlist suffix", lambda: requests.get("https://api.robinhood.com.evil.invalid/", timeout=2))
    _must_fail("unreviewed subdomain", lambda: requests.get("https://unreviewed.api.robinhood.com/", timeout=2))
    _must_fail("DoH host through proxy", lambda: requests.get("https://cloudflare-dns.com/dns-query", timeout=2))
    _must_fail("numeric CONNECT target", lambda: requests.get(f"https://{FIXTURE_IP}/", timeout=2, verify=False))
    _must_fail("direct raw-IP TLS", lambda: _direct_tcp(FIXTURE_IP, 443))
    _must_fail("direct host/LAN gateway", lambda: _direct_tcp("198.18.0.1", 443))
    _must_fail("metadata", lambda: _direct_tcp("169.254.169.254", 80))
    _must_fail("Ollama", lambda: _direct_tcp(FIXTURE_IP, 11434))
    _must_fail("DoT", lambda: _direct_tcp(FIXTURE_IP, 853))
    _must_fail("DNS", lambda: _udp_round_trip(FIXTURE_IP, 53))
    _must_fail("QUIC", lambda: _udp_round_trip(FIXTURE_IP, 443))
    print("offline egress probes passed", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
    server = subparsers.add_parser("serve")
    server.add_argument("--cert", required=True)
    server.add_argument("--key", required=True)
    client = subparsers.add_parser("probe")
    client.add_argument("--ca", required=True)
    args = parser.parse_args()
    if args.mode == "serve":
        serve(args.cert, args.key)
    else:
        time.sleep(1)
        probe(args.ca)


if __name__ == "__main__":
    main()
