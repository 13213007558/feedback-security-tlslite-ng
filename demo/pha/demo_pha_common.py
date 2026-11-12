"""
TLS 1.3 Post-Handshake Authentication (PHA) demo — shared helpers.

Everything runs over an in-memory socket.socketpair(), so no network ports
or real sockets are needed. Two OS threads play the server and the client.

tlslite-ng version target: 0.9.0b2 (the tree this demo lives in).
"""

import os
import socket
import threading
import time

from tlslite import TLSConnection, HandshakeSettings, X509CertChain
from tlslite.utils.keyfactory import parsePEMKey

_HERE = os.path.dirname(os.path.abspath(__file__))
_TEST_CERTS = os.path.normpath(os.path.join(_HERE, "..", "..", "tests"))


def _load_chain(name):
    chain = X509CertChain()
    with open(os.path.join(_TEST_CERTS, name), "r") as handle:
        chain.parsePemList(handle.read())
    return chain


def _load_key(name):
    with open(os.path.join(_TEST_CERTS, name), "r") as handle:
        return parsePEMKey(handle.read(), private=True)


SERVER_CHAIN = _load_chain("serverX509Cert.pem")
SERVER_KEY = _load_key("serverX509Key.pem")
CLIENT_CHAIN = _load_chain("clientX509Cert.pem")
CLIENT_KEY = _load_key("clientX509Key.pem")
# A second, distinct client identity used to demonstrate identity refresh.
CLIENT_CHAIN_EC = _load_chain("clientECCert.pem")
CLIENT_KEY_EC = _load_key("clientECKey.pem")
# Key that does NOT match CLIENT_CHAIN — used to provoke a bad CertificateVerify.
FOREIGN_KEY = _load_key("serverX509Key.pem")

TLS13 = HandshakeSettings()
TLS13.minVersion = (3, 4)
TLS13.maxVersion = (3, 4)


class Gate:
    """A tiny one-shot rendezvous so the two peers advance in a fixed order."""

    def __init__(self):
        self._event = threading.Event()

    def wait(self, timeout=10):
        if not self._event.wait(timeout):
            raise RuntimeError("gate timed out")

    def open(self):
        self._event.set()


class Log:
    def __init__(self, role):
        self.role = role

    def __call__(self, message):
        stamp = time.strftime("%H:%M:%S")
        millis = int((time.time() % 1) * 1000)
        print("[%s.%03d %-6s] %s" % (stamp, millis, self.role, message),
              flush=True)


def new_memory_pair():
    """Return (server_conn, client_conn) backed by one connected socketpair."""
    server_sock, client_sock = socket.socketpair()
    return TLSConnection(server_sock), TLSConnection(client_sock)


def run_in_thread(target):
    result = {"error": None}

    def wrapper():
        try:
            target()
        except Exception as exc:  # captured and re-raised by the caller
            result["error"] = exc

    thread = threading.Thread(target=wrapper, daemon=True)
    thread.start()
    return thread, result


def join(thread, result, timeout=10):
    thread.join(timeout)
    if thread.is_alive():
        raise RuntimeError("worker thread did not finish")
    if result["error"] is not None:
        raise result["error"]


def tls13_handshake(server_log, client_log, client_chain, client_key):
    """Anonymous server-side TLS 1.3 handshake; client advertises PHA support.

    The client only advertises the post_handshake_auth extension when it was
    given both a cert chain and a private key at handshake time
    (tlsconnection.py: if certParams and certParams[1]).  An empty
    X509CertChain() still counts, which is how the empty-cert demo opts in.
    """
    server_conn, client_conn = new_memory_pair()
    gate = Gate()

    def server():
        server_conn.handshakeServer(certChain=SERVER_CHAIN,
                                    privateKey=SERVER_KEY,
                                    settings=TLS13)
        server_log("handshake done; session.clientCertChain = %r"
                   % (server_conn.session.clientCertChain,))
        gate.wait()

    thread, result = run_in_thread(server)
    client_conn.handshakeClientCert(client_chain, client_key,
                                    settings=TLS13)
    client_log("handshake done (client side)")
    gate.open()
    join(thread, result)
    return server_conn, client_conn


def identity(conn):
    """Application-observable identity derived from the TLS session state."""
    chain = conn.session.clientCertChain
    if not chain or not chain.x509List:
        return "ANONYMOUS"
    return "cert:" + str(chain.x509List[0].getFingerprint())[:16]
