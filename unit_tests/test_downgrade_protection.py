# Copyright (c) 2026
#
# See the LICENSE file for legal information regarding use of this file.

"""End-to-end checks for the two independent downgrade defences.

These tests use only ``socket.socketpair`` (in-memory transport, no network
or bound ports) and the test certificates shipped under ``tests/``.

Covered mechanisms:

* TLS_FALLBACK_SCSV (RFC 7507): server-side check in
  :meth:`TLSConnection._serverGetClientHello`.
* TLS 1.3 ServerHello.random downgrade sentinels (RFC 8446 section 4.1.3):
  server-side placement and client-side verification in
  :mod:`tlslite.tlsconnection`.
* ``minVersion`` enforcement (protocol_version alerts).
"""

import os
import select
import socket
import struct
import threading

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.api import X509, X509CertChain, parsePEMKey, TLSConnection, \
    HandshakeSettings
from tlslite.constants import AlertDescription, ContentType, CipherSuite, \
    ExtensionType, HandshakeType, TLS_1_1_DOWNGRADE_SENTINEL, \
    TLS_1_2_DOWNGRADE_SENTINEL
from tlslite.messages import ClientHello
from tlslite.utils.codec import Parser

TESTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         os.pardir, "tests")


def _load_credentials():
    with open(os.path.join(TESTS_DIR, "serverX509Cert.pem")) as f:
        cert = X509CertChain([X509().parse(f.read())])
    with open(os.path.join(TESTS_DIR, "serverX509Key.pem")) as f:
        key = parsePEMKey(f.read(), private=True)
    return cert, key


CERT_CHAIN, PRIVATE_KEY = _load_credentials()


def _run_handshake(client_settings, server_settings, mitm=None):
    """Run one in-memory handshake and return (client_result, server_result).

    Each result is either ``("ok", negotiated_version, server_random_tail)``
    or ``("error", alert_description_or_class_name)``.
    """
    client_sock, mitm_client = socket.socketpair()
    if mitm is None:
        server_sock = mitm_client
        mitm_server = None
    else:
        mitm_server, server_sock = socket.socketpair()

    for sock in (client_sock, mitm_client, mitm_server, server_sock):
        if sock is not None:
            sock.settimeout(5)

    server_result = {}

    def server_worker():
        conn = TLSConnection(server_sock)
        try:
            conn.handshakeServer(certChain=CERT_CHAIN,
                                 privateKey=PRIVATE_KEY,
                                 settings=server_settings)
            server_result["ok"] = (conn.version,
                                   bytes(conn._serverRandom[-8:]))
            conn.close()
        except Exception as e:  # pylint: disable=broad-except
            server_result["error"] = e

    threads = [threading.Thread(target=server_worker)]

    if mitm is not None:
        def mitm_worker():
            try:
                mitm(mitm_client, mitm_server)
            except Exception as e:  # pylint: disable=broad-except
                server_result.setdefault("mitm_error", e)

        threads.append(threading.Thread(target=mitm_worker))

    for thread in threads:
        thread.start()

    client_result = {}
    client_conn = TLSConnection(client_sock)
    try:
        client_conn.handshakeClientCert(settings=client_settings)
        client_result["ok"] = client_conn.version
        client_conn.close()
    except Exception as e:  # pylint: disable=broad-except
        client_result["error"] = e

    for thread in threads:
        thread.join(10)

    for sock in (client_sock, mitm_client, mitm_server, server_sock):
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def normalise(result):
        if "ok" in result:
            return ("ok", result["ok"])
        exc = result["error"]
        description = getattr(exc, "description", type(exc).__name__)
        return ("error", description)

    return normalise(client_result), normalise(server_result)


def _recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


def _read_record(sock):
    header = _recv_exact(sock, 5)
    content_type, major, minor, length = struct.unpack(">BBBH", header)
    body = _recv_exact(sock, length)
    return content_type, (major, minor), body


def _build_record(content_type, version, body):
    return struct.pack(">BBBH", content_type, version[0], version[1],
                       len(body)) + body


def downgrade_mitm(legacy_version):
    """Return a MITM callback that strips TLS 1.3 negotiation from ClientHello.

    It rewrites the legacy client_version, removes the supported_versions and
    other TLS 1.3-only extensions and clears the middlebox-compatibility
    session id, so a TLS 1.3 server falls back to a legacy negotiation and
    (per RFC 8446) stamps a downgrade sentinel.
    """
    def callback(client_side, server_side):
        content_type, _, body = _read_record(client_side)
        assert content_type == ContentType.handshake
        assert body[0] == HandshakeType.client_hello
        hello_len = struct.unpack(">I", b"\x00" + body[1:4])[0]
        hello = ClientHello().parse(Parser(bytearray(body[1:1 + 3 + hello_len])))
        hello.client_version = legacy_version
        tls13_only = {ExtensionType.supported_versions,
                      ExtensionType.key_share,
                      ExtensionType.psk_key_exchange_modes,
                      ExtensionType.pre_shared_key}
        hello.extensions = [ext for ext in (hello.extensions or [])
                            if ext.extType not in tls13_only] or None
        hello.session_id = bytearray(0)
        server_side.sendall(
            _build_record(ContentType.handshake, (3, 1),
                          bytes(hello.write())))
        client_side.setblocking(False)
        server_side.setblocking(False)
        while True:
            readable, _, _ = select.select([client_side, server_side],
                                           [], [], 5)
            if not readable:
                break
            closed = False
            for sock in readable:
                try:
                    data = sock.recv(65536)
                except BlockingIOError:
                    continue
                if not data:
                    closed = True
                    break
                peer = server_side if sock is client_side else client_side
                peer.sendall(data)
            if closed:
                break

    return callback


class TestNormalNegotiation(unittest.TestCase):
    def test_tls13_normal(self):
        client, server = _run_handshake(HandshakeSettings(),
                                        HandshakeSettings())
        self.assertEqual(client, ("ok", (3, 4)))
        self.assertEqual(server[0], "ok")
        self.assertEqual(server[1][0], (3, 4))

    def test_genuine_legacy_client_tls12_is_not_an_attack(self):
        client_settings = HandshakeSettings()
        client_settings.maxVersion = (3, 3)
        server_settings = HandshakeSettings()
        client, server = _run_handshake(client_settings, server_settings)
        # Negotiated TLS 1.2 with a client that never supported 1.3.
        self.assertEqual(client, ("ok", (3, 3)))
        self.assertEqual(server[1][0], (3, 3))
        # Server stamps the 01 sentinel only because it itself supports 1.3;
        # a max-1.2 client does not evaluate it.
        self.assertEqual(server[1][1], bytes(TLS_1_2_DOWNGRADE_SENTINEL))

    def test_genuine_legacy_client_tls11_is_not_an_attack(self):
        client_settings = HandshakeSettings()
        client_settings.maxVersion = (3, 2)
        server_settings = HandshakeSettings()
        server_settings.maxVersion = (3, 3)
        client, server = _run_handshake(client_settings, server_settings)
        self.assertEqual(client, ("ok", (3, 2)))
        self.assertEqual(server[1][0], (3, 2))
        self.assertEqual(server[1][1], bytes(TLS_1_1_DOWNGRADE_SENTINEL))

    def test_legacy_only_server_with_matching_client(self):
        client_settings = HandshakeSettings()
        client_settings.maxVersion = (3, 3)
        server_settings = HandshakeSettings()
        server_settings.maxVersion = (3, 3)
        client, server = _run_handshake(client_settings, server_settings)
        self.assertEqual(client, ("ok", (3, 3)))
        # A server that does not support 1.3 has nothing to signal.
        self.assertNotEqual(server[1][1],
                            bytes(TLS_1_2_DOWNGRADE_SENTINEL))


class TestFallbackSCSV(unittest.TestCase):
    def test_scsv_on_1_3_capable_peers_is_allowed(self):
        client_settings = HandshakeSettings()
        client_settings.sendFallbackSCSV = True
        client, server = _run_handshake(client_settings,
                                        HandshakeSettings())
        self.assertEqual(client, ("ok", (3, 4)))
        self.assertEqual(server[1][0], (3, 4))

    def test_scsv_marks_inappropriate_fallback_to_tls12(self):
        client_settings = HandshakeSettings()
        client_settings.maxVersion = (3, 3)
        client_settings.sendFallbackSCSV = True
        client, server = _run_handshake(client_settings,
                                        HandshakeSettings())
        self.assertEqual(client,
                         ("error", AlertDescription.inappropriate_fallback))
        self.assertEqual(server,
                         ("error", AlertDescription.inappropriate_fallback))

    def test_scsv_marks_inappropriate_fallback_to_tls11(self):
        client_settings = HandshakeSettings()
        client_settings.maxVersion = (3, 2)
        client_settings.sendFallbackSCSV = True
        server_settings = HandshakeSettings()
        server_settings.maxVersion = (3, 3)
        client, server = _run_handshake(client_settings, server_settings)
        self.assertEqual(client,
                         ("error", AlertDescription.inappropriate_fallback))
        self.assertEqual(server,
                         ("error", AlertDescription.inappropriate_fallback))

    def test_without_scsv_legacy_client_is_served(self):
        client_settings = HandshakeSettings()
        client_settings.maxVersion = (3, 2)
        server_settings = HandshakeSettings()
        server_settings.maxVersion = (3, 3)
        client, server = _run_handshake(client_settings, server_settings)
        self.assertEqual(client, ("ok", (3, 2)))
        self.assertEqual(server[1][0], (3, 2))


class TestDowngradeSentinels(unittest.TestCase):
    def test_1_3_client_rejects_forced_tls12(self):
        client, server = _run_handshake(
            HandshakeSettings(), HandshakeSettings(),
            mitm=downgrade_mitm((3, 3)))
        self.assertEqual(client,
                         ("error", AlertDescription.illegal_parameter))
        self.assertEqual(server,
                         ("error", AlertDescription.illegal_parameter))

    def test_1_3_client_rejects_forced_tls11(self):
        client, server = _run_handshake(
            HandshakeSettings(), HandshakeSettings(),
            mitm=downgrade_mitm((3, 2)))
        self.assertEqual(client,
                         ("error", AlertDescription.illegal_parameter))
        self.assertEqual(server,
                         ("error", AlertDescription.illegal_parameter))

    def test_sentinel_values_match_rfc8446(self):
        self.assertEqual(bytes(TLS_1_1_DOWNGRADE_SENTINEL),
                         b"\x44\x4f\x57\x4e\x47\x52\x44\x00")
        self.assertEqual(bytes(TLS_1_2_DOWNGRADE_SENTINEL),
                         b"\x44\x4f\x57\x4e\x47\x52\x44\x01")


class TestMinimumVersion(unittest.TestCase):
    def _raw_legacy_hello_alert(self, legacy_version, server_min):
        client_sock, server_sock = socket.socketpair()
        client_sock.settimeout(5)
        server_sock.settimeout(5)
        result = {}

        def server_worker():
            settings = HandshakeSettings()
            settings.minVersion = server_min
            conn = TLSConnection(server_sock)
            try:
                conn.handshakeServer(certChain=CERT_CHAIN,
                                     privateKey=PRIVATE_KEY,
                                     settings=settings)
                result["ok"] = conn.version
            except Exception as e:  # pylint: disable=broad-except
                result["error"] = e

        thread = threading.Thread(target=server_worker)
        thread.start()

        body = bytes(legacy_version) + b"\x11" * 32 + b"\x00"
        suites = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                  CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        body += struct.pack(">H", 2 * len(suites))
        body += b"".join(struct.pack(">H", suite) for suite in suites)
        body += b"\x01\x00"
        record = _build_record(ContentType.handshake, legacy_version,
                               bytes([HandshakeType.client_hello]) +
                               struct.pack(">I", len(body))[1:] + body)
        client_sock.sendall(record)
        content_type, _, payload = _read_record(client_sock)
        thread.join(10)
        client_sock.close()
        server_sock.close()
        self.assertEqual(content_type, ContentType.alert)
        return payload[1], result

    def test_server_rejects_client_below_min_version(self):
        alert, result = self._raw_legacy_hello_alert((3, 2), (3, 3))
        self.assertEqual(alert, AlertDescription.protocol_version)
        self.assertIsInstance(result["error"], Exception)

    def test_server_accepts_client_at_min_version(self):
        client_sock, server_sock = socket.socketpair()
        client_sock.settimeout(5)
        server_sock.settimeout(5)
        result = {}

        def server_worker():
            settings = HandshakeSettings()
            settings.minVersion = (3, 2)
            conn = TLSConnection(server_sock)
            try:
                conn.handshakeServer(certChain=CERT_CHAIN,
                                     privateKey=PRIVATE_KEY,
                                     settings=settings)
                result["ok"] = conn.version
            except Exception as e:  # pylint: disable=broad-except
                result["error"] = e

        thread = threading.Thread(target=server_worker)
        thread.start()
        # Full tlslite client capped at 1.1 is a legitimate legacy peer.
        client_settings = HandshakeSettings()
        client_settings.maxVersion = (3, 2)
        conn = TLSConnection(client_sock)
        conn.handshakeClientCert(settings=client_settings)
        self.assertEqual(conn.version, (3, 2))
        conn.close()
        thread.join(10)
        client_sock.close()
        server_sock.close()
        self.assertEqual(result["ok"], (3, 2))


if __name__ == "__main__":
    unittest.main()
