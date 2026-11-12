# See the LICENSE file for legal information regarding use of this file.

"""Tests for the server-side session resumption admission callback."""

try:
    import unittest2 as unittest
except ImportError:
    import unittest

import os
import socket
import threading
import time

from tlslite import TLSConnection, HandshakeSettings, X509, X509CertChain
from tlslite.handshakesettings import ResumptionTicket
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.utils.cryptomath import getRandomBytes
from tlslite.errors import TLSLocalAlert, TLSRemoteAlert
from tlslite.constants import AlertDescription
from tlslite.utils.cipherfactory import createAESGCM

from unit_tests.mocksock import MockSocket

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "tests")

SERVER_CERT = X509CertChain([X509().parse(
    open(os.path.join(TEST_DIR, "serverX509Cert.pem")).read())])
SERVER_KEY = parsePEMKey(
    open(os.path.join(TEST_DIR, "serverX509Key.pem")).read(), private=True)
CLIENT_CERT = X509CertChain([X509().parse(
    open(os.path.join(TEST_DIR, "clientX509Cert.pem")).read())])
CLIENT_KEY = parsePEMKey(
    open(os.path.join(TEST_DIR, "clientX509Key.pem")).read(), private=True)


def make_server_settings(version, ticket_key, callback=None, lifetime=3600,
                         req_cert=False):
    """Build server settings pinned to one TLS version."""
    settings = HandshakeSettings()
    settings.minVersion = settings.maxVersion = version
    settings.ticketKeys = [ticket_key]
    settings.ticketLifetime = lifetime
    settings.resumption_admission_callback = callback
    return settings


def make_client_settings(version):
    """Build client settings; ticket keys are a server-side option."""
    settings = HandshakeSettings()
    settings.minVersion = settings.maxVersion = version
    return settings


def run_pair(server_fn, client_fn, timeout=5):
    """Run a server and a client over a socketpair, collect exceptions."""
    client_sock, server_sock = socket.socketpair()
    server_sock.settimeout(timeout)
    client_sock.settimeout(timeout)
    server = TLSConnection(server_sock)
    client = TLSConnection(client_sock)
    server_error = {}

    def server_thread():
        try:
            server_fn(server)
        except Exception as exc:
            server_error["error"] = exc

    thread = threading.Thread(target=server_thread)
    thread.daemon = True
    thread.start()
    client_error = None
    try:
        client_fn(client)
    except Exception as exc:
        client_error = exc
    thread.join(timeout)
    server_alive = thread.is_alive()
    client_sock.close()
    server_sock.close()
    if server_alive:
        raise AssertionError("server handshake did not finish in time")
    return server, client, server_error, client_error


class TestHandshakeSettingsCallback(unittest.TestCase):
    def test_default_is_none(self):
        self.assertIsNone(HandshakeSettings().resumption_admission_callback)

    def test_non_callable_rejected(self):
        settings = HandshakeSettings()
        settings.resumption_admission_callback = "not callable"
        with self.assertRaises(ValueError) as error:
            settings.validate()
        self.assertIn("resumption_admission_callback", str(error.exception))

    def test_callback_preserved_by_validate(self):
        def callback(info):
            return True

        settings = HandshakeSettings()
        settings.resumption_admission_callback = callback
        validated = settings.validate()
        self.assertIs(validated.resumption_admission_callback, callback)

    def test_none_callback_accepted(self):
        settings = HandshakeSettings()
        settings.resumption_admission_callback = None
        validated = settings.validate()
        self.assertIsNone(validated.resumption_admission_callback)


class TestResumptionTicketInfo(unittest.TestCase):
    def test_anonymous_ticket_is_not_authenticated(self):
        info = ResumptionTicket(
            protocol_version=(3, 4), cipher_suite=0x1301,
            client_cert_chain=None, server_name="", creation_time=0,
            age=1.0, expired=False, client_certificate_required=True,
            extended_master_secret=True, encrypt_then_mac=False)
        self.assertFalse(info.authenticated)
        self.assertTrue(info.client_certificate_required)

    def test_certificate_ticket_is_authenticated(self):
        info = ResumptionTicket(
            protocol_version=(3, 3), cipher_suite=0xC02F,
            client_cert_chain=CLIENT_CERT, server_name="localhost",
            creation_time=0, age=1.0, expired=False,
            client_certificate_required=True, extended_master_secret=True,
            encrypt_then_mac=False)
        self.assertTrue(info.authenticated)
        self.assertEqual(info.protocol_version, (3, 3))
        self.assertEqual(info.server_name, "localhost")


class AdmissionTestBase(unittest.TestCase):
    """Shared full-handshake and resumption helpers, same keys for all."""

    version = None

    def issue_ticket(self, ticket_key, req_cert=False, client_auth=False,
                     lifetime=3600):
        """Run a full handshake and return the client-side session."""
        session_holder = {}

        def server_fn(server):
            server.handshakeServer(
                certChain=SERVER_CERT, privateKey=SERVER_KEY,
                reqCert=req_cert,
                settings=make_server_settings(self.version, ticket_key,
                                              lifetime=lifetime,
                                              req_cert=req_cert))
            server.write(bytearray(b"app data"))

        def client_fn(client):
            settings = make_client_settings(self.version)
            if client_auth:
                client.handshakeClientCert(CLIENT_CERT, CLIENT_KEY,
                                           settings=settings)
            else:
                client.handshakeClientCert(settings=settings)
            client.read(min=8)
            session_holder["session"] = client.session
            client.close()

        _, _, server_error, client_error = run_pair(server_fn, client_fn)
        self.assertNotIn("error", server_error)
        self.assertIsNone(client_error)
        return session_holder["session"]

    def attempt_resume(self, ticket_key, session, callback, req_cert=False,
                       client_auth=False, lifetime=3600):
        """Try to resume and return the pair results for assertions."""

        def server_fn(server):
            server.handshakeServer(
                certChain=SERVER_CERT, privateKey=SERVER_KEY,
                reqCert=req_cert,
                settings=make_server_settings(self.version, ticket_key,
                                              callback=callback,
                                              lifetime=lifetime,
                                              req_cert=req_cert))
            server.write(bytearray(b"app data"))

        def client_fn(client):
            settings = make_client_settings(self.version)
            if client_auth:
                client.handshakeClientCert(CLIENT_CERT, CLIENT_KEY,
                                           settings=settings, session=session)
            else:
                client.handshakeClientCert(settings=settings, session=session)
            client.read(min=8)
            client.close()

        return run_pair(server_fn, client_fn)


class TestTLS13Admission(AdmissionTestBase):
    version = (3, 4)

    def setUp(self):
        self.ticket_key = getRandomBytes(32)

    def test_no_callback_keeps_default_resumption(self):
        session = self.issue_ticket(self.ticket_key)
        _, client, server_error, client_error = self.attempt_resume(
            self.ticket_key, session, None)
        self.assertIsNone(client_error)
        self.assertNotIn("error", server_error)
        self.assertTrue(client.resumed)

    def test_anonymous_ticket_resumes_when_policy_allows(self):
        session = self.issue_ticket(self.ticket_key)
        seen = []
        _, client, server_error, client_error = self.attempt_resume(
            self.ticket_key, session,
            lambda info: seen.append(info) or True)
        self.assertIsNone(client_error)
        self.assertNotIn("error", server_error)
        self.assertTrue(client.resumed)
        self.assertEqual(len(seen), 1)
        self.assertFalse(seen[0].authenticated)
        self.assertEqual(seen[0].protocol_version, (3, 4))
        self.assertFalse(seen[0].expired)
        self.assertGreaterEqual(seen[0].age, 0.0)

    def test_policy_rejection_falls_back_to_full_handshake(self):
        session = self.issue_ticket(self.ticket_key)
        _, client, server_error, client_error = self.attempt_resume(
            self.ticket_key, session, lambda info: False)
        self.assertIsNone(client_error)
        self.assertNotIn("error", server_error)
        self.assertFalse(client.resumed)

    def test_anonymous_ticket_rejected_when_cert_now_required(self):
        # ticket issued while the server did not ask for client certs
        session = self.issue_ticket(self.ticket_key, req_cert=False,
                                    client_auth=False)
        seen = []

        def policy(info):
            seen.append(info)
            # new admission rule: a client certificate is mandatory, so an
            # anonymous ticket must not count as authenticated
            return info.authenticated

        _, client, server_error, client_error = self.attempt_resume(
            self.ticket_key, session, policy, req_cert=True)
        self.assertIsNone(client_error)
        self.assertNotIn("error", server_error)
        self.assertFalse(client.resumed)
        self.assertTrue(seen[0].client_certificate_required)
        self.assertFalse(seen[0].authenticated)

    def test_authenticated_ticket_passes_cert_required_policy(self):
        session = self.issue_ticket(self.ticket_key, req_cert=True,
                                    client_auth=True)
        seen = []
        _, client, server_error, client_error = self.attempt_resume(
            self.ticket_key, session,
            lambda info: seen.append(info) or info.authenticated,
            req_cert=True, client_auth=True)
        self.assertIsNone(client_error)
        self.assertNotIn("error", server_error)
        self.assertTrue(client.resumed)
        self.assertTrue(seen[0].authenticated)
        self.assertEqual(
            seen[0].client_cert_chain.getFingerprint(),
            CLIENT_CERT.getFingerprint())

    def test_callback_exception_aborts_handshake(self):
        session = self.issue_ticket(self.ticket_key)

        def broken_policy(info):
            raise RuntimeError("policy engine unavailable")

        _, _, server_error, client_error = self.attempt_resume(
            self.ticket_key, session, broken_policy)
        self.assertIsInstance(server_error.get("error"), TLSLocalAlert)
        self.assertEqual(server_error["error"].description,
                         AlertDescription.internal_error)
        self.assertIsInstance(client_error, TLSRemoteAlert)
        self.assertEqual(client_error.description,
                         AlertDescription.internal_error)

    def test_full_handshake_without_ticket_does_not_invoke_callback(self):
        seen = []
        settings = make_server_settings(
            self.version, self.ticket_key,
            callback=lambda info: seen.append(info))

        def server_fn(server):
            server.handshakeServer(certChain=SERVER_CERT,
                                   privateKey=SERVER_KEY, settings=settings)
            server.write(bytearray(b"app data"))

        def client_fn(client):
            client.handshakeClientCert(
                settings=make_client_settings(self.version))
            client.read(min=8)
            client.close()

        _, _, server_error, client_error = run_pair(server_fn, client_fn)
        self.assertIsNone(client_error)
        self.assertNotIn("error", server_error)
        self.assertEqual(seen, [])


class TestTLS12Admission(AdmissionTestBase):
    version = (3, 3)

    def setUp(self):
        self.ticket_key = getRandomBytes(32)

    def test_no_callback_keeps_default_resumption(self):
        session = self.issue_ticket(self.ticket_key)
        _, client, server_error, client_error = self.attempt_resume(
            self.ticket_key, session, None)
        self.assertIsNone(client_error)
        self.assertNotIn("error", server_error)
        self.assertTrue(client.resumed)

    def test_anonymous_ticket_resumes_with_identity_exposed(self):
        session = self.issue_ticket(self.ticket_key)
        seen = []
        _, client, server_error, client_error = self.attempt_resume(
            self.ticket_key, session,
            lambda info: seen.append(info) or True)
        self.assertIsNone(client_error)
        self.assertNotIn("error", server_error)
        self.assertTrue(client.resumed)
        self.assertEqual(len(seen), 1)
        self.assertFalse(seen[0].authenticated)
        self.assertEqual(seen[0].protocol_version, (3, 3))

    def test_authenticated_ticket_carries_client_chain(self):
        session = self.issue_ticket(self.ticket_key, req_cert=True,
                                    client_auth=True)
        seen = []
        _, client, server_error, client_error = self.attempt_resume(
            self.ticket_key, session,
            lambda info: seen.append(info) or True,
            req_cert=True, client_auth=True)
        self.assertIsNone(client_error)
        self.assertNotIn("error", server_error)
        self.assertTrue(client.resumed)
        self.assertTrue(seen[0].authenticated)
        self.assertEqual(
            seen[0].client_cert_chain.getFingerprint(),
            CLIENT_CERT.getFingerprint())

    def test_policy_rejection_does_not_resume_on_server(self):
        session = self.issue_ticket(self.ticket_key)
        server, _, server_error, _ = self.attempt_resume(
            self.ticket_key, session, lambda info: False)
        self.assert_server_rejected_resumption(server, server_error)

    def test_anonymous_ticket_rejected_when_cert_now_required(self):
        session = self.issue_ticket(self.ticket_key)
        seen = []
        server, _, server_error, _ = self.attempt_resume(
            self.ticket_key, session,
            lambda info: seen.append(info) or info.authenticated,
            req_cert=True)
        self.assert_server_rejected_resumption(server, server_error)
        self.assertTrue(seen[0].client_certificate_required)
        self.assertFalse(seen[0].authenticated)

    def assert_server_rejected_resumption(self, server, server_error):
        """Check the server refused resumption and did a full handshake.

        The tlslite-ng TLS 1.2 client commits to resumption whenever it sent
        a non-empty ticket, so it answers the server's full handshake
        fallback with an unexpected_message alert; that alert is the expected
        outcome here, what matters is that the server never resumed.
        """
        self.assertFalse(server.resumed)
        if "error" in server_error:
            self.assertIsInstance(server_error["error"], TLSRemoteAlert)
            self.assertEqual(server_error["error"].description,
                             AlertDescription.unexpected_message)

    def test_callback_exception_aborts_handshake(self):
        session = self.issue_ticket(self.ticket_key)

        def broken_policy(info):
            raise ValueError("bad policy state")

        _, _, server_error, client_error = self.attempt_resume(
            self.ticket_key, session, broken_policy)
        self.assertIsInstance(server_error.get("error"), TLSLocalAlert)
        self.assertEqual(server_error["error"].description,
                         AlertDescription.internal_error)
        self.assertIsInstance(client_error, TLSRemoteAlert)
        self.assertEqual(client_error.description,
                         AlertDescription.internal_error)

    def test_backdated_ticket_reports_expired_and_is_rejected(self):
        # obtain a real ticket, then backdate its encrypted payload while
        # keeping the client-side cache entry fresh enough to send it
        session = self.issue_ticket(self.ticket_key, lifetime=3600)
        cached = session.tls_1_0_tickets[0]
        raw_ticket = cached.ticket

        settings = make_server_settings(self.version, self.ticket_key)
        probe = TLSConnection(MockSocket(bytearray(0)))
        probe.version = (3, 3)
        _, payload = probe._tryDecrypt(settings, ticket=raw_ticket)
        self.assertIsNotNone(payload)
        payload.creation_time = int(time.time()) - 7200

        nonce = raw_ticket[:32]
        key, iv = TLSConnection._derive_key_iv(nonce, self.ticket_key,
                                               settings)
        cipher = createAESGCM(key, settings.cipherImplementations)
        cached.ticket = nonce + cipher.seal(iv, payload.write(), b'')
        cached.time_received = time.time()
        cached.ticket_lifetime = 3600

        seen = []
        server, _, server_error, _ = self.attempt_resume(
            self.ticket_key, session,
            lambda info: seen.append(info) or True, lifetime=3600)
        self.assert_server_rejected_resumption(server, server_error)
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0].expired)
        self.assertGreater(seen[0].age, 7000)


class TestTLS13ExpiredTicket(AdmissionTestBase):
    version = (3, 4)

    def test_client_drops_expired_ticket_and_does_full_handshake(self):
        ticket_key = getRandomBytes(32)
        session = self.issue_ticket(ticket_key, lifetime=1)
        time.sleep(1.2)

        def server_fn(server):
            server.handshakeServer(
                certChain=SERVER_CERT, privateKey=SERVER_KEY,
                settings=make_server_settings(self.version, ticket_key,
                                              callback=lambda info: True,
                                              lifetime=1))
            server.write(bytearray(b"app data"))

        def client_fn(client):
            client.handshakeClientCert(
                settings=make_client_settings(self.version),
                session=session)
            client.read(min=8)
            client.close()

        _, client, server_error, client_error = run_pair(server_fn,
                                                         client_fn)
        self.assertIsNone(client_error)
        self.assertNotIn("error", server_error)
        self.assertFalse(client.resumed)


if __name__ == "__main__":
    unittest.main()
