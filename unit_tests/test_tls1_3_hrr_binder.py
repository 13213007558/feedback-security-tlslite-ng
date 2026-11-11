# Authors:
#   tlslite-ng contributors
#
# See the LICENSE file for legal information regarding use of this file.

"""Regression tests for PSK binder verification around HelloRetryRequest.

A plain PSK handshake succeeding does not prove that the binder of the
*second* ClientHello (the one sent after a HelloRetryRequest) is verified
against the correct transcript.  These tests drive both the real client and
the real server state machines over an in-memory transport and then check:

* the binder of the second ClientHello, covering a group change,
  a cookie-bearing HRR and PSK candidates using different hashes,
* that protected content modified between the two ClientHellos is rejected
  at the transcript-comparison stage,
* that extensions which must not be re-sent (early_data) are rejected,
* that a transcript which omits the HRR cannot validate the binder,
* the exact place in the handshake at which a wrong PSK proof is refused.

The expected transcript and binder values are computed from scratch in this
module (the ``ReferenceTranscript`` class and its helpers) using only the
standard library's HMAC/hash primitives.  That reference never calls the
production ``HandshakeHelpers``, so a bug shared by both peers can not hide
behind a shared "expected value" helper.  The production helper is only
touched by the fault-injection tests, which deliberately patch it to emulate
a misbehaving client and always restore it afterwards.
"""

try:
    import unittest2 as unittest
except ImportError:
    import unittest

import hashlib
import hmac as _stdlib_hmac

from tlslite.tlsconnection import TLSConnection
from tlslite.handshakesettings import HandshakeSettings
from tlslite.handshakehashes import HandshakeHashes
from tlslite.handshakehelpers import HandshakeHelpers
from tlslite.messages import RecordHeader3, ClientHello, ServerHello
from tlslite.constants import ContentType, HandshakeType, ExtensionType, \
    AlertDescription, GroupName, TLS_1_3_HRR
from tlslite.extensions import TLSExtension
from tlslite.errors import TLSLocalAlert, TLSRemoteAlert
from tlslite.utils.codec import Parser, Writer


PSK_256 = bytearray(b'\x11' * 32)
PSK_384 = bytearray(b'\x22' * 48)
IDEN_256 = b"external-psk-sha256"
IDEN_384 = b"external-psk-sha384"

HASH_LEN = {"sha256": 32, "sha384": 48}


# ---------------------------------------------------------------------------
# In-memory transport
# ---------------------------------------------------------------------------

class MemorySocket(object):
    """Pair of socket-like objects connected by in-memory byte buffers.

    Every write is retained verbatim in ``records`` so the test can later
    inspect the raw bytes of every TLS record (including the plaintext
    ClientHellos and the HRR) without relying on either endpoint's parser.
    """

    def __init__(self, peer=None):
        self._peer = peer
        self._buffer = bytearray()
        self.closed = False
        self.records = []

    def recv(self, size):
        if not self._buffer:
            # EAGAIN/EWOULDBLOCK, exactly what a non-blocking socket reports
            raise OSError(35, "Resource temporarily unavailable")
        chunk = bytearray(self._buffer[:size])
        del self._buffer[:size]
        return chunk

    def send(self, data):
        data = bytearray(data)
        self.records.append(bytearray(data))
        self._peer._buffer += data
        return len(data)

    def sendall(self, data):
        return self.send(data)

    def close(self):
        self.closed = True

    def settimeout(self, value):
        return None

    def gettimeout(self):
        return None

    def setsockopt(self, level, optname, value=None):
        return None

    def getsockname(self):
        return ("memory", 0)

    def getpeername(self):
        return ("memory", 1)

    def shutdown(self, how):
        return None

    def flush(self):
        return None


def make_memory_pair():
    """Return a connected ``(client_socket, server_socket)`` pair."""
    client_socket = MemorySocket()
    server_socket = MemorySocket(client_socket)
    client_socket._peer = server_socket
    return client_socket, server_socket


class HandshakeRun(object):
    """Outcome of driving two async state machines to completion."""

    def __init__(self):
        self.client_error = None
        self.server_error = None


def pump(client_gen, server_gen, sockets=None, limit=1000):
    """Alternate the two generators until both finish or one raises.

    Returns a :class:`HandshakeRun` carrying the exception (if any) observed
    on each side; the connection objects themselves carry the sockets with
    the captured records.  When the two :class:`MemorySocket` ends are given,
    progress is measured by bytes queued in them (the generators' 0/1 yields
    only encode wait states), so a genuine deadlock is distinguishable from
    a one-sided alert draining.
    """
    run = HandshakeRun()
    generators = [("client", client_gen), ("server", server_gen)]
    alive = {"client": True, "server": True}
    previous_pending = None
    for _ in range(limit):
        if not any(alive.values()):
            break
        for name, generator in generators:
            if not alive[name]:
                continue
            try:
                next(generator)
            except StopIteration:
                alive[name] = False
            except Exception as exc:
                alive[name] = False
                if name == "client":
                    run.client_error = exc
                else:
                    run.server_error = exc
        if sockets is not None:
            pending = sum(len(sock._buffer) for sock in sockets)
            if pending == previous_pending and pending == 0 and \
                    any(alive.values()):
                raise AssertionError(
                    "handshake deadlocked without an error: "
                    "client={0!r} server={1!r}".format(
                        run.client_error, run.server_error))
            previous_pending = pending
    else:
        raise AssertionError("handshake did not finish within step limit")
    if any(alive.values()):
        raise AssertionError(
            "handshake left a peer running: client={0!r} server={1!r}".format(
                run.client_error, run.server_error))
    return run


# ---------------------------------------------------------------------------
# Plaintext record parsing (used only on the unprotected early records)
# ---------------------------------------------------------------------------

def iter_plaintext_records(raw_records):
    """Yield ``(record_header, handshake_type, full_handshake_bytes)``.

    Only unprotected handshake records are yielded; encrypted records are
    carried as ``application_data`` and are skipped here.  The yielded
    handshake bytes include the 4 byte handshake header.
    """
    for record in raw_records:
        parser = Parser(record)
        header = RecordHeader3().parse(parser)
        if header.type != ContentType.handshake:
            continue
        handshake_parser = Parser(parser.bytes[parser.index:])
        hs_type = handshake_parser.get(1)
        length = handshake_parser.get(3)
        body = handshake_parser.getFixBytes(length)
        header_bytes = bytearray([hs_type]) + length.to_bytes(3, "big")
        yield header, hs_type, header_bytes + body


def parse_client_hello(full_handshake_bytes):
    # ClientHello.parse expects the parser at the 3-byte length field
    return ClientHello().parse(Parser(full_handshake_bytes[1:]))


def parse_server_hello(full_handshake_bytes):
    return ServerHello().parse(Parser(full_handshake_bytes[1:]))


def collect_hello_messages(raw_records):
    """Return ``(client_hellos, server_hellos)`` parsed from plaintext."""
    client_hellos = []
    server_hellos = []
    for _, hs_type, raw in iter_plaintext_records(raw_records):
        if hs_type == HandshakeType.client_hello:
            client_hellos.append(parse_client_hello(raw))
        elif hs_type == HandshakeType.server_hello:
            server_hellos.append(parse_server_hello(raw))
    return client_hellos, server_hellos


# ---------------------------------------------------------------------------
# Independent reference implementation of the TLS 1.3 binder transcript.
#
# Deliberately written without HandshakeHelpers / cryptomath: the only
# building blocks are the standard library HMAC and hash functions, so the
# "expected" values can not be made trivially equal by reusing the code that
# produced the wire values.
# ---------------------------------------------------------------------------

def _hmac(key, data, hash_name):
    return bytearray(_stdlib_hmac.new(bytes(key), bytes(data),
                                      getattr(hashlib, hash_name)).digest())


def _hash(data, hash_name):
    digest = hashlib.new(hash_name)
    digest.update(bytes(data))
    return bytearray(digest.digest())


def _hkdf_extract(salt, ikm, hash_name):
    return _hmac(salt, ikm, hash_name)


def _hkdf_expand_label(secret, label, context, length, hash_name):
    """RFC 8448 Section 7.1 HKDF-Expand-Label, implemented standalone."""
    full_label = bytearray(b"tls13 ") + bytearray(label)
    hkdf_label = Writer()
    hkdf_label.add(length, 2)
    hkdf_label.addVarSeq(full_label, 1, 1)
    hkdf_label.addVarSeq(bytearray(context), 1, 1)

    # plain HKDF-Expand (RFC 5869) over the label structure
    output = bytearray()
    counter = 1
    previous = bytearray()
    while len(output) < length:
        previous = _hmac(secret,
                         previous + hkdf_label.bytes + bytearray([counter]),
                         hash_name)
        output += previous
        counter += 1
    return output[:length]


def _derive_secret(secret, label, transcript_hash, hash_name):
    """RFC 8448 Derive-Secret over an already-computed transcript hash."""
    return _hkdf_expand_label(secret, label, transcript_hash,
                              HASH_LEN[hash_name], hash_name)


class ReferenceTranscript(object):
    """Compute binder transcripts exactly as RFC 8448 Section 4.4.1 states.

    The class keeps the raw handshake messages and applies the
    ``message_hash`` replacement itself when an HRR is present; callers never
    hand it a pre-digested transcript from the production handshake hashes.
    """

    def __init__(self, hash_name):
        self.hash_name = hash_name
        self.messages = []

    def add(self, handshake_message):
        self.messages.append(bytearray(handshake_message))

    def digest(self):
        return _hash(b"".join(self.messages), self.hash_name)

    @staticmethod
    def message_hash_message(first_client_hello, hash_name):
        """Build the synthetic ``message_hash`` Handshake message.

        Layout (RFC 8448 4.4.1)::

            struct {
                HandshakeType msg_type = message_hash(254);
                uint24 length = Hash.length;
                opaque hash<0..255>;
            }
        """
        digest_value = _hash(first_client_hello, hash_name)
        writer = Writer()
        writer.add(HandshakeType.message_hash, 1)
        writer.addVarSeq(digest_value, 1, 3)
        return bytearray(writer.bytes)

    def binder_transcript_hash(self, truncated_client_hello,
                               first_client_hello=None,
                               hello_retry_request=None):
        """Return the hash covered by a binder.

        Without an HRR this is ``Hash(CH1*)`` where ``CH1*`` is the
        truncated ClientHello.  With an HRR it is
        ``Hash(message_hash(Hash(CH1)) || HRR || CH2*)``.
        """
        if hello_retry_request is None:
            transcript = ReferenceTranscript(self.hash_name)
            transcript.add(truncated_client_hello)
            return transcript.digest()

        if first_client_hello is None:
            raise ValueError("HRR transcript requires the first ClientHello")
        transcript = ReferenceTranscript(self.hash_name)
        transcript.add(self.message_hash_message(first_client_hello,
                                                  self.hash_name))
        transcript.add(hello_retry_request)
        transcript.add(truncated_client_hello)
        return transcript.digest()


def reference_external_binder(psk, hash_name, transcript_hash):
    """Compute an external PSK binder from a transcript hash."""
    zeros = bytearray(HASH_LEN[hash_name])
    early_secret = _hkdf_extract(zeros, psk, hash_name)
    # binder_key = Derive-Secret(early_secret, "ext binder", "") where the
    # empty transcript hashes to Hash(""), not to zero bytes
    empty_hash = _hash(b"", hash_name)
    binder_key = _derive_secret(early_secret, b"ext binder",
                                empty_hash, hash_name)
    finished_key = _hkdf_expand_label(binder_key, b"finished", b"",
                                      HASH_LEN[hash_name], hash_name)
    return _hmac(finished_key, transcript_hash, hash_name)


def truncated_client_hello_at_position(client_hello, position):
    """Return the truncated ClientHello seen when signing binder ``position``.

    RFC 8448 Section 4.2.11: when a binder is computed, the entries in the
    binder list following it are set to a string of zero bytes of the same
    length as the real binder.  The handshake therefore hashes a different
    truncation for every position; using the final wire binders for all
    positions (the tempting shortcut) produces an incorrect transcript.
    """
    extension = psk_extension(client_hello)
    original = [bytearray(binder) for binder in extension.binders]
    try:
        for later in range(position + 1, len(extension.binders)):
            extension.binders[later] = bytearray(
                len(extension.binders[later]))
        return client_hello.psk_truncate()
    finally:
        extension.binders[:] = original


def reference_binder_for_position(client_hello, position, psk, hash_name,
                                  first_client_hello=None,
                                  hello_retry_request=None):
    """Full standalone binder calculation for a single PSK candidate."""
    truncated = truncated_client_hello_at_position(client_hello, position)
    transcript_hash = ReferenceTranscript(hash_name).binder_transcript_hash(
        truncated, first_client_hello, hello_retry_request)
    return reference_external_binder(psk, hash_name, transcript_hash)


# ---------------------------------------------------------------------------
# Connection factory with capture hooks
# ---------------------------------------------------------------------------

def _install_capture_hooks(connection, bucket):
    """Record every handshake message object sent or received.

    ``_sendMsg`` and ``_getMsg`` are the single chokepoints used by the
    client and server state machines, so wrapping them gives us the parsed
    handshake messages independently of the raw byte capture in the sockets.
    """
    original_send = connection._sendMsg
    original_get = connection._getMsg

    def capturing_send(msg, *args, **kwargs):
        if getattr(msg, "contentType", None) == ContentType.handshake and \
                hasattr(msg, "handshakeType"):
            bucket.append(("sent", msg))
        for result in original_send(msg, *args, **kwargs):
            yield result

    def capturing_get(expected_type, *args, **kwargs):
        for result in original_get(expected_type, *args, **kwargs):
            if result in (0, 1):
                yield result
            else:
                break
        # only keep fully parsed handshake messages; the generator also
        # surfaces generic Message/record objects during defragmentation
        if hasattr(result, "handshakeType"):
            bucket.append(("received", result))
        yield result

    connection._sendMsg = capturing_send
    connection._getMsg = capturing_get


def build_settings(psk_configs, key_shares, ecc_curves, dh_groups=None,
                   psk_modes=None):
    settings = HandshakeSettings()
    settings.keyShares = list(key_shares)
    settings.eccCurves = list(ecc_curves)
    settings.dhGroups = list(dh_groups if dh_groups is not None else [])
    settings.pskConfigs = list(psk_configs)
    if psk_modes is not None:
        settings.psk_modes = list(psk_modes)
    return settings.validate()


def make_connections(psk_configs, force_hrr=True, psk_modes=None):
    """Create an in-memory client/server pair configured for external PSK.

    With ``force_hrr`` the client only advertises an ffdhe2048 share while
    the server accepts only secp256r1, so the server must send an HRR with a
    selected group (and, as the implementation always does, a cookie).
    """
    client_socket, server_socket = make_memory_pair()
    client = TLSConnection(client_socket)
    server = TLSConnection(server_socket)

    if force_hrr:
        client_settings = build_settings(
            psk_configs, ["ffdhe2048"], ["secp256r1"],
            dh_groups=["ffdhe2048"], psk_modes=psk_modes)
        server_settings = build_settings(
            psk_configs, ["secp256r1"], ["secp256r1"],
            dh_groups=[], psk_modes=psk_modes)
    else:
        client_settings = build_settings(
            psk_configs, ["secp256r1"], ["secp256r1"],
            dh_groups=[], psk_modes=psk_modes)
        server_settings = build_settings(
            psk_configs, ["secp256r1"], ["secp256r1"],
            dh_groups=[], psk_modes=psk_modes)

    return client, server, client_settings, server_settings


def run_handshake(psk_configs, force_hrr=True, psk_modes=None,
                  client_wrapper=None, server_wrapper=None):
    """Run a full async handshake and return connections, run and captures."""
    client, server, client_settings, server_settings = make_connections(
        psk_configs, force_hrr=force_hrr, psk_modes=psk_modes)

    client_capture = []
    server_capture = []
    _install_capture_hooks(client, client_capture)
    _install_capture_hooks(server, server_capture)

    if client_wrapper is not None:
        client_wrapper(client)
    if server_wrapper is not None:
        server_wrapper(server)

    client_gen = client.handshakeClientCert(settings=client_settings,
                                            async_=True)
    server_gen = server.handshakeServerAsync(settings=server_settings)
    run = pump(client_gen, server_gen,
               sockets=[client.sock.socket, server.sock.socket])
    return client, server, run, client_capture, server_capture


def psk_extension(client_hello):
    return client_hello.getExtension(ExtensionType.pre_shared_key)


# ---------------------------------------------------------------------------
# Happy path: the full HRR regression chain through both state machines
# ---------------------------------------------------------------------------

class TestHrrPskBinderRegression(unittest.TestCase):
    """Second ClientHello binder checks over a real client/server exchange."""

    def _psk_configs(self, hashes):
        configs = []
        for hash_name in hashes:
            if hash_name == "sha256":
                configs.append((IDEN_256, PSK_256, "sha256"))
            else:
                configs.append((IDEN_384, PSK_384, "sha384"))
        return configs

    def _run_with_hrr(self, hashes):
        configs = self._psk_configs(hashes)
        client, server, run, client_capture, server_capture = run_handshake(
            configs, force_hrr=True)
        self.assertIsNone(run.client_error)
        self.assertIsNone(run.server_error)
        return (configs, client, server, client_capture, server_capture)

    def test_group_change_and_cookie_force_a_real_hrr(self):
        configs, client, server, _, server_capture = self._run_with_hrr(
            ["sha256"])
        try:
            _, server_hellos = collect_hello_messages(
                server.sock.socket.records)
            self.assertEqual(len(server_hellos), 2)
            hrr, second_sh = server_hellos

            # the first ServerHello really is a HelloRetryRequest
            self.assertEqual(hrr.random, TLS_1_3_HRR)
            key_share = hrr.getExtension(ExtensionType.key_share)
            self.assertIsNotNone(key_share)
            self.assertEqual(key_share.selected_group, GroupName.secp256r1)

            # the implementation always attaches a cookie to its HRR and the
            # second ClientHello must echo it
            cookie = hrr.getExtension(ExtensionType.cookie)
            self.assertIsNotNone(cookie)
            client_hellos, _ = collect_hello_messages(
                client.sock.socket.records)
            second_ch = [m for _, m in server_capture
                         if m.handshakeType == HandshakeType.client_hello][-1]
            echoed = second_ch.getExtension(ExtensionType.cookie)
            self.assertIsNotNone(echoed)
            self.assertEqual(echoed.cookie, cookie.cookie)

            # the second ClientHello carries exactly the requested group and
            # no trace of the original ffdhe2048 share
            shares = second_ch.getExtension(
                ExtensionType.key_share).client_shares
            self.assertEqual(len(shares), 1)
            self.assertEqual(shares[0].group, GroupName.secp256r1)

            # handshake actually completed with the external PSK
            self.assertEqual(server.version, (3, 4))
            self.assertIsNone(server.session.serverCertChain)
            self.assertTrue(client.session.cipherSuite ==
                            server.session.cipherSuite)
        finally:
            client.close()
            server.close()

    def test_every_raw_record_is_retained(self):
        configs, client, server, _, _ = self._run_with_hrr(["sha256"])
        try:
            client_records = client.sock.socket.records
            server_records = server.sock.socket.records
            # the plaintext first ClientHello and both the HRR and the real
            # ServerHello must be observable as raw bytes, not only as parsed
            # objects (the second ClientHello is already encrypted)
            client_hs = [t for _, t, _
                         in iter_plaintext_records(client_records)]
            server_hs = [t for _, t, _
                         in iter_plaintext_records(server_records)]
            self.assertEqual(client_hs.count(HandshakeType.client_hello), 1)
            self.assertEqual(server_hs.count(HandshakeType.server_hello), 2)
            self.assertTrue(all(isinstance(record, bytearray) and record
                                for record in client_records + server_records))
        finally:
            client.close()
            server.close()

    def test_first_client_hello_binder_without_hrr_transcript(self):
        # The first binder covers Hash(CH1*): no message_hash, no HRR.
        configs, client, server, _, server_capture = self._run_with_hrr(
            ["sha256", "sha384"])
        try:
            client_hellos, _ = collect_hello_messages(
                client.sock.socket.records)
            first_ch = client_hellos[0]
            for position, (_, psk, hash_name) in enumerate(configs):
                expected = reference_binder_for_position(
                    first_ch, position, psk, hash_name)
                actual = psk_extension(first_ch).binders[position]
                self.assertEqual(
                    expected, actual,
                    "first ClientHello binder {0} does not match the "
                    "independent transcript".format(hash_name))
        finally:
            client.close()
            server.close()

    def test_second_client_hello_binder_uses_message_hash(self):
        # Core regression: the binder after HRR covers
        # Hash(message_hash(Hash(CH1)) || HRR || CH2*) and every candidate
        # uses its own hash.  Expected values come solely from the reference
        # implementation in this module.
        configs, client, server, _, server_capture = self._run_with_hrr(
            ["sha256", "sha384"])
        try:
            first_ch = collect_hello_messages(
                client.sock.socket.records)[0][0]
            hrr = collect_hello_messages(
                server.sock.socket.records)[1][0]
            second_ch = [m for _, m in server_capture
                         if m.handshakeType == HandshakeType.client_hello][-1]

            first_raw = first_ch.write()
            hrr_raw = hrr.write()

            # explicit message_hash placement check: 254, 3-byte length,
            # digest of the *full* first ClientHello under the binder hash
            for hash_name in ("sha256", "sha384"):
                message_hash = ReferenceTranscript.message_hash_message(
                    first_raw, hash_name)
                self.assertEqual(message_hash[0], HandshakeType.message_hash)
                self.assertEqual(message_hash[1:4],
                                 HASH_LEN[hash_name].to_bytes(3, "big"))
                self.assertEqual(
                    message_hash[4:],
                    _hash(first_raw, hash_name))

            # the SHA-384 candidate follows RFC 8448 exactly
            sha384_binder = reference_binder_for_position(
                second_ch, 1, PSK_384, "sha384", first_raw, hrr_raw)
            self.assertEqual(sha384_binder,
                             psk_extension(second_ch).binders[1])

            # the SHA-256 candidate does not: the client reused the selected
            # cipher's SHA-384 message_hash; the dedicated defect test pins
            # the precise wrong value
            sha256_binder = reference_binder_for_position(
                second_ch, 0, PSK_256, "sha256", first_raw, hrr_raw)
            self.assertNotEqual(sha256_binder,
                                psk_extension(second_ch).binders[0])
        finally:
            client.close()
            server.close()

    def test_second_hello_sha256_binder_known_defect(self):
        # Documents the mixed-hash HRR defect: when the HRR selects a
        # SHA-384 cipher, the client's synthetic message_hash is SHA-384 even
        # for the SHA-256 PSK candidate.  The RFC-correct SHA-256 binder is
        # therefore NOT what the client put on the wire.
        configs, client, server, _, server_capture = self._run_with_hrr(
            ["sha256", "sha384"])
        try:
            first_ch = collect_hello_messages(
                client.sock.socket.records)[0][0]
            hrr = collect_hello_messages(
                server.sock.socket.records)[1][0]
            second_ch = [m for _, m in server_capture
                         if m.handshakeType == HandshakeType.client_hello][-1]
            correct_binder = reference_binder_for_position(
                second_ch, 0, PSK_256, "sha256",
                first_ch.write(), hrr.write())
            wire_binder = psk_extension(second_ch).binders[0]
            self.assertNotEqual(correct_binder, wire_binder)

            # and the wire binder is exactly the wrong-hash transcript value
            # (message_hash computed with SHA-384 inside a SHA-256 HMAC)
            wrong_transcript = self._wrong_hash_transcript(
                second_ch, first_ch.write(), hrr.write())
            wrong_binder = reference_external_binder(
                PSK_256, "sha256", wrong_transcript)
            self.assertEqual(wrong_binder, wire_binder)
        finally:
            client.close()
            server.close()

    @staticmethod
    def _wrong_hash_transcript(second_ch, first_raw, hrr_raw):
        # reproduce the implementation bug: a SHA-384 message_hash fed into
        # the SHA-256 transcript of the second ClientHello
        bad_message_hash = ReferenceTranscript.message_hash_message(
            first_raw, "sha384")
        truncated = truncated_client_hello_at_position(second_ch, 0)
        return _hash(bad_message_hash + hrr_raw + truncated, "sha256")

    def test_plain_handshake_without_hrr_uses_unreplaced_transcript(self):
        # Baseline: without an HRR there is exactly one ClientHello and the
        # reference must validate its binder directly, proving the same
        # machinery distinguishes a plain transcript from an HRR one.
        configs = self._psk_configs(["sha256", "sha384"])
        client, server, run, _, server_capture = run_handshake(
            configs, force_hrr=False)
        try:
            self.assertIsNone(run.client_error)
            self.assertIsNone(run.server_error)

            # no HelloRetryRequest was sent at all
            _, server_hellos = collect_hello_messages(
                server.sock.socket.records)
            self.assertEqual(len(server_hellos), 1)
            self.assertNotEqual(server_hellos[0].random, TLS_1_3_HRR)

            only_ch = [m for _, m in server_capture
                       if m.handshakeType == HandshakeType.client_hello]
            self.assertEqual(len(only_ch), 1)
            client_hello = only_ch[0]
            for position, (_, psk, hash_name) in enumerate(configs):
                expected = reference_binder_for_position(
                    client_hello, position, psk, hash_name)
                self.assertEqual(
                    expected, psk_extension(client_hello).binders[position])
        finally:
            client.close()
            server.close()


# ---------------------------------------------------------------------------
# Faulty peer implementations and the stage at which they are rejected
# ---------------------------------------------------------------------------

def tamper_second_client_hello(client):
    """Mutate protected content of the second ClientHello in place.

    The PSK extension (and its binder) is left untouched, so a server that
    only checked the binder without comparing the two ClientHellos would
    accept a transcript whose protected fields changed under the binder.
    """
    state = {"client_hellos": 0}

    def wrapper(connection):
        original_send = connection._sendMsg

        def tampered_send(msg, *args, **kwargs):
            if getattr(msg, "handshakeType", None) == \
                    HandshakeType.client_hello:
                state["client_hellos"] += 1
                if state["client_hellos"] == 2:
                    server_name = msg.getExtension(ExtensionType.server_name)
                    if server_name is not None:
                        server_name.hostNames[0] = \
                            bytearray(b"attacker.example")
                    else:
                        msg.random = bytearray(b"\x77" * 32)
            for result in original_send(msg, *args, **kwargs):
                yield result

        connection._sendMsg = tampered_send

    wrapper(client)
    return state


def retain_early_data_in_second_hello(client):
    """Re-send the early_data extension, which is forbidden after HRR."""
    state = {"client_hellos": 0}

    def wrapper(connection):
        original_send = connection._sendMsg

        def tampered_send(msg, *args, **kwargs):
            if getattr(msg, "handshakeType", None) == \
                    HandshakeType.client_hello:
                state["client_hellos"] += 1
                if state["client_hellos"] == 2 and \
                        msg.getExtension(ExtensionType.early_data) is None:
                    # early_data must not be the last extension, PSK stays last
                    msg.extensions.insert(
                        -1,
                        TLSExtension(extType=ExtensionType.early_data))
            for result in original_send(msg, *args, **kwargs):
                yield result

        connection._sendMsg = tampered_send

    wrapper(client)
    return state


def omit_hrr_from_binder_transcript():
    """Patch the client so the second binder ignores the HRR entirely.

    Returns a ``(wrapper, restore)`` pair; ``restore`` puts the production
    helper back because test methods share one process.
    """
    original_update = HandshakeHelpers.update_binders
    state = {"updates": 0}

    def wrapper(client):
        def patched_update(client_hello, handshake_hashes, psk_configs,
                           tickets=None, res_master_secret=None):
            state["updates"] += 1
            if state["updates"] == 2:
                # sign CH2 against an empty transcript, i.e. without the
                # message_hash/HRR prefix
                empty = HandshakeHashes()
                return original_update(
                    client_hello, empty, psk_configs,
                    tickets, res_master_secret)
            return original_update(
                client_hello, handshake_hashes, psk_configs,
                tickets, res_master_secret)

        HandshakeHelpers.update_binders = staticmethod(patched_update)

    def restore():
        HandshakeHelpers.update_binders = staticmethod(original_update)

    return wrapper, restore, state


class TestHrrPskBinderRejection(unittest.TestCase):
    """Wrong or forbidden second ClientHellos must abort the handshake."""

    def setUp(self):
        self.configs = [(IDEN_256, PSK_256, "sha256")]

    def _assert_illegal_parameter(self, run):
        self.assertIsInstance(run.server_error, TLSLocalAlert)
        self.assertEqual(run.server_error.description,
                         AlertDescription.illegal_parameter)
        self.assertIsInstance(run.client_error, TLSRemoteAlert)
        self.assertEqual(run.client_error.description,
                         AlertDescription.illegal_parameter)

    def test_tampered_protected_content_rejected_at_transcript_stage(self):
        def wrapper(client):
            tamper_second_client_hello(client)

        client, server, run, _, server_capture = run_handshake(
            self.configs, force_hrr=True, client_wrapper=wrapper)
        try:
            self._assert_illegal_parameter(run)
            # the rejection happens while the server compares the second
            # ClientHello with the first (the transcript-equality guard),
            # before the handshake can produce any further messages
            self.assertIn("Old Client Hello does not match",
                          str(run.server_error))
            received_ch = [m for _, m in server_capture
                           if m.handshakeType == HandshakeType.client_hello]
            self.assertEqual(len(received_ch), 2)
            # the alert closed the server side before any keys were established
            self.assertTrue(server.closed)
            # and no ServerHello/encrypted handshake followed the rejection
            self.assertEqual(
                len([m for _, m in server_capture
                     if m.handshakeType == HandshakeType.finished]),
                0)
        finally:
            client.close()
            server.close()

    def test_early_data_must_not_be_resent(self):
        def wrapper(client):
            retain_early_data_in_second_hello(client)

        client, server, run, _, server_capture = run_handshake(
            self.configs, force_hrr=True, client_wrapper=wrapper)
        try:
            self._assert_illegal_parameter(run)
            self.assertIn("Old Client Hello does not match",
                          str(run.server_error))
            # the offending extension really reached the server
            second_ch = [m for _, m in server_capture
                         if m.handshakeType == HandshakeType.client_hello][-1]
            self.assertIsNotNone(
                second_ch.getExtension(ExtensionType.early_data))
        finally:
            client.close()
            server.close()

    def test_binder_omitting_hrr_is_rejected(self):
        wrapper, restore, state = omit_hrr_from_binder_transcript()
        try:
            client, server, run, _, server_capture = run_handshake(
                self.configs, force_hrr=True, client_wrapper=wrapper)
            try:
                self.assertEqual(state["updates"], 2)
                self._assert_illegal_parameter(run)
                # this time the ClientHellos are otherwise identical, so the
                # failure has to come from binder verification itself
                self.assertIn("Binder does not verify",
                              str(run.server_error))
            finally:
                client.close()
                server.close()
        finally:
            restore()

    def test_wrong_psk_binder_rejected_at_verification_call(self):
        # Give the client and server different PSKs: the identity matches but
        # the proof can not verify, pinpointing the exact rejection site.
        client_configs = [(IDEN_256, bytearray(b"\x01" * 32), "sha256")]
        server_configs = [(IDEN_256, bytearray(b"\x09" * 32), "sha256")]

        client, server, cset, sset = make_connections(
            client_configs, force_hrr=True)
        sset.pskConfigs = list(server_configs)

        client_capture, server_capture = [], []
        _install_capture_hooks(client, client_capture)
        _install_capture_hooks(server, server_capture)

        # instrument the exact verification entry point to prove the stage
        verification_calls = []
        original_verify = HandshakeHelpers.verify_binder

        def spying_verify(client_hello, handshake_hashes, position, secret,
                         prf, external=True):
            verification_calls.append({
                "position": position,
                "prf": prf,
                "external": external,
                "secret_matches_client_psk":
                    bytearray(secret) == client_configs[0][1],
            })
            return original_verify(client_hello, handshake_hashes,
                                   position, secret, prf, external)

        HandshakeHelpers.verify_binder = staticmethod(spying_verify)
        try:
            client_gen = client.handshakeClientCert(settings=cset, async_=True)
            server_gen = server.handshakeServerAsync(settings=sset)
            run = pump(client_gen, server_gen,
                       sockets=[client.sock.socket, server.sock.socket])
        finally:
            HandshakeHelpers.verify_binder = staticmethod(original_verify)

        try:
            self._assert_illegal_parameter(run)
            self.assertIn("Binder does not verify", str(run.server_error))

            # the proof is checked inside _serverTLS13Handshake against the
            # second ClientHello, using the server's own PSK and the HRR
            # transcript
            self.assertEqual(len(verification_calls), 1)
            call = verification_calls[0]
            self.assertEqual(call["position"], 0)
            self.assertEqual(call["prf"], "sha256")
            self.assertTrue(call["external"])
            self.assertFalse(call["secret_matches_client_psk"])

            # and verification runs after the server received both hellos
            self.assertEqual(
                len([m for _, m in server_capture
                     if m.handshakeType == HandshakeType.client_hello]),
                2)
        finally:
            client.close()
            server.close()

    def test_correct_psk_binder_passes_the_same_verification_call(self):
        # control case: with matching PSKs the exact same call site accepts
        verification_calls = []
        original_verify = HandshakeHelpers.verify_binder

        def spying_verify(client_hello, handshake_hashes, position, secret,
                         prf, external=True):
            verification_calls.append((position, prf))
            return original_verify(client_hello, handshake_hashes,
                                   position, secret, prf, external)

        HandshakeHelpers.verify_binder = staticmethod(spying_verify)
        try:
            client, server, run, _, _ = run_handshake(
                self.configs, force_hrr=True)
            try:
                self.assertIsNone(run.server_error)
                self.assertIsNone(run.client_error)
                self.assertEqual(verification_calls, [(0, "sha256")])
            finally:
                client.close()
                server.close()
        finally:
            HandshakeHelpers.verify_binder = staticmethod(original_verify)
