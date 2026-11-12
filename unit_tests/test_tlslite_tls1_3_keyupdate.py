# Copyright (c) 2026, tlslite-ng contributors
#
# See the LICENSE file for legal information regarding use of this file.

"""Interleaved read/write tests for the TLS 1.3 KeyUpdate mechanism.

The tests drive two real :py:class:`TLSRecordLayer` endpoints (real read and
write generators, real AEAD encryption) connected through a pair of pausable
in-memory sockets.  A record layer wrapper annotates every traffic key with
its generation and keeps a wire log describing, for every record, the
direction, the key generation and the sequence number used to protect it and
the result of the decryption attempt.  This makes it possible to assert which
generation of keys has to open every record on the wire, when sequence
numbers are reset to zero and that an illegal update never moves the next
record onto the wrong key state.
"""

try:
    import unittest2 as unittest
except ImportError:
    import unittest

import socket
import errno

from tlslite.tlsrecordlayer import TLSRecordLayer
from tlslite.recordlayer import RecordLayer
from tlslite.messages import KeyUpdate
from tlslite.session import Session
from tlslite.constants import CipherSuite, ContentType, HandshakeType, \
        KeyUpdateMessageType, AlertDescription
from tlslite.errors import TLSLocalAlert, TLSIllegalParameterException


CIPHER_SUITE = CipherSuite.TLS_AES_128_GCM_SHA256
# same application traffic secrets on both endpoints; which one is the write
# secret depends only on the endpoint role
CL_APP_SECRET = bytearray(b"client application traffic secret!!")
SR_APP_SECRET = bytearray(b"server application traffic secret!!")


class PausableSocket(object):
    """In-memory socket whose reads and writes can be paused independently.

    Two instances created by :py:meth:`make_pair` are cross connected: bytes
    written to one end are queued for the other end.  ``write_paused`` makes
    a direction behave like a full non-blocking buffer while ``pause_after``
    blocks it once a given amount has moved, so the TLS generators can be
    suspended in the middle of writing a record.
    """

    def __init__(self, name):
        self.name = name
        self.peer = None
        self._incoming = bytearray()
        self.read_paused = False
        self.write_paused = False
        # when set, further bytes are rejected once this many of them have
        # already been moved, leaving a record half written on the wire
        self.pause_after = None
        self._bytes_moved = 0
        self.closed = False

    @classmethod
    def make_pair(cls, name_a="a", name_b="b"):
        end_a = cls(name_a)
        end_b = cls(name_b)
        end_a.peer = end_b
        end_b.peer = end_a
        return end_a, end_b

    def recv(self, size):
        if self.closed:
            raise ValueError("read from closed socket")
        if self.read_paused:
            raise socket.error(errno.EWOULDBLOCK)
        if not self._incoming:
            raise socket.error(errno.EWOULDBLOCK)
        data = self._incoming[:size]
        del self._incoming[:size]
        return data

    def _accept(self, data):
        limit = len(data)
        if self.pause_after is not None:
            remaining = self.pause_after - self._bytes_moved
            if remaining <= 0:
                # transport buffer full, record layer retries the remainder
                return 0
            limit = min(limit, remaining)
        chunk = data[:limit]
        self.peer._incoming += chunk
        self._bytes_moved += len(chunk)
        return len(chunk)

    def send(self, data):
        if self.closed:
            raise ValueError("write to closed socket")
        if not data:
            return 0
        # a paused transport behaves like a full non-blocking socket buffer:
        # report zero bytes sent so the record layer keeps the whole record
        # and asks to be driven again later
        if self.write_paused:
            return 0
        return self._accept(bytearray(data))

    def sendall(self, data):
        data = bytearray(data)
        sent = 0
        while sent < len(data):
            if self.write_paused:
                raise socket.error(errno.EWOULDBLOCK)
            moved = self._accept(data[sent:])
            if moved == 0:
                raise socket.error(errno.EWOULDBLOCK)
            sent += moved

    def close(self):
        self.closed = True


class TrackingRecordLayer(RecordLayer):
    """Record layer that tags key generations and records wire activity."""

    def __init__(self, sock):
        super(TrackingRecordLayer, self).__init__(sock)
        self._write_generation = 0
        self._read_generation = 0
        self.wire_log = []

    def _tag_write_state(self, state, generation):
        state.key_generation = generation

    def _tag_read_state(self, state, generation):
        state.key_generation = generation

    def changeWriteState(self):
        super(TrackingRecordLayer, self).changeWriteState()
        self._tag_write_state(self._writeState, self._write_generation)

    def changeReadState(self):
        super(TrackingRecordLayer, self).changeReadState()
        self._tag_read_state(self._readState, self._read_generation)

    def calcTLS1_3KeyUpdate_sender(self, cipherSuite, cl_app_secret,
                                   sr_app_secret):
        ret = super(TrackingRecordLayer, self).calcTLS1_3KeyUpdate_sender(
            cipherSuite, cl_app_secret, sr_app_secret)
        self._read_generation += 1
        self._tag_read_state(self._readState, self._read_generation)
        return ret

    def calcTLS1_3KeyUpdate_reciever(self, cipherSuite, cl_app_secret,
                                     sr_app_secret):
        ret = super(TrackingRecordLayer, self).calcTLS1_3KeyUpdate_reciever(
            cipherSuite, cl_app_secret, sr_app_secret)
        self._write_generation += 1
        self._tag_write_state(self._writeState, self._write_generation)
        return ret

    @property
    def write_generation(self):
        return self._write_generation

    @property
    def read_generation(self):
        return self._read_generation

    @staticmethod
    def _is_keyupdate(msg):
        if msg.contentType != ContentType.handshake:
            return False
        data = msg.write()
        # handshake header: msg_type (1) + length (3)
        return len(data) >= 4 and data[0] == HandshakeType.key_update

    def sendRecord(self, msg):
        inner_is_ku = self._is_keyupdate(msg)
        # getSeqNumBytes() inside the parent consumes the sequence number, so
        # capture it beforehand to keep the on-wire position
        seqnum = self._writeState.seqnum
        generation = getattr(self._writeState, "key_generation", 0)
        for result in super(TrackingRecordLayer, self).sendRecord(msg):
            yield result
        self.wire_log.append({
            "direction": "send",
            "generation": generation,
            "seqnum": seqnum,
            "content_type": msg.contentType,
            "is_keyupdate": inner_is_ku,
            "decrypt_ok": None,
        })

    def recvRecord(self):
        # the parent consumes the sequence number while unsealing, so even a
        # failed decryption leaves the record position identifiable; log the
        # attempt before re-raising so the failure stays in the wire log
        try:
            for result in super(TrackingRecordLayer, self).recvRecord():
                if result in (0, 1):
                    yield result
                else:
                    break
        except Exception:
            state = self._readState
            self.wire_log.append({
                "direction": "recv",
                "generation": getattr(state, "key_generation", 0),
                "seqnum": state.seqnum - 1,
                "content_type": ContentType.application_data,
                "is_keyupdate": False,
                "decrypt_ok": False,
            })
            raise
        header, parser = result
        state = self._readState
        is_ku = header.type == ContentType.handshake and \
            parser.bytes and parser.bytes[0] == HandshakeType.key_update
        entry = {
            "direction": "recv",
            "generation": getattr(state, "key_generation", 0),
            "seqnum": state.seqnum - 1,
            "content_type": header.type,
            "is_keyupdate": is_ku,
            "decrypt_ok": True,
        }
        self.wire_log.append(entry)
        yield (header, parser)


class Endpoint(object):
    """A TLS 1.3 endpoint driven through its asynchronous generators."""

    def __init__(self, sock, client):
        self.sock = sock
        self.tls = TLSRecordLayer(sock)
        tracking = TrackingRecordLayer(self.tls.sock)
        self.tls._recordLayer = tracking
        self.tls.version = (3, 4)
        self.tls.closed = False
        self.tls.session = Session()
        self.tls.session.cipherSuite = CIPHER_SUITE
        self.tls.session.cl_app_secret = bytearray(CL_APP_SECRET)
        self.tls.session.sr_app_secret = bytearray(SR_APP_SECRET)

        record_layer = self.tls._recordLayer
        record_layer.client = client
        record_layer.calcTLS1_3PendingState(
            CIPHER_SUITE, CL_APP_SECRET, SR_APP_SECRET, None)
        record_layer.changeWriteState()
        record_layer.changeReadState()

        self.active = {}
        self.reader = None
        self.received = []

    @property
    def record_layer(self):
        return self.tls._recordLayer

    @property
    def wire_log(self):
        return self.record_layer.wire_log

    def new_reader(self):
        # background reader; with no data available it only yields 0 and stays
        # suspended, so the pump has to keep it around instead of retiring it
        self.reader = self.tls.readAsync()
        self.active["read"] = self.reader

    def start_write(self, data):
        generator = self.tls.writeAsync(bytearray(data))
        self.active["write"] = generator
        return generator

    def start_keyupdate(self, message_type):
        generator = self.tls.send_keyupdate_request(message_type)
        self.active["keyupdate"] = generator
        return generator


def pump(endpoints, max_rounds=100):
    """Interleave the endpoints until every generator is blocked on I/O.

    Reads are driven through a single long-lived background generator per
    endpoint: it stays suspended (yielding 0) while no record is available
    and keeps running after it processes a KeyUpdate, so post-handshake
    messages are consumed automatically.  A round counts as progress only
    when a record actually moved (a generator finished or returned data),
    hence a blocked generator can never spin the loop.  Exceptions raised by
    a generator are propagated to the caller.
    """
    for endpoint in endpoints:
        if endpoint.reader is None:
            endpoint.new_reader()

    for _ in range(max_rounds):
        progressed = False
        for endpoint in endpoints:
            for name, generator in list(endpoint.active.items()):
                try:
                    value = next(generator)
                except StopIteration:
                    # write/control generator ran to completion
                    endpoint.active.pop(name, None)
                    progressed = True
                    continue
                if value in (0, 1):
                    # waiting for the non-blocking transport, keep it parked
                    continue
                progressed = True
                if isinstance(value, (bytes, bytearray)):
                    # application data: remember it and arm a fresh reader so
                    # records queued behind it are processed as well
                    endpoint.received.append(bytes(value))
                    endpoint.reader = None
                    endpoint.active.pop(name, None)
                    endpoint.new_reader()
                else:
                    endpoint.active.pop(name, None)
        if not progressed:
            return
    raise AssertionError("pump did not settle, possible request loop")


def drive(generator):
    """Run a generator to completion, retrying while it asks for I/O."""
    result = None
    while True:
        try:
            value = next(generator)
        except StopIteration:
            return result
        if value not in (0, 1):
            result = value


def drive_until_retry(generator, max_steps=10):
    """Advance a generator until it asks the transport to retry."""
    for _ in range(max_steps):
        value = next(generator)
        if value in (0, 1):
            return value
    raise AssertionError("generator never blocked on the transport")


def drain_app_data(endpoint):
    """Return application data collected by the background reader."""
    data = bytearray()
    while endpoint.received:
        data += endpoint.received.pop(0)
    return data


def make_endpoints():
    sock_a, sock_b = PausableSocket.make_pair("client", "server")
    client = Endpoint(sock_a, client=True)
    server = Endpoint(sock_b, client=False)
    return client, server


def assert_wire_pairs(test_case, client, server):
    """Every sent record must be opened by the peer with matching keys."""
    for sender, receiver in ((client, server), (server, client)):
        sent = [e for e in sender.wire_log if e["direction"] == "send"]
        received = [e for e in receiver.wire_log
                    if e["direction"] == "recv"]
        test_case.assertEqual(len(sent), len(received))
        for sent_entry, recv_entry in zip(sent, received):
            test_case.assertEqual(sent_entry["generation"],
                                  recv_entry["generation"])
            test_case.assertEqual(sent_entry["seqnum"],
                                  recv_entry["seqnum"])
            test_case.assertEqual(sent_entry["is_keyupdate"],
                                  recv_entry["is_keyupdate"])
            test_case.assertTrue(recv_entry["decrypt_ok"])


def keyupdate_entries(log):
    return [e for e in log if e["is_keyupdate"]]


class TestKeyUpdateInterleaving(unittest.TestCase):
    def test_update_not_requested_advances_only_write_generation(self):
        client, server = make_endpoints()

        drive(client.start_keyupdate(
            KeyUpdateMessageType.update_not_requested))
        pump((client, server))

        # sender rotates its own write keys, receiver its read keys
        self.assertEqual(1, client.record_layer.write_generation)
        self.assertEqual(0, client.record_layer.read_generation)
        self.assertEqual(1, server.record_layer.read_generation)
        self.assertEqual(0, server.record_layer.write_generation)

        # no reply is sent for an unsolicited update: the server's only
        # KeyUpdate record is the one it received, it never sent one
        self.assertEqual(0, len([e for e in server.wire_log
                                 if e["is_keyupdate"]
                                 and e["direction"] == "send"]))
        self.assertEqual(0, len([e for e in client.wire_log
                                 if e["is_keyupdate"]
                                 and e["direction"] == "recv"]))

        # the KeyUpdate is the last record protected by generation 0
        ku_entries = keyupdate_entries(client.wire_log)
        self.assertEqual(1, len(ku_entries))
        self.assertEqual((0, 0), (ku_entries[0]["generation"],
                                  ku_entries[0]["seqnum"]))

        drive(client.start_write(b"after update"))
        pump((client, server))
        app_entries = [e for e in client.wire_log
                       if e["content_type"] == ContentType.application_data]
        # following application record starts the new generation at seq zero
        self.assertEqual((1, 0), (app_entries[-1]["generation"],
                                  app_entries[-1]["seqnum"]))
        self.assertEqual(bytearray(b"after update"),
                         drain_app_data(server))
        assert_wire_pairs(self, client, server)

    def test_update_requested_gets_single_not_requested_reply(self):
        client, server = make_endpoints()

        drive(client.start_keyupdate(KeyUpdateMessageType.update_requested))
        pump((client, server))

        # both directions rotated exactly once
        self.assertEqual(1, client.record_layer.write_generation)
        self.assertEqual(1, client.record_layer.read_generation)
        self.assertEqual(1, server.record_layer.write_generation)
        self.assertEqual(1, server.record_layer.read_generation)

        # exactly one request and one reply on the wire, no mutual request
        # ping-pong: count only records each side itself sent
        client_sends = [e for e in keyupdate_entries(client.wire_log)
                        if e["direction"] == "send"]
        server_sends = [e for e in keyupdate_entries(server.wire_log)
                        if e["direction"] == "send"]
        client_recvs = [e for e in keyupdate_entries(client.wire_log)
                        if e["direction"] == "recv"]
        self.assertEqual(1, len(client_sends))
        self.assertEqual(1, len(server_sends))
        self.assertEqual(1, len(client_recvs))

        # request leaves under the client's generation 0; the server's reply
        # is still protected by its old write generation 0 - per RFC 8446 the
        # receiver rotates read keys first and only switches write keys after
        # emitting the reply KeyUpdate
        self.assertEqual((0, 0), (client_sends[0]["generation"],
                                  client_sends[0]["seqnum"]))
        self.assertEqual((0, 0), (server_sends[0]["generation"],
                                  server_sends[0]["seqnum"]))
        # but once the reply was sent, both write generations did advance
        self.assertEqual(1, server.record_layer.write_generation)
        assert_wire_pairs(self, client, server)

    def test_simultaneous_updates_do_not_loop(self):
        client, server = make_endpoints()
        # pause the transports so neither update reaches the peer before both
        # were sent
        client.sock.write_paused = True
        server.sock.write_paused = True

        client_gen = client.start_keyupdate(
            KeyUpdateMessageType.update_requested)
        server_gen = server.start_keyupdate(
            KeyUpdateMessageType.update_requested)
        # the first record byte may still be accepted, but the generators are
        # soon suspended by the blocked transport before any full record is
        # logged
        drive_until_retry(client_gen)
        drive_until_retry(server_gen)
        self.assertEqual(0, len(client.wire_log))
        self.assertEqual(0, len(server.wire_log))

        client.sock.write_paused = False
        server.sock.write_paused = False
        pump((client, server))

        # each side sent its own request plus a single reply to the peer's
        # request: two sends and two receives per side, nothing more (no loop)
        client_ku = keyupdate_entries(client.wire_log)
        self.assertEqual(4, len(client_ku))
        self.assertEqual(4, len(keyupdate_entries(server.wire_log)))
        self.assertEqual(["send", "recv", "send", "recv"],
                         [e["direction"] for e in client_ku])
        # the request uses generation 0, the not-requested reply generation 1
        self.assertEqual([0, 0, 1, 1],
                         [e["generation"] for e in client_ku])
        self.assertEqual(
            2, len([e for e in client_ku if e["direction"] == "send"]))

        # two generations in each direction, every sent update at seq zero
        for endpoint in (client, server):
            self.assertEqual(2, endpoint.record_layer.write_generation)
            self.assertEqual(2, endpoint.record_layer.read_generation)
            for entry in keyupdate_entries(endpoint.wire_log):
                if entry["direction"] == "send":
                    self.assertEqual(0, entry["seqnum"])
        assert_wire_pairs(self, client, server)

    def test_segmented_write_with_paused_socket_keeps_record_order(self):
        client, server = make_endpoints()
        # let the first 30 bytes of the application record leave, then block
        # the transport so the record is suspended half written
        client.sock.pause_after = 30

        generator = client.start_write(b"x" * 100)
        # drive it until the transport reports it cannot accept more
        drive_until_retry(generator)
        self.assertEqual(30, len(client.sock.peer._incoming))
        # the record is not complete, so it is not logged yet
        self.assertEqual(0, len(client.wire_log))

        # rotate keys while that application record is still stuck
        ku_generator = client.start_keyupdate(
            KeyUpdateMessageType.update_not_requested)
        drive_until_retry(ku_generator)

        # unblock both halves of the split record and the KeyUpdate
        client.sock.pause_after = None
        drive(generator)
        drive(ku_generator)
        pump((client, server))

        # app record leaves first under generation 0, then the KeyUpdate
        events = client.wire_log
        self.assertEqual(ContentType.application_data,
                         events[0]["content_type"])
        self.assertEqual((0, 0), (events[0]["generation"],
                                  events[0]["seqnum"]))
        self.assertTrue(events[1]["is_keyupdate"])
        self.assertEqual((0, 1), (events[1]["generation"],
                                  events[1]["seqnum"]))

        drive(client.start_write(b"tail"))
        pump((client, server))
        tail = [e for e in client.wire_log
                if e["content_type"] == ContentType.application_data][-1]
        self.assertEqual((1, 0), (tail["generation"], tail["seqnum"]))

        self.assertEqual(bytearray(b"x" * 100 + b"tail"),
                         drain_app_data(server))
        assert_wire_pairs(self, client, server)

    def test_consecutive_updates_reset_sequence_numbers_each_time(self):
        client, server = make_endpoints()

        drive(client.start_write(b"first"))
        pump((client, server))
        for _ in range(3):
            drive(client.start_keyupdate(
                KeyUpdateMessageType.update_not_requested))
            pump((client, server))
        drive(client.start_write(b"second"))
        pump((client, server))

        self.assertEqual(3, client.record_layer.write_generation)
        self.assertEqual(3, server.record_layer.read_generation)

        ku_entries = [e for e in keyupdate_entries(client.wire_log)
                      if e["direction"] == "send"]
        # the three updates open write generations 0, 1 and 2
        self.assertEqual([0, 1, 2], [e["generation"] for e in ku_entries])
        # the first update shares generation 0 with the earlier app record, so
        # it continues that sequence space; every later update is the first
        # record of a fresh generation and therefore restarts at zero
        self.assertEqual([1, 0, 0], [e["seqnum"] for e in ku_entries])
        # every write generation actually in use starts its counter at zero
        write_seqnums = {}
        for entry in client.wire_log:
            if entry["direction"] != "send":
                continue
            write_seqnums.setdefault(entry["generation"],
                                     entry["seqnum"])
        self.assertEqual(0, min(write_seqnums.values()))
        for generation in (1, 2, 3):
            self.assertEqual(0, write_seqnums[generation])

        app_entries = [e for e in client.wire_log
                       if e["content_type"] == ContentType.application_data]
        self.assertEqual([0, 3], [e["generation"] for e in app_entries])
        self.assertEqual([0, 0], [e["seqnum"] for e in app_entries])
        self.assertEqual(bytearray(b"firstsecond"),
                         drain_app_data(server))
        assert_wire_pairs(self, client, server)

    def test_unknown_key_update_value_is_rejected_without_state_change(self):
        client, server = make_endpoints()
        # smuggle a KeyUpdate with an unknown request value
        bad_msg = KeyUpdate().create(240)
        drive(client.tls._sendMsg(bad_msg))

        with self.assertRaises(TLSLocalAlert) as context:
            pump((client, server))
        self.assertEqual(AlertDescription.illegal_parameter,
                         context.exception.description)

        # the offending message was still decrypted under the current
        # generation and no key rotation happened on either side
        self.assertEqual(0, server.record_layer.read_generation)
        self.assertEqual(0, server.record_layer.write_generation)
        self.assertEqual(0, client.record_layer.write_generation)
        self.assertTrue(server.tls.closed)
        last_recv = [e for e in server.wire_log
                     if e["direction"] == "recv"][-1]
        self.assertTrue(last_recv["is_keyupdate"])
        self.assertEqual(0, last_recv["generation"])
        self.assertTrue(last_recv["decrypt_ok"])

        # the fatal alert is emitted with the still-current write generation
        alert_entries = [e for e in server.wire_log
                         if e["content_type"] == ContentType.alert]
        self.assertEqual(1, len(alert_entries))
        self.assertEqual(0, alert_entries[0]["generation"])

    def test_bad_mac_record_fails_in_place_without_key_rotation(self):
        client, server = make_endpoints()

        drive(client.start_write(b"good one"))
        pump((client, server))
        self.assertEqual(bytearray(b"good one"), drain_app_data(server))

        # emit two records from a fresh sender so no background reader can
        # consume them, then corrupt the second one in transit
        sender, _ = make_endpoints()
        _, receiver = make_endpoints()
        sender.sock.peer._incoming = bytearray()
        drive(sender.start_write(b"good"))
        good_wire = bytearray(sender.sock.peer._incoming)
        sender.sock.peer._incoming = bytearray()
        drive(sender.start_write(b"tampered"))
        bad_wire = bytearray(sender.sock.peer._incoming)
        self.assertTrue(bad_wire)
        bad_wire[-1] ^= 0xFF
        receiver.sock._incoming += good_wire + bad_wire

        with self.assertRaises(TLSLocalAlert) as context:
            pump((receiver,))
        self.assertEqual(AlertDescription.bad_record_mac,
                         context.exception.description)

        # keys are untouched and the failed attempt is kept in the wire log at
        # its exact on-wire position: the second record of generation 0
        self.assertEqual(0, receiver.record_layer.read_generation)
        recv_entries = [e for e in receiver.wire_log
                        if e["direction"] == "recv"]
        self.assertEqual(2, len(recv_entries))
        self.assertTrue(recv_entries[0]["decrypt_ok"])
        failure = recv_entries[-1]
        self.assertFalse(failure["decrypt_ok"])
        self.assertEqual(0, failure["generation"])
        self.assertEqual(1, failure["seqnum"])
        self.assertTrue(receiver.tls.closed)

        # and the alert goes out with the still-current generation
        alert_entries = [e for e in receiver.wire_log
                         if e["content_type"] == ContentType.alert]
        self.assertEqual(1, len(alert_entries))
        self.assertEqual(0, alert_entries[0]["generation"])

    def test_send_keyupdate_rejected_below_tls_1_3(self):
        client, _ = make_endpoints()
        client.tls.version = (3, 3)
        with self.assertRaises(TLSIllegalParameterException):
            drive(client.start_keyupdate(
                KeyUpdateMessageType.update_not_requested))


if __name__ == "__main__":
    unittest.main()
