"""
Scenario 4 — successful PHA, request-context correlation, identity refresh.

Two sensitive requests are issued on the SAME connection, each gated by its
own PHA round. tlslite-ng generates a fresh random 32-byte
certificate_request_context per request (request_post_handshake_auth),
remembers it in _cert_requests, and the client must echo it verbatim;
_handle_srv_pha pops the matching entry and rejects an unknown or reused
context with a fatal illegal_parameter alert. The library does not expose
that context to the application, so the demo shows the equivalent
application-level correlation token and explains the mapping.

The second round re-authenticates and replaces session.clientCertChain,
demonstrating that identity is per-connection state and can be refreshed.
"""

import sys
import os
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from demo_pha_common import (TLS13, Gate, Log, join, run_in_thread,
                             tls13_handshake, identity,
                             CLIENT_CHAIN, CLIENT_KEY,
                             CLIENT_CHAIN_EC, CLIENT_KEY_EC)


class AppGateway:
    """Application-layer admission control sitting on top of one TLS conn."""

    def __init__(self, conn, log):
        self.conn = conn
        self.log = log
        # maps application request id -> the identity observed when its PHA
        # round was driven to completion
        self.verified = {}

    def challenge(self, request_id):
        # one fresh TLS-level certificate_request_context is generated here
        # internally and remembered in conn._cert_requests
        for _ in self.conn.request_post_handshake_auth(TLS13):
            pass
        self.log("request %s: CertificateRequest sent (TLS context is "
                 "library-private)" % request_id)

    def complete(self, request_id):
        # pumping read(0,0) runs _handle_srv_pha: TLS context is matched to
        # the outstanding request, Finished verified, then clientCertChain
        # is assigned — the single observable success point.
        self.conn.read(0, 0)
        peer_identity = identity(self.conn)
        assert peer_identity != "ANONYMOUS"
        self.verified[request_id] = peer_identity
        self.log("request %s: PHA completed, bound to identity %s"
                 % (request_id, peer_identity))
        return peer_identity

    def admit(self, request_id):
        if request_id not in self.verified:
            self.log("request %s: REFUSED, no completed PHA on record"
                     % request_id)
            return False
        self.log("request %s: admitted as %s"
                 % (request_id, self.verified[request_id]))
        return True


def main():
    slog, clog = Log("server"), Log("client")
    server, client = tls13_handshake(slog, clog, CLIENT_CHAIN, CLIENT_KEY)
    gateway = AppGateway(server, slog)
    requested = Gate()

    def client_worker():
        requested.wait()
        requested._event.clear()
        client.read(0, 0)  # round 1: RSA identity
        clog("answered CertificateRequest #1 with the RSA client cert")

        # The PHA credential is connection-level state in tlslite-ng
        # (TLSConnection._client_keypair, set during the initial handshake).
        # Switching it models the user selecting a different identity in a
        # real client before answering the next challenge.
        client._client_keypair = (CLIENT_CHAIN_EC, CLIENT_KEY_EC)
        requested.wait()
        requested._event.clear()
        client.read(0, 0)  # round 2: EC identity
        clog("answered CertificateRequest #2 with the EC client cert")

    thread, result = run_in_thread(client_worker)

    # ---- request #1 arrives while anonymous -> challenge -> complete -----
    req1 = uuid.uuid4().hex[:8]
    slog("request %s arrived while identity = %s"
         % (req1, identity(server)))
    assert not gateway.admit(req1)
    gateway.challenge(req1)
    requested.open()
    identity_one = gateway.complete(req1)
    assert gateway.admit(req1)

    # proof the two layers keep separate correlation spaces: the TLS context
    # exists inside the library, the application keeps its own request id
    assert len(server._cert_requests) == 0  # popped when matched
    slog("outstanding TLS contexts after completion: %d"
         % len(server._cert_requests))

    # ---- request #2: a second PHA round on the same connection -----------
    req2 = uuid.uuid4().hex[:8]
    gateway.challenge(req2)
    requested.open()
    identity_two = gateway.complete(req2)
    assert identity_two != identity_one  # replaced by the EC identity
    assert gateway.admit(req2)
    slog("connection identity refreshed: %s -> %s"
         % (identity_one, identity_two))
    assert identity(server) == identity_two

    # ---- a request that never ran a PHA round must stay inadmissible ----
    req3 = uuid.uuid4().hex[:8]
    assert not gateway.admit(req3)

    join(thread, result)
    server.close()
    client.close()
    print("\nSCENARIO 4 OK: each PHA round correlates via its TLS context "
          "inside the library; the app binds the observed identity to its "
          "own request id at completion time.")


if __name__ == "__main__":
    main()
