"""
Scenario 3 — authentication FAILURE: CertificateVerify does not verify.

The client presents a valid-looking certificate chain but signs the
CertificateVerify with a private key that does not match the end-entity
certificate. In _handle_srv_pha the library recomputes the handshake
context and calls the public key's verify(); on failure it sends a fatal
decrypt_error alert and raises TLSLocalAlert. The session's clientCertChain
is only assigned AFTER all checks pass (the last line of _handle_srv_pha),
so a failed PHA leaves the previous identity (here: anonymous) untouched.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tlslite.constants import AlertDescription
from tlslite.errors import TLSRemoteAlert, TLSAbruptCloseError, TLSLocalAlert

from demo_pha_common import (TLS13, Gate, Log, join, run_in_thread,
                             tls13_handshake, identity,
                             CLIENT_CHAIN, FOREIGN_KEY)


def main():
    slog, clog = Log("server"), Log("client")
    # honest chain, wrong key — the PHA extension is still advertised because
    # a private key is present, but the signature cannot verify.
    server, client = tls13_handshake(slog, clog, CLIENT_CHAIN, FOREIGN_KEY)
    requested = Gate()
    client_state = {}

    def client_worker():
        requested.wait()
        try:
            client.read(0, 0)  # builds + sends Certificate/CV/Finished
            client.read()      # observes the server's fatal reaction
        except TLSRemoteAlert as exc:
            client_state["error"] = exc
            clog("received fatal alert %s (%d)"
                 % (AlertDescription.toStr(exc.description),
                    exc.description))
        except TLSAbruptCloseError:
            client_state["error"] = "abrupt-close"
            clog("connection torn down (abrupt close)")

    thread, result = run_in_thread(client_worker)

    for _ in server.request_post_handshake_auth(TLS13):
        pass
    slog("CertificateRequest sent")
    requested.open()

    server_error = None
    try:
        server.read(0, 0)
    except TLSLocalAlert as exc:
        server_error = exc
        slog("local fatal alert %s (%d): %s"
             % (AlertDescription.toStr(exc.description),
                exc.description, exc))

    assert isinstance(server_error, TLSLocalAlert)
    assert server_error.description == AlertDescription.decrypt_error
    # wait for the client thread to actually observe the fatal teardown
    join(thread, result)
    assert client_state.get("error") is not None
    # the assignment never happened: identity is exactly what it was before
    assert server.session.clientCertChain is None
    slog("post-failure session.clientCertChain = %r, identity = %s"
         % (server.session.clientCertChain, identity(server)))
    slog("=> a failed PHA is atomic at the library boundary: no partial "
         "identity is ever observable")

    print("\nSCENARIO 3 OK: bad CertificateVerify rejected with fatal "
          "decrypt_error; pre-PHA identity retained.")


if __name__ == "__main__":
    main()
