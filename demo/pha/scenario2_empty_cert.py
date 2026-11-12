"""
Scenario 2 — client answers with an EMPTY certificate.

To advertise post_handshake_auth the client still needs a private key at
handshake time (the extension is added when certParams[1] is set), but the
chain itself may be an empty X509CertChain(). Its Certificate message then
carries an empty certificate_list and no CertificateVerify is sent
(_handle_pha only signs when cert.x509List and p_key are both present).

Two server policies:

  A) client_cert_required = False (default):
     empty answer is accepted at the TLS layer; the parsed Certificate has
     no entries so its cert_chain property is None (messages.py), and
     session.clientCertChain therefore stays None. The application must
     treat that as anonymous.

  B) client_cert_required = True:
     the library sends a fatal certificate_required alert and tears the
     connection down (_handle_srv_pha, tlsrecordlayer.py).
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tlslite import X509CertChain
from tlslite.constants import AlertDescription
from tlslite.errors import (TLSRemoteAlert, TLSAbruptCloseError,
                             TLSLocalAlert)

from demo_pha_common import (TLS13, Gate, Log, join, run_in_thread,
                             tls13_handshake, identity, CLIENT_KEY)


EMPTY_CHAIN = X509CertChain()


def run_case(required, slog, clog):
    slog("---- policy: client_cert_required = %s ----" % required)
    server, client = tls13_handshake(slog, clog, EMPTY_CHAIN, CLIENT_KEY)
    requested = Gate()
    errors = []

    def client_worker():
        requested.wait()
        try:
            client.read(0, 0)  # auto-answer with the empty chain
            clog("empty Certificate + Finished sent; read(0,0) returned")
            if required:
                client.read()  # next read observes the fatal teardown
        except TLSRemoteAlert as exc:
            clog("received fatal alert %s (%s)"
                 % (AlertDescription.toStr(exc.description), exc.description))
            errors.append(exc)
        except TLSAbruptCloseError:
            # on a raw socketpair the fatal alert may be followed immediately
            # by socket close, which surfaces as an abrupt close to the peer
            clog("peer tore the connection down after its fatal alert")
            errors.append("abrupt-close")

    thread, result = run_in_thread(client_worker)

    server.client_cert_required = required
    for _ in server.request_post_handshake_auth(TLS13):
        pass
    slog("CertificateRequest sent")
    requested.open()

    server_error = None
    try:
        pumped = server.read(0, 0)
        slog("read(0,0) returned %r; clientCertChain = %r"
             % (pumped, server.session.clientCertChain))
    except TLSLocalAlert as exc:
        server_error = exc
        slog("local fatal alert %s (%d): %s"
             % (AlertDescription.toStr(exc.description),
                exc.description, exc))

    join(thread, result)
    return server, client, errors, server_error


def main():
    slog, clog = Log("server"), Log("client")

    # Case A: optional authentication — empty answer tolerated by TLS
    server, client, client_errors, server_error = run_case(False, slog, clog)
    assert server_error is None
    assert server.session.clientCertChain is None
    assert identity(server) == "ANONYMOUS"
    slog("app-observable identity after empty PHA: %s" % identity(server))
    slog("=> transport stayed open, but no identity was established; the "
         "sensitive API must still return 401/403")
    server.close()
    client.close()

    # Case B: required authentication — library enforces a non-empty answer
    server, client, client_errors, server_error = run_case(True, slog, clog)
    assert isinstance(server_error, TLSLocalAlert)
    assert server_error.description == AlertDescription.certificate_required
    assert client_errors  # remote alert on real sockets, abrupt close here
    assert server.session.clientCertChain is None
    slog("connection closed by library; identity remains unauthenticated")
    slog("=> with client_cert_required=True the refusal is enforced at the "
         "TLS layer, no application code can accidentally admit the peer")

    print("\nSCENARIO 2 OK: empty certificate handled per policy; the app "
          "never observes an identity for the empty answer.")


if __name__ == "__main__":
    main()
