"""
Scenario 1 — application records and PHA handshake records interleaved.

Timeline (single TCP byte stream, one TLS connection):

  client -> server : ApplicationData "anonymous probe"   (sent BEFORE PHA)
  server -> client : CertificateRequest (PHA, random context)
  client -> server : Certificate / CertificateVerify / Finished (auto-answered
                     inside the client's own read() loop, see _handle_pha)
  client -> server : ApplicationData "authenticated request" (sent AFTER PHA)

The server's read() loop accepts BOTH content types while a PHA request is
outstanding (TLSRecordLayer.readAsync: allowedTypes includes
application_data and handshake). Handshake records are consumed internally
and never reach the application buffer; only ApplicationData records come
back from read(). The application decides, using its own auth-state, which
bytes are admissible.

Threading note: a blocking socketpair() means each peer must keep its own
record layer pumped. The client thread parks in read(0,0), which both waits
for the CertificateRequest and automatically answers it.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from demo_pha_common import (TLS13, Gate, Log, join, run_in_thread,
                             tls13_handshake, identity,
                             CLIENT_CHAIN, CLIENT_KEY)


def main():
    slog, clog = Log("server"), Log("client")
    server, client = tls13_handshake(slog, clog, CLIENT_CHAIN, CLIENT_KEY)

    request_sent = Gate()      # server has issued the PHA request
    pha_done_client = Gate()   # client's read loop finished the PHA exchange

    def client_worker():
        # 1) data on the still-anonymous connection
        client.send(b"anonymous probe")
        clog("sent app data while ANONYMOUS: 'anonymous probe'")

        # 2) park in the read loop: CertificateRequest arrives and is answered
        #    automatically by _handle_pha; read(0,0) returns once pumped.
        request_sent.wait()
        pumped = client.read(0, 0)
        assert pumped == b""
        clog("read(0,0) auto-answered CertificateRequest "
             "(Certificate/CertificateVerify/Finished sent)")
        pha_done_client.open()

        # 3) app record after the PHA exchange completed locally
        client.send(b"authenticated request")
        clog("sent app data after PHA completed: 'authenticated request'")

    thread, result = run_in_thread(client_worker)

    # --- server side -------------------------------------------------------
    slog("identity before PHA: %s" % identity(server))

    # drain the probe that crossed the (not yet sent) CertificateRequest
    probe = server.read()
    slog("read() returned %r while identity is still %s"
         % (probe, identity(server)))
    assert probe == b"anonymous probe"
    assert identity(server) == "ANONYMOUS"
    slog("=> library delivered the bytes; the app auth-gate still says "
         "ANONYMOUS, so the request is refused at the application layer")

    # issue PHA: the generator only SENDS CertificateRequest, it does not wait
    for _ in server.request_post_handshake_auth(TLS13):
        pass
    slog("request_post_handshake_auth() returned; CertificateRequest sent, "
         "identity still %s" % identity(server))
    request_sent.open()

    # Pumping with min==0 processes the client's Certificate/CV/Finished
    # without requiring any application data.
    pumped = server.read(0, 0)
    assert pumped == b""
    slog("read(0,0) processed the PHA handshake; identity now: %s"
         % identity(server))
    assert identity(server) != "ANONYMOUS"

    pha_done_client.wait()
    request = server.read()
    slog("read() returned %r under identity %s" % (request, identity(server)))
    assert request == b"authenticated request"
    slog("=> same read() API, but now the app auth-gate admits the request")

    join(thread, result)
    server.close()
    client.close()
    print("\nSCENARIO 1 OK: interleaving preserved; authorization is an "
          "application decision layered over the TLS session state.")


if __name__ == "__main__":
    main()
