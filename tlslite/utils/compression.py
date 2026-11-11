# Authors:
#   George Pantelakis
#
# See the LICENSE file for legal information regarding use of this file.

"""compression module

This module has basic supported compression modules."""

import zlib

from ..constants import CertificateCompressionAlgorithm
from .lists import getFirstMatching
from ..errors import TLSDecodeError

# Trusted upper bound on the size of a decompressed Certificate message.
#
# The uncompressed length advertised by the peer in a CompressedCertificate
# message is attacker controlled and so it can't be used as a memory budget.
# All decompression backends are fed this limit while the stream is being
# expanded so that a "compression bomb" is rejected before the output buffer
# grows past the bound instead of after the whole message was allocated.
MAX_DECOMPRESSED_CERTIFICATE_SIZE = 1024 * 1024

# Size of the chunks fed to a streaming decompressor. The output buffer of a
# bounded decompression therefore never grows past
# ``MAX_DECOMPRESSED_CERTIFICATE_SIZE`` plus a single chunk.
DECOMPRESSION_CHUNK_SIZE = 16384

compression_algo_impls = {
    "brotli_compress": None,
    "brotli_decompress": None,
    "brotli_accepts_limit": None,
    "zstd_compress": None,
    "zstd_decompress": None,
    "zstd_accepts_limit": None
}

try:
    import brotli
    compression_algo_impls["brotli_compress"] = brotli.compress
    compression_algo_impls["brotli_decompress"] = brotli.decompress
    compression_algo_impls["brotli_accepts_limit"] = False
except ImportError:
    try:
        from .brotlidecpy import decompress
        compression_algo_impls["brotli_decompress"] = decompress
        compression_algo_impls["brotli_accepts_limit"] = True
    except ImportError:
        pass

try:
    import zstandard
    compression_algo_impls["zstd_compress"] = zstandard.compress
    compression_algo_impls["zstd_decompress"] = zstandard.decompress
    compression_algo_impls["zstd_accepts_limit"] = True
except ImportError:
    try:
        import zstd
        compression_algo_impls["zstd_compress"] = zstd.compress
        compression_algo_impls["zstd_decompress"] = zstd.decompress
    except ImportError:
        pass


def choose_compression_send_algo(version, extension, valid_algos):
    if not extension or not version or version < (3, 4):
        return None

    chosen_compression_algo = None
    advertized_algos = extension.algorithms

    if not advertized_algos:
        raise TLSDecodeError("Empty algorithm list in compress_certificate "
                             "extension")

    if advertized_algos:
        supported_comp_algos = []
        for algo in valid_algos:
            try:
                supported_comp_algos.append(
                    getattr(CertificateCompressionAlgorithm, algo))
            except AttributeError:
                pass

        if supported_comp_algos:
            chosen_compression_algo = getFirstMatching(
                advertized_algos, supported_comp_algos)

    return chosen_compression_algo


def zlib_decompress_limited(compressed_msg, max_output_size, observer=None):
    """Decompress a zlib stream while enforcing a hard output size cap.

    The cap is applied while the stream is being expanded (never after the
    full message has been materialised), so a peer that advertises a small
    uncompressed length but sends a highly compressible payload can't make us
    allocate an unbounded amount of memory.

    The whole stream has to be consumed: a truncated stream (missing end of
    stream marker) or trailing data after the stream are both rejected.

    :param bytes compressed_msg: the zlib compressed payload
    :param int max_output_size: trusted maximum size of the decompressed data
    :param callable observer: optional callback invoked with the current size
        of the output buffer after every expansion step (used by tests to
        assert the transient memory bound)

    :rtype: bytearray
    :raises zlib.error: on malformed or truncated streams
    :raises BufferError: when the decompressed data exceeds ``max_output_size``
    """
    decompressor = zlib.decompressobj()
    output = bytearray()
    # Feed the stream in bounded chunks so that the output buffer never grows
    # past the cap plus a single chunk.
    chunk_size = DECOMPRESSION_CHUNK_SIZE
    for offset in range(0, len(compressed_msg), chunk_size):
        chunk = compressed_msg[offset:offset + chunk_size]
        while True:
            produced = decompressor.decompress(
                chunk, max_output_size - len(output) + 1)
            output += produced
            if observer is not None:
                observer(len(output))
            if len(output) > max_output_size:
                raise BufferError(
                    "Decompressed certificate exceeds the maximum allowed "
                    "size of {0} bytes".format(max_output_size))
            if not decompressor.unconsumed_tail:
                break
            chunk = decompressor.unconsumed_tail
    if not decompressor.eof:
        raise zlib.error("Truncated compressed certificate stream")
    if decompressor.unused_data:
        raise zlib.error("Trailing data after compressed certificate stream")
    return output
