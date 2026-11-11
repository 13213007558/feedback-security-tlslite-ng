# Copyright (c) 2014, George Pantelakis
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

import zlib

from tlslite.utils.compression import compression_algo_impls, \
    choose_compression_send_algo, zlib_decompress_limited, \
    MAX_DECOMPRESSED_CERTIFICATE_SIZE, DECOMPRESSION_CHUNK_SIZE
from tlslite.errors import TLSDecodeError

class TestCompression(unittest.TestCase):
    def setUp(self):
        class DummyExtension():
            algorithms = None

            def change_algos(self, algos):
                self.algorithms = algos

        self.extension = DummyExtension()

    def test_compression_algo_impls(self):
        self.assertIsNotNone(compression_algo_impls)
        self.assertIn("brotli_compress", compression_algo_impls)
        self.assertIn("brotli_decompress", compression_algo_impls)
        self.assertIn("brotli_accepts_limit", compression_algo_impls)
        self.assertIn("zstd_compress", compression_algo_impls)
        self.assertIn("zstd_decompress", compression_algo_impls)
        self.assertIn("zstd_accepts_limit", compression_algo_impls)

    def test_choose_compression_send_algo_sanity(self):
        self.extension.change_algos([1])
        algo = choose_compression_send_algo((3, 4), self.extension, ['zlib'])
        self.assertEqual(algo, 1)

    def test_choose_compression_send_algo_previous_tls_version(self):
        self.extension.change_algos([1])
        algo = choose_compression_send_algo((3, 2), self.extension, ['zlib'])
        self.assertIsNone(algo)

    def test_choose_compression_send_algo_no_tls_version(self):
        self.extension.change_algos([1])
        algo = choose_compression_send_algo(None, self.extension, ['zlib'])
        self.assertIsNone(algo)

    def test_choose_compression_send_algo_choose_first_common(self):
        self.extension.change_algos([1, 2])
        algo = choose_compression_send_algo(
            (3, 4), self.extension, ['zlib', 'brotli'])
        self.assertEqual(algo, 1)

    def test_choose_compression_send_algo_empty_extension_algos(self):
        self.extension.change_algos([])
        with self.assertRaises(TLSDecodeError):
            choose_compression_send_algo((3, 4), self.extension, ['zlib'])

    def test_choose_compression_send_algo_empty_accepted_algos(self):
        self.extension.change_algos([1])
        algo = choose_compression_send_algo((3, 4), self.extension, [])
        self.assertIsNone(algo)

    def test_choose_compression_send_algo_none_extension_algos(self):
        self.extension.change_algos(None)
        with self.assertRaises(TLSDecodeError):
            choose_compression_send_algo((3, 4), self.extension, ['zlib'])

    def test_choose_compression_send_algo_no_common_algos(self):
        self.extension.change_algos([2])
        algo = choose_compression_send_algo((3, 4), self.extension, ['zlib'])
        self.assertIsNone(algo)


class TestZlibDecompressLimited(unittest.TestCase):
    def test_decompresses_valid_stream(self):
        msg = b"compressed certificate payload " * 64
        compressed = zlib.compress(msg)

        self.assertEqual(
            bytes(zlib_decompress_limited(compressed, len(msg))), msg)

    def test_cap_equal_to_output_is_accepted(self):
        msg = b"x" * 1000
        compressed = zlib.compress(msg)

        self.assertEqual(
            bytes(zlib_decompress_limited(compressed, 1000)), msg)

    def test_cap_one_byte_too_small_is_rejected(self):
        msg = b"x" * 1000
        compressed = zlib.compress(msg)

        with self.assertRaises(BufferError):
            zlib_decompress_limited(compressed, len(msg) - 1)

    def test_bomb_is_rejected_before_full_expansion(self):
        # a few KiB of input that would expand to tens of MiB
        compressed = zlib.compress(b"\x00" * (32 * 1024 * 1024), 9)
        self.assertLess(len(compressed), 64 * 1024)

        with self.assertRaises(BufferError):
            zlib_decompress_limited(
                compressed, MAX_DECOMPRESSED_CERTIFICATE_SIZE)

    def test_truncated_stream_is_rejected(self):
        compressed = zlib.compress(b"payload " * 256)

        with self.assertRaises(zlib.error):
            zlib_decompress_limited(compressed[:-4], 1024 * 1024)

    def test_trailing_data_is_rejected(self):
        compressed = zlib.compress(b"payload " * 256)

        with self.assertRaises(zlib.error):
            zlib_decompress_limited(
                compressed + b"trailing bytes", 1024 * 1024)

    def test_malformed_stream_is_rejected(self):
        with self.assertRaises(zlib.error):
            zlib_decompress_limited(b"not a zlib stream", 1024 * 1024)

    def test_empty_stream(self):
        compressed = zlib.compress(b"")

        self.assertEqual(
            bytes(zlib_decompress_limited(compressed, 1024)), b"")

    def test_peak_output_never_exceeds_cap_plus_a_chunk(self):
        # streaming expansion must keep the output buffer bounded even when
        # a small input would expand to a lot of data
        compressed = zlib.compress(b"\x00" * (4 * 1024 * 1024), 9)
        cap = 64 * 1024
        observed_sizes = []

        with self.assertRaises(BufferError):
            zlib_decompress_limited(
                compressed, cap, observer=observed_sizes.append)

        self.assertTrue(observed_sizes)
        # overshoot is limited to a single expansion step past the cap
        self.assertLessEqual(
            max(observed_sizes), cap + DECOMPRESSION_CHUNK_SIZE)
        # and the buffer never came close to holding the full 4 MiB output
        self.assertLess(max(observed_sizes), 256 * 1024)
