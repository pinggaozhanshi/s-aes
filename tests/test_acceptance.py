"""课程五关的本地可复现验收；真实组间互测必须另行执行。"""

import json
from pathlib import Path
import random
from tempfile import TemporaryDirectory
from threading import Event
import unittest

import reference_saes as reference
from saes.core import (encrypt_block, decrypt_block, expand_key, gf_multiply,
                       mix_columns, shift_rows, substitute_nibbles, trace_block)
from saes.encoding import (parse_fixed, parse_hex_bytes, encode_ascii, escaped_bytes,
                           pad_bytes, unpad_bytes, bytes_to_blocks, blocks_to_bytes)
from saes.modes import (split_key, transform_block, transform_bytes, cbc_process,
                        compare_cbc_tampering, generate_iv)
from saes.attack import meet_in_the_middle
from saes.records import build_record, write_record


class CoreAcceptance(unittest.TestCase):
    def test_published_vector_and_each_stage(self):
        expected = [0xA749, 0x8A1C, 0x604C, 0x6C40, 0x3743,
                    0x8BAA, 0x6300, 0x6003, 0xC349]
        self.assertEqual(expand_key(0x2D55), (0x2D55, 0xBCE9, 0xA34A))
        self.assertEqual([s.state for s in trace_block(0xA749, 0x2D55)], expected)
        self.assertEqual(encrypt_block(0xA749, 0x2D55), 0xC349)
        self.assertEqual([s.state for s in trace_block(0xC349, 0x2D55, True)], expected[::-1])
        self.assertEqual(decrypt_block(0xC349, 0x2D55), 0xA749)

    def test_second_known_vector(self):
        self.assertEqual(encrypt_block(0xD728, 0x4AF5), 0x24EC)
        self.assertEqual(decrypt_block(0x24EC, 0x4AF5), 0xD728)

    def test_polynomial_multiplication_all_256_pairs(self):
        for left in range(16):
            for right in range(16):
                self.assertEqual(gf_multiply(left, right), reference.multiply(left, right))

    def test_transform_inverses_all_65536_states(self):
        for state in range(65536):
            self.assertEqual(substitute_nibbles(substitute_nibbles(state), True), state)
            self.assertEqual(shift_rows(shift_rows(state)), state)
            self.assertEqual(mix_columns(mix_columns(state), True), state)

    def test_all_blocks_for_three_keys_and_bijection(self):
        for key in (0x0000, 0x2D55, 0xFFFF):
            ciphertexts = set()
            for block in range(65536):
                cipher = encrypt_block(block, key)
                ciphertexts.add(cipher)
                self.assertEqual(decrypt_block(cipher, key), block)
            self.assertEqual(len(ciphertexts), 65536)

    def test_all_keys_for_fixed_plaintext(self):
        for key in range(65536):
            self.assertEqual(decrypt_block(encrypt_block(0xA749, key), key), 0xA749)

    def test_reference_implementation_2048_samples(self):
        rng = random.Random(20261027)
        for _ in range(2048):
            plain, key = rng.randrange(65536), rng.randrange(65536)
            expected = reference.encrypt(plain, key)
            self.assertEqual(encrypt_block(plain, key), expected)
            self.assertEqual(decrypt_block(expected, key), reference.decrypt(expected, key))
            self.assertEqual(trace_block(plain, key)[-1].state, expected)

    def test_reject_out_of_range_and_noninteger_blocks_keys(self):
        for bad in (-1, 65536, True, 1.5, '1234', None):
            for function, args in ((encrypt_block, (bad, 0)), (decrypt_block, (0, bad)),
                                   (expand_key, (bad,))):
                with self.assertRaises(ValueError):
                    function(*args)
        for bad in (-1, 16, False):
            with self.assertRaises(ValueError):
                gf_multiply(bad, 1)


class EncodingAcceptance(unittest.TestCase):
    def test_leading_zero_binary_prefix_and_whitespace(self):
        self.assertEqual(parse_fixed('0x 00 0A', 16), 10)
        self.assertEqual(parse_fixed('0B0000 0000 0000 1010', 16, 'bin'), 10)
        self.assertEqual(parse_hex_bytes('00 0A\nFF'), b'\0\x0a\xff')

    def test_invalid_width_character_base_and_hex_bytes(self):
        for value in ('', '123', '12345', '-001', 'GGGG'):
            with self.assertRaises(ValueError):
                parse_fixed(value, 16)
        with self.assertRaises(ValueError):
            parse_fixed('0' * 15 + '2', 16, 'bin')
        with self.assertRaises(ValueError):
            parse_fixed('0000', 16, 'oct')
        for value in ('', 'A', 'XZ', '0x12'):
            with self.assertRaises(ValueError):
                parse_hex_bytes(value)

    def test_padding_known_bytes_and_rejection(self):
        for plain, padded in ((b'', b'\x02\x02'), (b'A', b'A\x01'),
                              (b'AB', b'AB\x02\x02'), (b'ABC', b'ABC\x01')):
            self.assertEqual(pad_bytes(plain), padded)
            self.assertEqual(unpad_bytes(padded), plain)
        for bad in (b'', b'A', b'AB', b'A\0', b'A\x03', b'A\x02'):
            with self.assertRaises(ValueError):
                unpad_bytes(bad)

    def test_byte_order_and_ascii_control_characters(self):
        self.assertEqual(bytes_to_blocks(b'AB\0\x01'), [0x4142, 0x0001])
        self.assertEqual(blocks_to_bytes([0x4142, 0x0001]), b'AB\0\x01')
        self.assertEqual(encode_ascii(' A\n\t\0 '), b' A\n\t\0 ')
        self.assertIn('\\x00', escaped_bytes(b'\0'))
        with self.assertRaises(ValueError):
            encode_ascii('中文')
        with self.assertRaises(ValueError):
            bytes_to_blocks(b'A')


class ModesAcceptance(unittest.TestCase):
    def test_ee_eee_independent_layer_order_and_inverse(self):
        for keys in ((0x2D55,), (0x2D55, 0x1234), (0x2D55, 0x1234, 0xABCD)):
            key = int(''.join(f'{part:04x}' for part in keys), 16)
            self.assertEqual(split_key(key, len(keys)), keys)
            for plain in (0, 1, 0xA749, 0xFFFF):
                expected = plain
                for part in keys:
                    expected = reference.encrypt(expected, part)
                self.assertEqual(transform_block(plain, key, len(keys)), expected)
                self.assertEqual(transform_block(expected, key, len(keys), True), plain)

    def test_ascii_lengths_and_single_padding_for_all_schemes(self):
        for count, key in ((1, 0x2D55), (2, 0x2D551234), (3, 0x2D551234ABCD)):
            for plain in (b'', b'A', b'AB', b'ABC', b' A\n\t\0 ', bytes(range(128)), b'x' * 1001):
                cipher = transform_bytes(plain, key, count)
                self.assertEqual(len(cipher), (len(plain) // 2 + 1) * 2)
                self.assertEqual(transform_bytes(cipher, key, count, True), plain)
                expected = []
                for block in bytes_to_blocks(pad_bytes(plain)):
                    for part in split_key(key, count):
                        block = reference.encrypt(block, part)
                    expected.append(block)
                self.assertEqual(cipher, blocks_to_bytes(expected))

    def test_unpadded_mode_and_invalid_inputs(self):
        self.assertEqual(transform_bytes(b'\xa7\x49', 0x2D55, padding=False), b'\xc3\x49')
        for function, args in ((split_key, (0, 4)), (split_key, (1 << 32, 2)),
                               (transform_bytes, (b'', 0, 1, True)),
                               (transform_bytes, (b'A', 0, 1, True)),
                               (cbc_process, (b'', 0, 0, True)),
                               (cbc_process, (b'AB', 0, 65536))):
            with self.assertRaises(ValueError):
                function(*args)

    def test_cbc_independent_chain_and_roundtrip(self):
        for plain in (b'', b'A', b'AB', b'Hello S-AES CBC!', b' \n\0 ', b'x' * 1001):
            cipher, trace = cbc_process(plain, 0x2D55, 0x1234)
            chain, expected = 0x1234, []
            for index, block in enumerate(bytes_to_blocks(pad_bytes(plain))):
                output = reference.encrypt(block ^ chain, 0x2D55)
                self.assertEqual((trace[index].chain, trace[index].intermediate), (chain, block ^ chain))
                expected.append(output)
                chain = output
            self.assertEqual(cipher, blocks_to_bytes(expected))
            restored, inverse_trace = cbc_process(cipher, 0x2D55, 0x1234, True)
            self.assertEqual(restored, plain)
            self.assertEqual(len(inverse_trace), len(trace))

    def test_cbc_iv_changes_first_chain_and_wrong_iv_only_first_plain_block(self):
        plain = b'ABCDEFGH'
        cipher, _ = cbc_process(plain, 0x2D55, 0x1234)
        other, _ = cbc_process(plain, 0x2D55, 0x1235)
        self.assertNotEqual(cipher, other)
        decoded, _ = cbc_process(cipher, 0x2D55, 0x1235, True)
        self.assertEqual(decoded, b'AC' + plain[2:])
        for _ in range(128):
            self.assertTrue(0 <= generate_iv() < 65536)

    def test_cbc_first_middle_last_xor_and_replacement_propagation(self):
        cipher, _ = cbc_process(b'Hello S-AES CBC!', 0x2D55, 0x1234)
        blocks = bytes_to_blocks(cipher)
        for index in (0, 3, len(blocks) - 1):
            for replace in (False, True):
                value = blocks[index] ^ 1 if replace else 1
                result = compare_cbc_tampering(cipher, 0x2D55, 0x1234, index, value, replace)
                expected = (index, index + 1) if index + 1 < len(blocks) else (index,)
                self.assertEqual(result.changed_blocks, expected)
                before = bytes_to_blocks(result.original_raw)
                after = bytes_to_blocks(result.modified_raw)
                if index + 1 < len(blocks):
                    self.assertEqual(before[index + 1] ^ after[index + 1], 1)
                if index == len(blocks) - 1:
                    self.assertIsNotNone(result.modified_padding_error)

    def test_cbc_tampering_invalid_index_noop_and_invalid_cipher(self):
        cipher, _ = cbc_process(b'ABCD', 0x2D55, 0x1234)
        for index, value, replace in ((-1, 1, False), (3, 1, False), (True, 1, False),
                                      (0, 0, False), (0, int.from_bytes(cipher[:2], 'big'), True)):
            with self.assertRaises(ValueError):
                compare_cbc_tampering(cipher, 0x2D55, 0x1234, index, value, replace)


class AttackAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = (0x2D55, 0x1234)
        cls.pairs = [(p, reference.encrypt(reference.encrypt(p, cls.key[0]), cls.key[1]))
                     for p in (0xA749, 0x1234, 0)]

    def test_full_single_pair_preserves_collisions_and_real_key(self):
        result = meet_in_the_middle(self.pairs[:1])
        self.assertFalse(result.cancelled)
        self.assertEqual((result.forward_evaluations, result.backward_evaluations), (65536, 65536))
        self.assertIn(self.key, result.candidates)
        self.assertGreater(len(result.candidates), 1)
        # 同一个 K2 下出现多个 K1，证明表碰撞没有覆盖旧键。
        self.assertGreater(len(result.candidates), len({k2 for _, k2 in result.candidates}))
        plain, cipher = self.pairs[0]
        for k1, k2 in result.candidates:
            self.assertEqual(transform_block(plain, (k1 << 16) | k2, 2), cipher)

    def test_full_three_pairs_and_progress(self):
        progress = []
        result = meet_in_the_middle(self.pairs, lambda *item: progress.append(item))
        self.assertEqual(result.candidates, (self.key,))
        self.assertEqual((result.forward_evaluations, result.backward_evaluations), (65536, 65536))
        self.assertFalse(result.cancelled)
        self.assertEqual(progress[-1][1:], (65536, 65536))

    def test_contradictory_pairs_have_no_key(self):
        plain, cipher = self.pairs[0]
        result = meet_in_the_middle([(plain, cipher), (plain, cipher ^ 1)])
        self.assertFalse(result.cancelled)
        self.assertEqual(result.candidates, ())

    def test_cancel_during_forward_and_backward_then_restart(self):
        for target_stage in ('建立', '反向'):
            cancel = Event()
            def progress(stage, done, total):
                if stage.startswith(target_stage) and done >= 1024:
                    cancel.set()
            result = meet_in_the_middle(self.pairs, progress, cancel)
            self.assertTrue(result.cancelled)
            self.assertLess(result.backward_evaluations, 65536)
        result = meet_in_the_middle(self.pairs)
        self.assertFalse(result.cancelled)
        self.assertIn(self.key, result.candidates)

    def test_empty_invalid_pairs_and_pre_cancel(self):
        for pairs in ([], [(65536, 0)], [(0, -1)]):
            with self.assertRaises(ValueError):
                meet_in_the_middle(pairs)
        cancel = Event()
        cancel.set()
        result = meet_in_the_middle(self.pairs, cancel=cancel)
        self.assertTrue(result.cancelled)
        self.assertEqual((result.forward_evaluations, result.backward_evaluations), (0, 0))


class RecordsAcceptance(unittest.TestCase):
    def test_snapshot_independent_of_changed_input_and_dataclass_bytes(self):
        parameters = {'key': '2D55', 'nested': [1]}
        record = build_record('test', parameters, {'bytes': b'AB', 'trace': trace_block(0, 0)})
        parameters['key'], parameters['nested'][0] = 'FFFF', 2
        self.assertEqual(record['parameters'], {'key': '2D55', 'nested': [1]})
        self.assertEqual(record['result']['bytes'], {'encoding': 'hex', 'data': '4142'})
        self.assertEqual(len(record['result']['trace']), 9)
        with TemporaryDirectory() as folder:
            path = Path(folder) / '记录.json'
            write_record(path, record)
            self.assertEqual(json.loads(path.read_text(encoding='utf-8')), record)
            text = Path(folder) / '记录.txt'
            write_record(text, record)
            self.assertIn('2D55', text.read_text(encoding='utf-8'))
            with self.assertRaises(ValueError):
                write_record(Path(folder) / 'bad.csv', record)


if __name__ == '__main__':
    unittest.main(verbosity=2)
