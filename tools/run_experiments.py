"""复现实验并保存原始证据：python tools/run_experiments.py。

默认完整运行 unittest 和 1/2/3 对明密文的攻击实验，非性能基准测试。
"""

import csv
from dataclasses import asdict
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path
import platform
import subprocess
import sys
import tkinter
import unittest
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))

from saes.core import encrypt_block, decrypt_block, expand_key, trace_block
from saes.encoding import bytes_to_blocks, pad_bytes, escaped_bytes
from saes.modes import (transform_block, transform_bytes, cbc_process,
                        compare_cbc_tampering, generate_iv)
from saes.attack import meet_in_the_middle
import reference_saes as reference

OUTPUT = ROOT / 'reports' / 'results'


def write_json(name, content):
    (OUTPUT / name).write_text(json.dumps(content, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def write_csv(name, header, rows):
    with (OUTPUT / name).open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(header)
        writer.writerows(rows)


def timestamp():
    try:
        return datetime.now(ZoneInfo('America/New_York')).isoformat(timespec='seconds')
    except ZoneInfoNotFoundError:
        # Windows 未安装 IANA 时区数据时，调用系统 zoneinfo 数据不可用；
        # 证据时间使用 UTC 并显式带偏移，不猜测宿主本地时区。
        from datetime import timezone
        return datetime.now(timezone.utc).isoformat(timespec='seconds')


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
    log = io.StringIO()
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    (OUTPUT / 'unittest.txt').write_text(log.getvalue(), encoding='utf-8')
    summary = {'executed_at': timestamp(), 'python': sys.version, 'os': platform.platform(),
               'tk': tkinter.TkVersion, 'tests_run': result.testsRun,
               'failures': len(result.failures), 'errors': len(result.errors),
               'skipped': len(result.skipped), 'success': result.wasSuccessful(),
               'real_group_cross_test': 'pending', 'members': [{'name': '季冬阳', 'student_id': '2024501'},
                                                           {'name': '待定'}, {'name': '待定'}]}
    if not result.wasSuccessful():
        write_json('summary.json', summary)
        print(log.getvalue())
        return 1

    key, plain = 0x2D55, 0xA749
    write_json('basic.json', {'plaintext_hex': f'{plain:04X}', 'plaintext_bin': f'{plain:016b}',
                            'key_hex': f'{key:04X}', 'key_bin': f'{key:016b}',
                            'round_keys_hex': [f'{k:04X}' for k in expand_key(key)],
                            'ciphertext_hex': f'{encrypt_block(plain, key):04X}',
                            'recovered_hex': f'{decrypt_block(0xC349, key):04X}',
                            'trace': [{'operation': s.operation, 'state_hex': f'{s.state:04X}'}
                                      for s in trace_block(plain, key)]})

    cross_vectors = []
    for test_key in (0, 0x2D55, 0x4AF5, 0xFFFF):
        for test_plain in (0, 1, 0x1234, 0xA749, 0xD728, 0xFFFF):
            expected = reference.encrypt(test_plain, test_key)
            actual = encrypt_block(test_plain, test_key)
            assert actual == expected
            cross_vectors.append((f'{test_plain:04X}', f'{test_key:04X}', f'{actual:04X}',
                                  f'{reference.decrypt(actual, test_key):04X}', 'local_reference_only'))
    write_csv('cross-test-vectors.csv', ('plaintext_hex', 'key_hex', 'ciphertext_hex',
                                       'reference_decrypted_hex', 'evidence_type'), cross_vectors)

    ascii_cases = []
    for text in ('', 'A', 'AB', 'ABC', 'Hello S-AES!', ' A\n\t\0 '):
        data = text.encode('ascii')
        cipher = transform_bytes(data, key)
        recovered = transform_bytes(cipher, key, decrypt=True)
        assert recovered == data
        ascii_cases.append({'plaintext': text, 'plaintext_bytes': len(data),
                            'padded_hex': pad_bytes(data).hex().upper(),
                            'ciphertext_hex': cipher.hex().upper(),
                            'ciphertext_escaped': escaped_bytes(cipher), 'recovered': recovered.decode('ascii')})
    write_json('ascii.json', ascii_cases)

    multi = []
    for count, compound_key in ((2, 0x2D551234), (3, 0x2D551234ABCD)):
        cipher = transform_block(plain, compound_key, count)
        recovered = transform_block(cipher, compound_key, count, True)
        assert recovered == plain
        multi.append({'scheme': 'EE' if count == 2 else 'EEE', 'plaintext_hex': 'A749',
                      'key_hex': f'{compound_key:0{4 * count}X}', 'ciphertext_hex': f'{cipher:04X}',
                      'recovered_hex': f'{recovered:04X}'})
    write_json('multiple.json', multi)

    pairs = [(p, reference.encrypt(reference.encrypt(p, 0x2D55), 0x1234)) for p in (0xA749, 0x1234, 0)]
    attacks = []
    for count in (1, 2, 3):
        attack = meet_in_the_middle(pairs[:count])
        assert not attack.cancelled and (0x2D55, 0x1234) in attack.candidates
        attacks.append({'known_pairs': [{'plaintext_hex': f'{p:04X}', 'ciphertext_hex': f'{c:04X}'}
                                        for p, c in pairs[:count]],
                        'pair_count': count, 'elapsed_seconds': attack.elapsed_seconds,
                        'forward_evaluations': attack.forward_evaluations,
                        'backward_evaluations': attack.backward_evaluations,
                        'candidate_count': len(attack.candidates), 'search_complete': not attack.cancelled,
                        'actual_key_retained': True, 'candidates_csv': f'mitm-{count}-pairs.csv'})
        write_csv(f'mitm-{count}-pairs.csv', ('k1_hex', 'k2_hex', 'combined_key_hex'),
                  ((f'{a:04X}', f'{b:04X}', f'{a:04X}{b:04X}') for a, b in attack.candidates))
    write_json('attacks.json', attacks)

    text, iv = b'Hello S-AES CBC!', 0x1234
    cipher, trace = cbc_process(text, key, iv)
    restored, inverse_trace = cbc_process(cipher, key, iv, True)
    assert restored == text
    write_json('cbc.json', {'plaintext': text.decode('ascii'), 'key_hex': '2D55', 'iv_hex': '1234',
                          'padded_hex': pad_bytes(text).hex().upper(), 'ciphertext_hex': cipher.hex().upper(),
                          'recovered': restored.decode('ascii'), 'encrypt_trace': [asdict(s) for s in trace],
                          'decrypt_trace': [asdict(s) for s in inverse_trace]})
    rows, tampering = [], []
    cipher_blocks = bytes_to_blocks(cipher)
    for index in (0, 3, len(cipher_blocks) - 1):
        for replace in (False, True):
            value = cipher_blocks[index] ^ 1 if replace else 1
            comparison = compare_cbc_tampering(cipher, key, iv, index, value, replace)
            record = {'cipher_block_index': index, 'mode': 'replace' if replace else 'xor',
                      'value_hex': f'{value:04X}', 'changed_plaintext_blocks': list(comparison.changed_blocks),
                      'original_raw_hex': comparison.original_raw.hex().upper(),
                      'modified_ciphertext_hex': comparison.modified_ciphertext.hex().upper(),
                      'modified_raw_hex': comparison.modified_raw.hex().upper(),
                      'original_padding_error': comparison.original_padding_error,
                      'modified_padding_error': comparison.modified_padding_error}
            tampering.append(record)
            for block_index, (a, b) in enumerate(zip(bytes_to_blocks(comparison.original_raw),
                                                    bytes_to_blocks(comparison.modified_raw))):
                rows.append((index, record['mode'], f'{value:04X}', block_index, f'{a:04X}', f'{b:04X}',
                             f'{a ^ b:04X}', a != b))
    write_json('cbc-tampering.json', tampering)
    write_csv('cbc-tampering.csv', ('modified_cipher_index', 'mode', 'value_hex', 'plaintext_index',
                                    'original_hex', 'modified_hex', 'xor_difference_hex', 'changed'), rows)
    iv_examples = []
    for _ in range(3):
        random_iv = generate_iv()
        output, _ = cbc_process(text, key, random_iv)
        iv_examples.append({'iv_hex': f'{random_iv:04X}', 'ciphertext_hex': output.hex().upper()})
    write_json('random-iv.json', iv_examples)

    summary['attack_summary'] = [{'pair_count': a['pair_count'], 'candidate_count': a['candidate_count'],
                                 'elapsed_seconds': a['elapsed_seconds']} for a in attacks]
    summary['source_commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    write_json('summary.json', summary)
    checksums = []
    for path in sorted(OUTPUT.iterdir()):
        if path.is_file() and path.name != 'checksums.json':
            checksums.append({'file': path.name, 'bytes': path.stat().st_size,
                              'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    write_json('checksums.json', checksums)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
