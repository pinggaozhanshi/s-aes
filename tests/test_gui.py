"""真实 Tk 小部件与回调的集成测试；窗口隐藏避免干扰桌面。"""

import csv
import gc
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
import unittest
from unittest.mock import patch

from saes.gui import SAESApp, ASCII, BINARY, get_text, set_text


class GUIAcceptance(unittest.TestCase):
    def setUp(self):
        self.app = SAESApp()
        self.app.withdraw()
        self.errors = []
        # 只替换阻塞模态错误提示，仍走真实输入验证和计算路径。
        self.app.show_error = self.errors.append

    def tearDown(self):
        self.app.close()
        self.app = None
        # 在主线程回收已销毁的 Tk 图，避免下一次后台搜索触发其析构。
        gc.collect()

    def test_basic_hex_binary_decrypt_and_snapshot(self):
        panel = self.app.basic_panel
        panel.run(False)
        self.assertEqual(panel.last_record['result']['output_hex'], 'C349')
        panel.key.set('FFFF')
        self.assertEqual(panel.last_record['parameters']['key_hex'], '2D55')
        panel.key.set('2D55')
        panel.refill()
        panel.run(True)
        self.assertEqual(panel.last_record['result']['output_hex'], 'A749')
        panel.input_format.set(BINARY)
        set_text(panel.input, '1010011101001001')
        panel.run(False)
        self.assertIn('1100001101001001', get_text(panel.output))
        self.assertEqual(len(panel.trace.get_children()), 9)
        self.assertFalse(self.errors)

    def test_ascii_whitespace_empty_and_record_save(self):
        panel = self.app.basic_panel
        panel.input_format.set(ASCII)
        for plain in ('', ' A\n\t\0 '):
            set_text(panel.input, plain)
            panel.run(False)
            panel.refill()
            panel.run(True)
            result = bytes.fromhex(panel.last_record['result']['output_hex'])
            self.assertEqual(result.decode('ascii'), plain)
        with TemporaryDirectory() as folder:
            path = Path(folder) / '操作记录.json'
            with patch('saes.gui.filedialog.asksaveasfilename', return_value=str(path)):
                panel.save_record()
            self.assertEqual(json.loads(path.read_text(encoding='utf-8')), panel.last_record)
        self.assertFalse(self.errors)

    def test_multi_eee_trace_and_decrypt(self):
        panel = self.app.multi_panel
        panel.scheme.set('三重加密 · 48 位密钥')
        panel.key.set('2D551234ABCD')
        panel.run(False)
        self.assertEqual(len(panel.trace.get_children()), 27)
        self.assertEqual(panel.last_record['parameters']['scheme'], 'EEE')
        panel.refill()
        panel.run(True)
        self.assertEqual(panel.last_record['result']['output_hex'], 'A749')
        self.assertFalse(self.errors)

    def test_cbc_roundtrip_tamper_and_original_cipher_preserved(self):
        panel = self.app.cbc_panel
        panel.load_sample()
        panel.encrypt()
        cipher = get_text(panel.cipher)
        panel.decrypt()
        self.assertEqual(get_text(panel.plain), 'Hello S-AES CBC!')
        panel.index.set('3')
        panel.compare()
        self.assertEqual(get_text(panel.cipher), cipher)
        self.assertEqual(panel.last_record['result']['comparison']['changed_blocks'], [3, 4])
        self.assertFalse(self.errors)

    def test_invalid_input_does_not_replace_successful_record(self):
        panel = self.app.basic_panel
        panel.run(False)
        snapshot = panel.last_record
        set_text(panel.input, 'XYZ')
        panel.run(False)
        self.assertIs(panel.last_record, snapshot)
        self.assertEqual(len(self.errors), 1)

    def test_attack_thread_result_and_export(self):
        panel = self.app.attack_panel
        panel.make_demo()
        panel.start()
        self.assertEqual(str(panel.start_button['state']), 'disabled')
        deadline = monotonic() + 15
        def await_result():
            if str(panel.start_button['state']) != 'disabled' or monotonic() >= deadline:
                self.app.quit()
            else:
                self.app.after(10, await_result)
        self.app.after(10, await_result)
        self.app.mainloop()
        self.assertIsNotNone(panel.result)
        self.assertFalse(panel.result.cancelled)
        self.assertEqual(panel.result.candidates, ((0x2D55, 0x1234),))
        with TemporaryDirectory() as folder:
            path = Path(folder) / 'keys.csv'
            with patch('saes.gui.filedialog.asksaveasfilename', return_value=str(path)):
                panel.export()
            with path.open(encoding='utf-8-sig', newline='') as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(rows[0]['combined_key_hex'], '2D551234')
            self.assertEqual(rows[0]['search_complete'], 'True')
        self.assertEqual(panel.last_record['result']['candidate_count'], 1)
        self.assertFalse(self.errors)


if __name__ == '__main__':
    unittest.main(verbosity=2)
