"""基于 Tkinter/ttk 的 S-AES 教学桌面界面，无第三方依赖。"""

import csv
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Thread
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from .attack import AttackResult, meet_in_the_middle
from .core import expand_key, trace_block
from .encoding import (bytes_to_blocks, encode_ascii, escaped_bytes, pad_bytes,
                       parse_fixed, parse_hex_bytes)
from .modes import (cbc_process, compare_cbc_tampering, generate_iv,
                    split_key, transform_block, transform_bytes)
from .records import build_record, write_record

HEX = "16 位十六进制"
BINARY = "16 位二进制"
ASCII = "ASCII 字符串 / HEX 密文"


def get_text(widget: tk.Text) -> str:
    # 只移除 Tk Text 自带的末尾换行，保留用户输入的空格和换行。
    return widget.get("1.0", "end-1c")


def set_text(widget: tk.Text, value: str, readonly: bool = False) -> None:
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", value)
    if readonly:
        widget.configure(state="disabled")


def text_box(parent: tk.Widget, height: int = 5, readonly: bool = False) -> ScrolledText:
    box = ScrolledText(parent, height=height, wrap="word", font=("Consolas", 10),
                       relief="solid", borderwidth=1, padx=10, pady=8,
                       background="#FFFFFF", foreground="#15243A", undo=not readonly)
    if readonly:
        box.configure(state="disabled")
    return box


def ascii_result(data: bytes) -> str:
    try:
        return "ASCII 明文（标记间为原始文本）：\n--- 开始 ---\n" + data.decode("ascii") + "\n--- 结束 ---"
    except UnicodeDecodeError:
        return "解密结果包含非 ASCII 字节；请核对密钥、IV 或密文。"


def matrix_text(state: int) -> str:
    a, b, c, d = f"{state:04X}"
    return f"[{a} {c}; {b} {d}]"


class RecordPanel(ttk.Frame):
    """各页共享的记录导出；只读取上次操作快照，不读取当前输入框。"""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.last_record: dict | None = None

    def save_record(self) -> None:
        if self.last_record is None:
            self.app.set_status("当前没有操作记录，请先完成一次计算。")
            return
        path = filedialog.asksaveasfilename(
            parent=self, title="保存上次操作记录", defaultextension=".json",
            filetypes=[("JSON 记录", "*.json"), ("文本记录", "*.txt")],
            initialdir=str(Path(__file__).resolve().parent.parent / "reports"),
            initialfile="saes-record.json")
        if not path:
            return
        try:
            write_record(path, self.last_record)
            self.app.set_status("已保存上次计算的参数、结果和轨迹：" + path)
        except (OSError, ValueError) as exc:
            self.app.show_error(f"保存失败：{exc}")


class CryptoPanel(RecordPanel):
    def __init__(self, parent: tk.Widget, app: "SAESApp", multiple: bool = False):
        super().__init__(parent, padding=16)
        self.app = app
        self.multiple = multiple
        self.input_format = tk.StringVar(value=HEX)
        self.key_format = tk.StringVar(value="HEX")
        self.key = tk.StringVar(value="2D551234" if multiple else "2D55")
        self.scheme = tk.StringVar(value="双重加密 · 32 位密钥")
        self.key_hint = tk.StringVar()
        self.last_cipher: tuple[str, str] | None = None
        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=1)
        self.rowconfigure(6, weight=2)

        description = ("双重：E(K2, E(K1, P))    三重：E(K3, E(K2, E(K1, P)))；子密钥从左向右拆分。"
                       if multiple else "16 位分组 · 16 位密钥 · 两轮 S-AES；矩阵按列排列，最后一轮没有列混淆。")
        ttk.Label(self, text=description, style="Hint.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 10))
        form = ttk.Frame(self)
        form.grid(row=1, column=0, sticky="ew")
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text="数据格式").grid(row=0, column=0, sticky="w", padx=(0, 10))
        ttk.Combobox(form, textvariable=self.input_format, values=(HEX, BINARY, ASCII),
                     state="readonly", width=30).grid(row=0, column=1, sticky="w")
        if multiple:
            chooser = ttk.Combobox(form, textvariable=self.scheme,
                                   values=("双重加密 · 32 位密钥", "三重加密 · 48 位密钥"),
                                   state="readonly", width=28)
            chooser.grid(row=0, column=2, padx=(12, 0), sticky="e")
            chooser.bind("<<ComboboxSelected>>", lambda _event: self.update_hint())
        ttk.Label(form, text="密钥").grid(row=1, column=0, sticky="w", pady=8)
        ttk.Entry(form, textvariable=self.key).grid(row=1, column=1, sticky="ew", pady=8)
        ttk.Combobox(form, textvariable=self.key_format, values=("HEX", "BIN"), state="readonly",
                     width=8).grid(row=1, column=2, sticky="e", padx=(12, 0))
        ttk.Label(form, textvariable=self.key_hint, style="Hint.TLabel").grid(row=2, column=1, sticky="w")
        self.update_hint()

        group = ttk.LabelFrame(self, text="输入：加密时填明文；解密时填密文", padding=8)
        group.grid(row=2, column=0, sticky="ew", pady=(12, 8))
        self.input = text_box(group, height=3)
        self.input.pack(fill="both", expand=True)
        set_text(self.input, "A749")
        actions = ttk.Frame(self)
        actions.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(actions, text="加密", style="Accent.TButton", command=lambda: self.run(False)).pack(side="left")
        ttk.Button(actions, text="解密", command=lambda: self.run(True)).pack(side="left", padx=8)
        self.refill_button = ttk.Button(actions, text="回填上次密文", command=self.refill, state="disabled")
        self.refill_button.pack(side="left")
        ttk.Button(actions, text="保存记录", command=self.save_record).pack(side="left", padx=8)
        ttk.Button(actions, text="载入示例", command=self.load_sample).pack(side="right")
        ttk.Button(actions, text="复制结果", command=lambda: app.copy_text(get_text(self.output))).pack(side="right", padx=8)

        output_group = ttk.LabelFrame(self, text="结果与轮密钥", padding=8)
        output_group.grid(row=4, column=0, sticky="nsew")
        self.output = text_box(output_group, height=6, readonly=True)
        self.output.pack(fill="both", expand=True)

        ttk.Label(self, text="分组计算轨迹（字符串模式显示首分组）", style="Hint.TLabel").grid(
            row=5, column=0, sticky="w", pady=(10, 4))
        trace_frame = ttk.Frame(self)
        trace_frame.grid(row=6, column=0, sticky="nsew")
        trace_frame.columnconfigure(0, weight=1)
        trace_frame.rowconfigure(0, weight=1)
        self.trace = ttk.Treeview(trace_frame, columns=("step", "hex", "bin", "matrix"), show="headings", height=6)
        for column, label, width in (("step", "步骤", 290), ("hex", "HEX", 90),
                                     ("bin", "16 位二进制", 185), ("matrix", "状态矩阵", 140)):
            self.trace.heading(column, text=label)
            self.trace.column(column, width=width, minwidth=70, stretch=column == "step")
        scroll = ttk.Scrollbar(trace_frame, orient="vertical", command=self.trace.yview)
        self.trace.configure(yscrollcommand=scroll.set)
        self.trace.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

    def count(self) -> int:
        return (3 if self.scheme.get().startswith("三重") else 2) if self.multiple else 1

    def update_hint(self) -> None:
        count = self.count()
        self.key_hint.set(f"{16 * count} 位密钥：HEX 需要 {4 * count} 个字符；BIN 需要 {16 * count} 个字符。")

    def load_sample(self) -> None:
        self.input_format.set(HEX)
        self.key_format.set("HEX")
        self.key.set({1: "2D55", 2: "2D551234", 3: "2D551234ABCD"}[self.count()])
        set_text(self.input, "A749")
        self.last_cipher = None
        self.refill_button.configure(state="disabled")
        self.app.set_status("已载入示例；点击加密查看结果。")

    def refill(self) -> None:
        if self.last_cipher:
            mode, ciphertext = self.last_cipher
            self.input_format.set(mode)
            set_text(self.input, ciphertext)
            self.app.set_status("已回填上次密文；保持原加密方案和密钥后点击解密。")

    def run(self, decrypt: bool) -> None:
        try:
            count, mode = self.count(), self.input_format.get()
            key = parse_fixed(self.key.get(), 16 * count, self.key_format.get().lower(), "密钥")
            source = get_text(self.input)
            if mode == ASCII:
                data = parse_hex_bytes(source) if decrypt else encode_ascii(source)
                result = transform_bytes(data, key, count, decrypt=decrypt)
                lines = [f"{'解密' if decrypt else '加密'}完成 · ASCII 字符串 · 每分组 2 字节 · PKCS#7 填充",
                         f"结果 HEX：{result.hex(' ').upper()}", f"字节转义：{escaped_bytes(result)}"]
                if decrypt:
                    lines.append(ascii_result(result))
                else:
                    self.last_cipher = (ASCII, result.hex().upper())
                # 加密轨迹输入须使用填充后的首分组（空字符串也有填充分组）。
                trace_data = data if decrypt else pad_bytes(data)
                block = int.from_bytes(trace_data[:2], "big")
            else:
                base = "bin" if mode == BINARY else "hex"
                block = parse_fixed(source, 16, base, "输入分组")
                result_block = transform_block(block, key, count, decrypt=decrypt)
                lines = [f"{'解密' if decrypt else '加密'}完成 · 单个 16 位分组（无填充）",
                         f"结果 HEX：{result_block:04X}", f"结果 BIN：{result_block:016b}"]
                if not decrypt:
                    self.last_cipher = (mode, f"{result_block:016b}" if mode == BINARY else f"{result_block:04X}")
            parts = split_key(key, count)
            for index, part in enumerate(parts, 1):
                rounds = expand_key(part)
                lines.append(f"子密钥 {index} = {part:04X}；轮密钥 K0/K1/K2 = " + " / ".join(f"{k:04X}" for k in rounds))
            set_text(self.output, "\n".join(lines), readonly=True)
            self.trace.delete(*self.trace.get_children())
            ordered = tuple(enumerate(parts, 1))
            record_trace = []
            if decrypt:
                ordered = ordered[::-1]
            for index, part in ordered:
                steps = trace_block(block, part, decrypt=decrypt)
                record_trace.append({"subkey_index": index, "steps": steps})
                for step in steps:
                    self.trace.insert("", "end", values=(f"子密钥{index} · {step.operation}",
                                                          f"{step.state:04X}", f"{step.state:016b}", matrix_text(step.state)))
                block = steps[-1].state
            self.last_record = build_record(
                "多重加密" if self.multiple else "基础加解密",
                {"direction": "decrypt" if decrypt else "encrypt", "input_format": mode,
                 "input": source, "key_hex": f"{key:0{4 * count}X}", "key_count": count,
                 "scheme": "EEE" if count == 3 else "EE" if count == 2 else "S-AES",
                 "padding": "PKCS#7 (2 bytes)" if mode == ASCII else "none", "byte_order": "big"},
                {"output_hex": result.hex().upper() if mode == ASCII else f"{result_block:04X}",
                 "summary": "\n".join(lines), "trace_scope": "first_block" if mode == ASCII else "single_block",
                 "trace": record_trace})
            self.refill_button.configure(state="normal" if self.last_cipher else "disabled")
            self.app.set_status("计算完成；结果可复制，轨迹可滚动查看。")
        except ValueError as exc:
            self.app.show_error(str(exc))


class AttackPanel(RecordPanel):
    def __init__(self, parent: tk.Widget, app: "SAESApp"):
        super().__init__(parent, padding=16)
        self.app = app
        self.messages: Queue = Queue()
        self.cancel_event = Event()
        self.worker: Thread | None = None
        self.result: AttackResult | None = None
        self.columnconfigure(0, weight=1)
        self.rowconfigure(7, weight=1)
        ttk.Label(self, text="针对双重加密 C = E(K2, E(K1, P))；完整搜索 K1、K2 各 65,536 个值。",
                  style="Hint.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(self, text="已知明密文对：每行填写 P C，各为 4 位 HEX；建议至少 3 组不同明文。",
                  style="Hint.TLabel").grid(row=1, column=0, sticky="w", pady=(8, 4))
        self.pairs = text_box(self, height=5)
        self.pairs.grid(row=2, column=0, sticky="ew")
        demo = ttk.Frame(self)
        demo.grid(row=3, column=0, sticky="ew", pady=8)
        self.demo_key = tk.StringVar(value="2D551234")
        ttk.Label(demo, text="演示用组合密钥（8 位 HEX）").pack(side="left")
        ttk.Entry(demo, textvariable=self.demo_key, width=20).pack(side="left", padx=8)
        self.demo_button = ttk.Button(demo, text="生成演示明密文对", command=self.make_demo)
        self.demo_button.pack(side="left")
        controls = ttk.Frame(self)
        controls.grid(row=4, column=0, sticky="ew", pady=(0, 8))
        self.start_button = ttk.Button(controls, text="开始中间相遇搜索", style="Accent.TButton", command=self.start)
        self.start_button.pack(side="left")
        self.cancel_button = ttk.Button(controls, text="取消", command=self.cancel, state="disabled")
        self.cancel_button.pack(side="left", padx=8)
        self.export_button = ttk.Button(controls, text="导出全部候选 CSV", command=self.export, state="disabled")
        self.export_button.pack(side="left")
        self.record_button = ttk.Button(controls, text="保存搜索记录", command=self.save_record)
        self.record_button.pack(side="left", padx=8)
        self.progress = ttk.Progressbar(self, maximum=131072, mode="determinate")
        self.progress.grid(row=5, column=0, sticky="ew")
        self.progress_label = tk.StringVar(value="尚未运行。攻击使用后台线程，运行中可以取消。")
        ttk.Label(self, textvariable=self.progress_label, style="Hint.TLabel").grid(row=6, column=0, sticky="w", pady=8)
        self.output = text_box(self, height=12, readonly=True)
        self.output.grid(row=7, column=0, sticky="nsew")
        ttk.Label(self, text="演示密钥仅用于构造样本；搜索函数只接收明密文对，不读取演示密钥。",
                  style="Hint.TLabel").grid(row=8, column=0, sticky="w", pady=(8, 0))

    def make_demo(self) -> None:
        try:
            key = parse_fixed(self.demo_key.get(), 32, "hex", "演示密钥")
            pairs = [(plain, transform_block(plain, key, 2)) for plain in (0xA749, 0x1234, 0x0000)]
            set_text(self.pairs, "\n".join(f"{p:04X} {c:04X}" for p, c in pairs))
            self.app.set_status("已生成 3 组演示数据；尚未执行搜索。")
        except ValueError as exc:
            self.app.show_error(str(exc))

    def start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        try:
            pairs = []
            for number, line in enumerate(get_text(self.pairs).splitlines(), 1):
                if not line.strip():
                    continue
                fields = line.split()
                if len(fields) != 2:
                    raise ValueError(f"第 {number} 行需要两个值，例如 A749 1234。")
                pairs.append((parse_fixed(fields[0], 16, name=f"第{number}行明文"),
                              parse_fixed(fields[1], 16, name=f"第{number}行密文")))
            if not pairs:
                raise ValueError("请先输入已知明密文对，或生成演示数据。")
        except ValueError as exc:
            self.app.show_error(str(exc))
            return
        self.result = None
        self.last_record = None
        self.search_pairs = tuple(pairs)
        self.cancel_event.clear()
        self.progress["value"] = 0
        self.start_button.configure(state="disabled")
        self.demo_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.export_button.configure(state="disabled")
        self.record_button.configure(state="disabled")
        self.pairs.configure(state="disabled")
        set_text(self.output, "搜索中：先建立 E(K1,P) 正向表，再计算 D(K2,C) 并过滤候选。", readonly=True)

        def progress(stage: str, done: int, total: int) -> None:
            self.messages.put(("progress", stage, done, total))

        def work() -> None:
            try:
                result = meet_in_the_middle(pairs, progress=progress, cancel=self.cancel_event)
                self.messages.put(("result", result))
            except Exception as exc:
                self.messages.put(("error", str(exc)))

        self.worker = Thread(target=work, name="saes-mitm", daemon=True)
        self.worker.start()
        self.app.set_status("中间相遇搜索正在后台运行。")
        self.after(100, self.poll)

    def cancel(self) -> None:
        self.cancel_event.set()
        self.cancel_button.configure(state="disabled")
        self.progress_label.set("正在取消；已找到的候选不代表搜索完整结果。")

    def poll(self) -> None:
        finished = False
        try:
            while True:
                item = self.messages.get_nowait()
                if item[0] == "progress":
                    _, stage, done, total = item
                    self.progress["value"] = done + (65536 if stage.startswith("反向") else 0)
                    self.progress_label.set(f"{stage}：{done:,} / {total:,}")
                elif item[0] == "result":
                    self.result = item[1]
                    self.show_result(item[1])
                    finished = True
                elif item[0] == "error":
                    set_text(self.output, "搜索失败：" + item[1], readonly=True)
                    self.app.show_error(item[1])
                    finished = True
        except Empty:
            pass
        if finished:
            self.start_button.configure(state="normal")
            self.demo_button.configure(state="normal")
            self.cancel_button.configure(state="disabled")
            self.pairs.configure(state="normal")
            self.record_button.configure(state="normal")
            if self.result and self.result.candidates:
                self.export_button.configure(state="normal")
        else:
            self.after(100, self.poll)

    def show_result(self, result: AttackResult) -> None:
        status = "已取消（搜索不完整）" if result.cancelled else "完整搜索已结束"
        lines = [status, f"已知明密文对：{result.pair_count} 组",
                 f"主搜索正向计算：{result.forward_evaluations:,}；反向计算：{result.backward_evaluations:,}",
                 f"耗时：{result.elapsed_seconds:.3f} 秒；候选数量：{len(result.candidates):,}",
                 "计数不含额外明密文对的候选过滤计算。"]
        if result.cancelled:
            lines.append("取消前的候选仅为部分结果，不能据此判断唯一性或没有解。")
        elif not result.candidates:
            lines.append("未找到匹配密钥，请核对明密文对和双重加密顺序。")
        elif len(result.candidates) == 1:
            lines.append("当前已知明密文对下仅有一个候选；这不构成所有输入上的密钥唯一性证明。")
        else:
            lines.append("存在多个匹配候选，请补充其他明文对应的密文后重新搜索。")
        lines.append("\nK1    K2    组合密钥（HEX）")
        for k1, k2 in result.candidates[:200]:
            lines.append(f"{k1:04X}  {k2:04X}  {k1:04X}{k2:04X}")
        if len(result.candidates) > 200:
            lines.append("界面仅展示前 200 个候选；CSV 导出包含全部候选。")
        set_text(self.output, "\n".join(lines), readonly=True)
        self.last_record = build_record(
            "双重 S-AES 中间相遇搜索",
            {"scheme": "EE", "known_pairs": [{"plaintext_hex": f"{p:04X}", "ciphertext_hex": f"{c:04X}"}
                                               for p, c in self.search_pairs]},
            {"search_complete": not result.cancelled, "elapsed_seconds": result.elapsed_seconds,
             "forward_evaluations": result.forward_evaluations,
             "backward_evaluations": result.backward_evaluations,
             "candidate_count": len(result.candidates),
             "candidates": [{"k1_hex": f"{k1:04X}", "k2_hex": f"{k2:04X}"} for k1, k2 in result.candidates],
             "summary": "\n".join(lines)})
        self.progress_label.set(status)
        self.app.set_status(status)

    def export(self) -> None:
        if not self.result:
            return
        path = filedialog.asksaveasfilename(parent=self, title="保存候选密钥",
                                            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                            initialfile="mitm-candidates.csv")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as stream:
                writer = csv.writer(stream)
                writer.writerow(("k1_hex", "k2_hex", "combined_key_hex", "search_complete"))
                for k1, k2 in self.result.candidates:
                    writer.writerow((f"{k1:04X}", f"{k2:04X}", f"{k1:04X}{k2:04X}", not self.result.cancelled))
            self.app.set_status("候选密钥已导出：" + path)
        except OSError as exc:
            self.app.show_error(f"保存失败：{exc}")


class CBCPanel(RecordPanel):
    def __init__(self, parent: tk.Widget, app: "SAESApp"):
        super().__init__(parent, padding=16)
        self.app = app
        self.key = tk.StringVar(value="2D55")
        self.iv = tk.StringVar(value=f"{generate_iv():04X}")
        self.index = tk.StringVar(value="0")
        self.tamper_mode = tk.StringVar(value="异或掩码")
        self.tamper_value = tk.StringVar(value="0001")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)
        ttk.Label(self, text="CBC 使用单个 16 位 S-AES 密钥；文本按 ASCII 编码、PKCS#7 填充，IV 独立保存并共享。",
                  style="Hint.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 10))
        form = ttk.Frame(self)
        form.grid(row=1, column=0, sticky="ew")
        ttk.Label(form, text="密钥 HEX").pack(side="left")
        ttk.Entry(form, textvariable=self.key, width=12).pack(side="left", padx=8)
        ttk.Label(form, text="IV HEX").pack(side="left", padx=(12, 0))
        ttk.Entry(form, textvariable=self.iv, width=12).pack(side="left", padx=8)
        ttk.Button(form, text="生成随机 IV", command=self.new_iv).pack(side="left")
        ttk.Button(form, text="载入示例", command=self.load_sample).pack(side="right")

        inputs = ttk.Frame(self)
        inputs.grid(row=2, column=0, sticky="ew", pady=12)
        inputs.columnconfigure(0, weight=1)
        inputs.columnconfigure(1, weight=1)
        plain_group = ttk.LabelFrame(inputs, text="ASCII 明文（空格和换行均保留）", padding=8)
        plain_group.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        cipher_group = ttk.LabelFrame(inputs, text="HEX 密文（不含 IV，可粘贴外部密文）", padding=8)
        cipher_group.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        self.plain = text_box(plain_group, height=5)
        self.plain.pack(fill="both", expand=True)
        self.cipher = text_box(cipher_group, height=5)
        self.cipher.pack(fill="both", expand=True)
        set_text(self.plain, "Hello S-AES CBC!")

        actions = ttk.Frame(self)
        actions.grid(row=3, column=0, sticky="ew", pady=(0, 10))
        ttk.Button(actions, text="加密明文 → 密文", style="Accent.TButton", command=self.encrypt).pack(side="left")
        ttk.Button(actions, text="解密密文 → 明文", command=self.decrypt).pack(side="left", padx=8)
        ttk.Button(actions, text="复制密文", command=lambda: app.copy_text(get_text(self.cipher))).pack(side="right")
        ttk.Button(actions, text="保存记录", command=self.save_record).pack(side="right", padx=8)

        tamper = ttk.LabelFrame(self, text="篡改实验：保留原密文，对副本进行修改并对比", padding=10)
        tamper.grid(row=4, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(tamper, text="分组序号（从 0 开始）").pack(side="left")
        ttk.Entry(tamper, textvariable=self.index, width=6).pack(side="left", padx=8)
        ttk.Combobox(tamper, textvariable=self.tamper_mode, values=("异或掩码", "整组替换"),
                     state="readonly", width=12).pack(side="left", padx=(6, 0))
        ttk.Entry(tamper, textvariable=self.tamper_value, width=9).pack(side="left", padx=8)
        ttk.Label(tamper, text="4 位 HEX").pack(side="left")
        ttk.Button(tamper, text="篡改并比较", command=self.compare).pack(side="right")
        self.output = text_box(self, height=13, readonly=True)
        self.output.grid(row=5, column=0, sticky="nsew")

    def parameters(self) -> tuple[int, int]:
        return (parse_fixed(self.key.get(), 16, name="密钥"),
                parse_fixed(self.iv.get(), 16, name="IV"))

    def new_iv(self) -> None:
        self.iv.set(f"{generate_iv():04X}")
        self.app.set_status("已更新 IV。解密现有密文前，请恢复加密时使用的 IV。")

    def load_sample(self) -> None:
        self.key.set("2D55")
        self.iv.set("1234")
        set_text(self.plain, "Hello S-AES CBC!")
        set_text(self.cipher, "")
        self.index.set("0")
        self.tamper_value.set("0001")
        self.app.set_status("已载入 CBC 示例；示例 IV 固定为 1234，便于复现。")

    def show_trace(self, result: bytes, trace: tuple, decrypt: bool) -> None:
        lines = [f"CBC {'解密' if decrypt else '加密'}完成 · IV = {self.iv.get().strip().upper()}",
                 f"结果 HEX：{result.hex(' ').upper()}", f"字节转义：{escaped_bytes(result)}"]
        if decrypt:
            lines.append(ascii_result(result))
        lines.extend(("", "序号  输入  链值  中间值  输出", "解密中间值为 D(Ci)；加密中间值为 Pi XOR 链值。"))
        for step in trace[:500]:
            lines.append(f"{step.index:04d}  {step.input_block:04X}  {step.chain:04X}  {step.intermediate:04X}  {step.output_block:04X}")
        if len(trace) > 500:
            lines.append(f"共有 {len(trace)} 组，界面仅显示前 500 组轨迹。全部密文／结果见上方。")
        set_text(self.output, "\n".join(lines), readonly=True)

    def encrypt(self) -> None:
        try:
            key, iv = self.parameters()
            source = get_text(self.plain)
            result, trace = cbc_process(encode_ascii(source), key, iv)
            set_text(self.cipher, result.hex(' ').upper())
            self.show_trace(result, trace, False)
            self.capture_cbc("encrypt", source, key, iv, result, trace)
            self.app.set_status("CBC 加密完成；请将当前 IV 与密文一并记录。")
        except ValueError as exc:
            self.app.show_error(str(exc))

    def decrypt(self) -> None:
        try:
            key, iv = self.parameters()
            source = get_text(self.cipher)
            result, trace = cbc_process(parse_hex_bytes(source), key, iv, decrypt=True)
            try:
                decoded = result.decode("ascii")
            except UnicodeDecodeError:
                decoded = None
            if decoded is not None:
                set_text(self.plain, decoded)
            self.show_trace(result, trace, True)
            self.capture_cbc("decrypt", source, key, iv, result, trace)
            self.app.set_status("CBC 解密完成。" if decoded is not None else "已解密，但结果包含非 ASCII 字节，请检查参数。")
        except ValueError as exc:
            self.app.show_error(str(exc))

    def capture_cbc(self, direction, source, key, iv, result, trace) -> None:
        self.last_record = build_record(
            "CBC 加解密", {"direction": direction, "input": source, "key_hex": f"{key:04X}",
                            "iv_hex": f"{iv:04X}", "padding": "PKCS#7 (2 bytes)", "byte_order": "big"},
            {"output_hex": result.hex().upper(), "trace": trace, "summary": get_text(self.output)})

    def compare(self) -> None:
        try:
            key, iv = self.parameters()
            try:
                index = int(self.index.get())
            except ValueError as exc:
                raise ValueError("分组序号必须是从 0 开始的整数。") from exc
            value = parse_fixed(self.tamper_value.get(), 16, name="篡改值")
            cipher = parse_hex_bytes(get_text(self.cipher))
            comparison = compare_cbc_tampering(cipher, key, iv, index, value,
                                               replace=self.tamper_mode.get() == "整组替换")
            original = bytes_to_blocks(comparison.original_raw)
            modified = bytes_to_blocks(comparison.modified_raw)
            lines = [f"篡改密文分组 C[{index}]；模式：{self.tamper_mode.get()}；值：{value:04X}",
                     f"修改后的密文 HEX：{comparison.modified_ciphertext.hex(' ').upper()}",
                     "\n分组  原始解密  篡改后解密  XOR差值  是否变化（均含原始填充字节）"]
            for number, (before, after) in enumerate(zip(original, modified)):
                lines.append(f"{number:04d}  {before:04X}      {after:04X}        {before ^ after:04X}    {'是' if before != after else '否'}")
            lines.extend((f"\n变化的明文分组：{comparison.changed_blocks}",
                          "原始解密字节：" + escaped_bytes(comparison.original_raw),
                          "篡改后解密字节：" + escaped_bytes(comparison.modified_raw),
                          "原始填充：" + (comparison.original_padding_error or "有效"),
                          "篡改后填充：" + (comparison.modified_padding_error or "有效"),
                          "\n原理：修改 Ci 会改变 Pi；若存在 Pi+1，则其 XOR 差值等于 Ci 的改变量。后续其他分组保持不变。",
                          "比较使用未移除填充的原始解密字节，因此末分组填充损坏时也能显示实验结果。"))
            set_text(self.output, "\n".join(lines), readonly=True)
            self.last_record = build_record(
                "CBC 密文篡改比较", {"key_hex": f"{key:04X}", "iv_hex": f"{iv:04X}",
                                    "ciphertext_hex": cipher.hex().upper(), "block_index": index,
                                    "tamper_mode": self.tamper_mode.get(), "value_hex": f"{value:04X}"},
                {"comparison": comparison, "summary": "\n".join(lines)})
            self.app.set_status("CBC 篡改对比完成，原密文输入保持不变。")
        except ValueError as exc:
            self.app.show_error(str(exc))


class SAESApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("S-AES 实验工作台")
        self.geometry("1120x880")
        self.minsize(1000, 780)
        self.configure(background="#F1F5F9")
        self.option_add("*Font", ("Microsoft YaHei UI", 10))
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", font=("Microsoft YaHei UI", 10), background="#F1F5F9", foreground="#15243A")
        style.configure("TButton", padding=(12, 7))
        style.configure("Accent.TButton", background="#2457C5", foreground="white")
        style.map("Accent.TButton", background=[("active", "#1D469F"), ("disabled", "#AAB6CA")])
        style.configure("TNotebook.Tab", padding=(18, 9))
        style.configure("Hint.TLabel", foreground="#526176", font=("Microsoft YaHei UI", 9))
        style.configure("Treeview", rowheight=27, fieldbackground="#FFFFFF", background="#FFFFFF")
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold"))
        header = tk.Frame(self, background="#142A49", padx=24, pady=14)
        header.pack(fill="x")
        tk.Label(header, text="S-AES 实验工作台", foreground="white", background="#142A49",
                 font=("Microsoft YaHei UI", 19, "bold")).pack(anchor="w")
        tk.Label(header, text="信息安全导论 · 课外作业 2 · 简化 AES",
                 foreground="#B9CCE8", background="#142A49", font=("Microsoft YaHei UI", 10)).pack(anchor="w", pady=(4, 0))
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=14, pady=(12, 6))
        self.basic_panel = CryptoPanel(self.notebook, self)
        self.multi_panel = CryptoPanel(self.notebook, self, multiple=True)
        self.attack_panel = AttackPanel(self.notebook, self)
        self.cbc_panel = CBCPanel(self.notebook, self)
        for page, title in ((self.basic_panel, "基础加解密 / 字符串"), (self.multi_panel, "双重 / 三重加密"),
                            (self.attack_panel, "中间相遇攻击"), (self.cbc_panel, "CBC / 篡改实验")):
            self.notebook.add(page, text=title)
        self.status = tk.StringVar(value="就绪。最终验收与组间互测尚未进行。")
        footer = ttk.Frame(self, padding=(18, 5, 18, 10))
        footer.pack(fill="x")
        ttk.Label(footer, textvariable=self.status, style="Hint.TLabel", wraplength=1000).pack(anchor="w")
        ttk.Label(footer, text="教学算法：16 位密钥空间较小，仅用于本课程实验。", style="Hint.TLabel").pack(anchor="w", pady=(3, 0))
        self.protocol("WM_DELETE_WINDOW", self.close)

    def set_status(self, text: str) -> None:
        self.status.set(text)

    def show_error(self, text: str) -> None:
        self.set_status("输入或操作有误：" + text)
        messagebox.showerror("请检查输入", text, parent=self)

    def copy_text(self, text: str) -> None:
        if not text:
            self.set_status("当前没有可复制的内容。")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.set_status("已复制到剪贴板。")

    def close(self) -> None:
        self.attack_panel.cancel_event.set()
        self.destroy()


def main() -> None:
    SAESApp().mainloop()
