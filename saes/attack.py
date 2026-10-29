"""针对双重 S-AES 的教学用中间相遇攻击，搜索完整的两个 16 位子密钥空间。"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from threading import Event
from time import perf_counter

from .core import (encrypt_block, decrypt_block, expand_key, require_uint,
                   _encrypt_with_keys, _decrypt_with_keys)


@dataclass(frozen=True)
class AttackResult:
    candidates: tuple[tuple[int, int], ...]
    elapsed_seconds: float
    forward_evaluations: int
    backward_evaluations: int
    pair_count: int
    cancelled: bool


def meet_in_the_middle(pairs: Sequence[tuple[int, int]],
                       progress: Callable[[str, int, int], None] | None = None,
                       cancel: Event | None = None) -> AttackResult:
    """寻找所有符合已知明密文对的 (K1,K2)，不将单对的候选误报为唯一密钥。

    正向表为 E_K1(P)，反向计算 D_K2(C)，使用额外明密文对过滤。
    保留每个中间值下的全部 K1，防止碰撞导致正确候选被覆盖。
    """
    pairs = tuple(pairs)
    if not pairs:
        raise ValueError("至少需要一组已知明文和密文。建议使用 3 组不同明文的数据。")
    for plain, cipher in pairs:
        require_uint(plain, 16, "已知明文")
        require_uint(cipher, 16, "已知密文")
    started, forward, backward = perf_counter(), 0, 0
    matches: list[tuple[int, int]] = []
    table: dict[int, list[int]] = {}
    plaintext, ciphertext = pairs[0]

    def result(cancelled: bool) -> AttackResult:
        return AttackResult(tuple(matches), perf_counter() - started,
                            forward, backward, len(pairs), cancelled)

    def notify(stage: str, done: int) -> None:
        if progress:
            progress(stage, done, 65536)

    notify("建立正向表", 0)
    for k1 in range(65536):
        if cancel and cancel.is_set():
            return result(True)
        middle = _encrypt_with_keys(plaintext, expand_key(k1))
        table.setdefault(middle, []).append(k1)
        forward += 1
        if forward % 1024 == 0:
            notify("建立正向表", forward)

    notify("反向搜索及过滤", 0)
    for k2 in range(65536):
        if cancel and cancel.is_set():
            return result(True)
        middle = _decrypt_with_keys(ciphertext, expand_key(k2))
        backward += 1
        for k1 in table.get(middle, ()):
            if cancel and cancel.is_set():
                return result(True)
            if all(encrypt_block(plain, k1) == decrypt_block(cipher, k2)
                   for plain, cipher in pairs[1:]):
                matches.append((k1, k2))
        if backward % 1024 == 0:
            notify("反向搜索及过滤", backward)
    return result(False)
