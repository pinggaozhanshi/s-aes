"""教材附录 D 的 S-AES。状态半字节按列排列为 [[n0, n2], [n1, n3]]。"""

from dataclasses import dataclass

S_BOX = (0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5,
         0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7)
INVERSE_S_BOX = (0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF,
                 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE)
MODULUS = 0b10011  # x^4 + x + 1


def require_uint(value: int, bits: int, name: str = "数值") -> int:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ValueError(f"{name}必须是 {bits} 位无符号整数（0 至 {(1 << bits) - 1}）。")
    return value


def gf_multiply(left: int, right: int) -> int:
    """GF(2^4) 乘法；加法为异或，乘法按 MODULUS 约减。"""
    require_uint(left, 4, "左操作数")
    require_uint(right, 4, "右操作数")
    result = 0
    while right:
        if right & 1:
            result ^= left
        right >>= 1
        left <<= 1
        if left & 0x10:
            left ^= MODULUS
    return result


_MULTIPLY_2 = tuple(gf_multiply(2, n) for n in range(16))
_MULTIPLY_4 = tuple(gf_multiply(4, n) for n in range(16))
_MULTIPLY_9 = tuple(gf_multiply(9, n) for n in range(16))


def _substitute(state: int, box: tuple[int, ...]) -> int:
    return (box[state >> 12] << 12 | box[(state >> 8) & 15] << 8
            | box[(state >> 4) & 15] << 4 | box[state & 15])


def substitute_nibbles(state: int, inverse: bool = False) -> int:
    require_uint(state, 16, "状态")
    return _substitute(state, INVERSE_S_BOX if inverse else S_BOX)


def _shift_rows(state: int) -> int:
    # 保留 n0、n2，交换第二行的 n1、n3；此变换自身可逆。
    return (state & 0xF0F0) | ((state & 0x0F00) >> 8) | ((state & 15) << 8)


def shift_rows(state: int) -> int:
    require_uint(state, 16, "状态")
    return _shift_rows(state)


def _mix_columns(state: int, inverse: bool = False) -> int:
    a, b, c, d = state >> 12, (state >> 8) & 15, (state >> 4) & 15, state & 15
    if inverse:
        a, b, c, d = (_MULTIPLY_9[a] ^ _MULTIPLY_2[b],
                      _MULTIPLY_2[a] ^ _MULTIPLY_9[b],
                      _MULTIPLY_9[c] ^ _MULTIPLY_2[d],
                      _MULTIPLY_2[c] ^ _MULTIPLY_9[d])
    else:
        a, b, c, d = (a ^ _MULTIPLY_4[b], _MULTIPLY_4[a] ^ b,
                      c ^ _MULTIPLY_4[d], _MULTIPLY_4[c] ^ d)
    return a << 12 | b << 8 | c << 4 | d


def mix_columns(state: int, inverse: bool = False) -> int:
    require_uint(state, 16, "状态")
    return _mix_columns(state, inverse)


def expand_key(key: int) -> tuple[int, int, int]:
    """返回 K0、K1、K2；轮常数分别为 0x80 和 0x30。"""
    require_uint(key, 16, "密钥")
    w0, w1 = key >> 8, key & 255

    def g(word: int, constant: int) -> int:
        return (S_BOX[word & 15] << 4 | S_BOX[word >> 4]) ^ constant

    w2 = w0 ^ g(w1, 0x80)
    w3 = w2 ^ w1
    w4 = w2 ^ g(w3, 0x30)
    w5 = w4 ^ w3
    return key, w2 << 8 | w3, w4 << 8 | w5


def _encrypt_with_keys(block: int, keys: tuple[int, int, int]) -> int:
    state = block ^ keys[0]
    state = _mix_columns(_shift_rows(_substitute(state, S_BOX))) ^ keys[1]
    return _shift_rows(_substitute(state, S_BOX)) ^ keys[2]


def _decrypt_with_keys(block: int, keys: tuple[int, int, int]) -> int:
    state = _substitute(_shift_rows(block ^ keys[2]), INVERSE_S_BOX)
    state = _mix_columns(state ^ keys[1], inverse=True)
    return _substitute(_shift_rows(state), INVERSE_S_BOX) ^ keys[0]


def encrypt_block(block: int, key: int) -> int:
    require_uint(block, 16, "明文分组")
    return _encrypt_with_keys(block, expand_key(key))


def decrypt_block(block: int, key: int) -> int:
    require_uint(block, 16, "密文分组")
    return _decrypt_with_keys(block, expand_key(key))


@dataclass(frozen=True)
class TraceStep:
    operation: str
    state: int


def trace_block(block: int, key: int, decrypt: bool = False) -> tuple[TraceStep, ...]:
    """逐步状态用于教学展示；顺序与真实加解密一致。"""
    require_uint(block, 16, "输入分组")
    k0, k1, k2 = expand_key(key)
    state = block
    steps = [TraceStep("输入密文" if decrypt else "输入明文", state)]
    if decrypt:
        operations = (
            ("轮密钥加 K2", lambda s: s ^ k2),
            ("逆行移位", _shift_rows),
            ("逆半字节替换", lambda s: _substitute(s, INVERSE_S_BOX)),
            ("轮密钥加 K1", lambda s: s ^ k1),
            ("逆列混淆", lambda s: _mix_columns(s, inverse=True)),
            ("逆行移位", _shift_rows),
            ("逆半字节替换", lambda s: _substitute(s, INVERSE_S_BOX)),
            ("轮密钥加 K0／输出明文", lambda s: s ^ k0),
        )
    else:
        operations = (
            ("轮密钥加 K0", lambda s: s ^ k0),
            ("第1轮：半字节替换", lambda s: _substitute(s, S_BOX)),
            ("第1轮：行移位", _shift_rows),
            ("第1轮：列混淆", _mix_columns),
            ("第1轮：轮密钥加 K1", lambda s: s ^ k1),
            ("第2轮：半字节替换", lambda s: _substitute(s, S_BOX)),
            ("第2轮：行移位", _shift_rows),
            ("第2轮：轮密钥加 K2／输出密文", lambda s: s ^ k2),
        )
    for label, transform in operations:
        state = transform(state)
        steps.append(TraceStep(label, state))
    return tuple(steps)
