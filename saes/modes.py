"""ASCII 字符串、双重／三重加密及 CBC 模式。"""

from dataclasses import dataclass
import secrets

from .core import (require_uint, expand_key, _encrypt_with_keys, _decrypt_with_keys)
from .encoding import bytes_to_blocks, blocks_to_bytes, pad_bytes, unpad_bytes


def split_key(key: int, count: int) -> tuple[int, ...]:
    if count not in (1, 2, 3):
        raise ValueError("密钥数量必须为 1、2 或 3。")
    require_uint(key, 16 * count, "组合密钥")
    return tuple((key >> (16 * index)) & 0xFFFF for index in reversed(range(count)))


def transform_block(block: int, key: int, count: int = 1, decrypt: bool = False) -> int:
    """多重加密采用 EEE：E_K3(E_K2(E_K1(P)))，双重加密同理。"""
    require_uint(block, 16, "分组")
    keys = split_key(key, count)
    if decrypt:
        keys = keys[::-1]
    transform = _decrypt_with_keys if decrypt else _encrypt_with_keys
    for part in keys:
        block = transform(block, expand_key(part))
    return block


def transform_bytes(data: bytes, key: int, count: int = 1,
                    decrypt: bool = False, padding: bool = True) -> bytes:
    """逐分组处理字节串。padding=False 时由调用者提供完整分组。"""
    parts = split_key(key, count)
    keys = tuple(expand_key(k) for k in (parts[::-1] if decrypt else parts))
    transform = _decrypt_with_keys if decrypt else _encrypt_with_keys
    if decrypt and not data:
        raise ValueError("密文不能为空。")
    if not decrypt and padding:
        data = pad_bytes(data)
    output = []
    for block in bytes_to_blocks(data):
        for schedule in keys:
            block = transform(block, schedule)
        output.append(block)
    result = blocks_to_bytes(output)
    return unpad_bytes(result) if decrypt and padding else result


def generate_iv() -> int:
    return secrets.randbits(16)


@dataclass(frozen=True)
class CBCStep:
    index: int
    input_block: int
    chain: int
    intermediate: int
    output_block: int


def cbc_process(data: bytes, key: int, iv: int, decrypt: bool = False,
                padding: bool = True) -> tuple[bytes, tuple[CBCStep, ...]]:
    """返回字节结果和分组轨迹。IV 独立传递，不隐式拼接到密文。"""
    keys = expand_key(key)
    require_uint(iv, 16, "初始向量 IV")
    if decrypt and not data:
        raise ValueError("CBC 密文不能为空。")
    if not decrypt and padding:
        data = pad_bytes(data)
    chain, output, trace = iv, [], []
    for index, block in enumerate(bytes_to_blocks(data)):
        if decrypt:
            intermediate = _decrypt_with_keys(block, keys)
            result = intermediate ^ chain
        else:
            intermediate = block ^ chain
            result = _encrypt_with_keys(intermediate, keys)
        trace.append(CBCStep(index, block, chain, intermediate, result))
        output.append(result)
        chain = block if decrypt else result
    result = blocks_to_bytes(output)
    if decrypt and padding:
        result = unpad_bytes(result)
    return result, tuple(trace)


@dataclass(frozen=True)
class TamperResult:
    original_raw: bytes
    modified_ciphertext: bytes
    modified_raw: bytes
    changed_blocks: tuple[int, ...]
    original_unpadded: bytes | None
    original_padding_error: str | None
    modified_unpadded: bytes | None
    modified_padding_error: str | None


def compare_cbc_tampering(ciphertext: bytes, key: int, iv: int, index: int,
                          value: int, replace: bool = False) -> TamperResult:
    """分组序号从 0 开始；支持整组替换或与 16 位掩码异或。"""
    blocks = bytes_to_blocks(ciphertext)
    if type(index) is not int or not 0 <= index < len(blocks):
        raise ValueError(f"分组序号必须在 0 至 {len(blocks) - 1} 之间。")
    require_uint(value, 16, "替换值／异或掩码")
    if not replace and value == 0:
        raise ValueError("异或掩码不能为 0000，否则密文不会变化。")
    original, _ = cbc_process(ciphertext, key, iv, decrypt=True, padding=False)
    blocks[index] = value if replace else blocks[index] ^ value
    modified_ciphertext = blocks_to_bytes(blocks)
    if modified_ciphertext == ciphertext:
        raise ValueError("替换值与原密文相同，请选择不同的值。")
    modified, _ = cbc_process(modified_ciphertext, key, iv, decrypt=True, padding=False)
    changed = tuple(i for i, (a, b) in enumerate(zip(bytes_to_blocks(original),
                                                   bytes_to_blocks(modified))) if a != b)

    def try_unpad(data: bytes) -> tuple[bytes | None, str | None]:
        try:
            return unpad_bytes(data), None
        except ValueError as exc:
            return None, str(exc)

    original_unpadded, original_error = try_unpad(original)
    modified_unpadded, modified_error = try_unpad(modified)
    return TamperResult(original, modified_ciphertext, modified, changed,
                        original_unpadded, original_error, modified_unpadded, modified_error)
