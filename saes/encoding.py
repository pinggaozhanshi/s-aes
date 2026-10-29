"""GUI 和实验共用的数据格式约定。字节序为大端，文本填充为 PKCS#7。"""

import re


def parse_fixed(value: str, bits: int, base: str = "hex", name: str = "输入") -> int:
    """严格要求固定长度；允许空白分隔和对应的 0x/0b 前缀。"""
    value = "".join(value.split())
    if base == "hex":
        value = value.removeprefix("0x").removeprefix("0X")
        digits, pattern, radix, kind = bits // 4, r"[0-9a-fA-F]+", 16, "十六进制字符"
    elif base == "bin":
        value = value.removeprefix("0b").removeprefix("0B")
        digits, pattern, radix, kind = bits, r"[01]+", 2, "二进制字符"
    else:
        raise ValueError("只支持 hex 或 bin 格式。")
    if len(value) != digits or re.fullmatch(pattern, value) is None:
        raise ValueError(f"{name}需要恰好 {digits} 个{kind}（{bits} 位）。")
    return int(value, radix)


def parse_hex_bytes(value: str, name: str = "密文") -> bytes:
    value = "".join(value.split())
    if not value or len(value) % 2 or re.fullmatch(r"[0-9a-fA-F]+", value) is None:
        raise ValueError(f"{name}需要非空、偶数长度的十六进制字节串，可用空格分隔。")
    return bytes.fromhex(value)


def encode_ascii(text: str) -> bytes:
    try:
        return text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("本实验的文本输入仅支持 ASCII 字符，请勿输入中文或其他非 ASCII 字符。") from exc


def escaped_bytes(data: bytes) -> str:
    """保留可打印 ASCII，其他字节写成转义形式，避免乱码和控制字符。"""
    return repr(data)[2:-1]


def pad_bytes(data: bytes) -> bytes:
    size = 2 - len(data) % 2
    return data + bytes([size]) * size


def unpad_bytes(data: bytes) -> bytes:
    if not data or len(data) % 2:
        raise ValueError("填充数据必须包含完整的 2 字节分组。")
    size = data[-1]
    if size not in (1, 2) or data[-size:] != bytes([size]) * size:
        raise ValueError("PKCS#7 填充无效：请核对密钥、IV、密文及填充约定。")
    return data[:-size]


def bytes_to_blocks(data: bytes) -> list[int]:
    if len(data) % 2:
        raise ValueError("数据长度必须是 2 字节的整数倍。")
    return [int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2)]


def blocks_to_bytes(blocks: list[int] | tuple[int, ...]) -> bytes:
    return b"".join(block.to_bytes(2, "big") for block in blocks)
