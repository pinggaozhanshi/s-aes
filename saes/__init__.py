"""教学用 S-AES：16 位分组、16 位基础密钥。"""

from .core import decrypt_block, encrypt_block, expand_key

__all__ = ["encrypt_block", "decrypt_block", "expand_key"]
