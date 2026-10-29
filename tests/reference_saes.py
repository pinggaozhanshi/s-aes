"""验收用独立参考实现：二维矩阵、显式轮操作和多项式长除法。

不导入 saes，不代表其他小组的实现。算法参数来自课程指定 S-AES 标准。
"""

SUBSTITUTION = (9, 4, 10, 11, 13, 1, 8, 5, 6, 2, 0, 3, 12, 14, 15, 7)


def multiply(a, b):
    polynomial = 0
    for power in range(4):
        if b & (1 << power):
            polynomial ^= a << power
    for power in range(6, 3, -1):
        if polynomial & (1 << power):
            polynomial ^= 0x13 << (power - 4)
    return polynomial


def schedule(key):
    words = [key >> 8, key & 255]
    for constant in (0x80, 0x30):
        last = words[-1]
        rotated_sub = (SUBSTITUTION[last & 15] << 4) + SUBSTITUTION[last >> 4]
        words.append(words[-2] ^ constant ^ rotated_sub)
        words.append(words[-1] ^ words[-2])
    return [words[i] * 256 + words[i + 1] for i in (0, 2, 4)]


def matrix(value):
    return [[(value >> 12) & 15, (value >> 4) & 15],
            [(value >> 8) & 15, value & 15]]


def serialize(state):
    value = 0
    for column in range(2):
        for row in range(2):
            value = value * 16 + state[row][column]
    return value


def add_key(state, key):
    other = matrix(key)
    return [[state[r][c] ^ other[r][c] for c in range(2)] for r in range(2)]


def substitute(state, inverse=False):
    box = [SUBSTITUTION.index(i) for i in range(16)] if inverse else SUBSTITUTION
    return [[box[n] for n in row] for row in state]


def shift(state):
    return [state[0][:], state[1][::-1]]


def mix(state, inverse=False):
    coefficients = ((9, 2), (2, 9)) if inverse else ((1, 4), (4, 1))
    return [[multiply(coefficients[r][0], state[0][c]) ^
             multiply(coefficients[r][1], state[1][c]) for c in range(2)] for r in range(2)]


def encrypt(block, key):
    keys = schedule(key)
    state = add_key(matrix(block), keys[0])
    state = add_key(mix(shift(substitute(state))), keys[1])
    return serialize(add_key(shift(substitute(state)), keys[2]))


def decrypt(block, key):
    keys = schedule(key)
    state = substitute(shift(add_key(matrix(block), keys[2])), True)
    state = mix(add_key(state, keys[1]), True)
    return serialize(add_key(substitute(shift(state), True), keys[0]))
