import tkinter as tk
from tkinter import scrolledtext, messagebox
from typing import List

# ============================================================
# ВСПОМОГАТЕЛЬНЫЕ ТАБЛИЦЫ
# ============================================================

EXP_TABLE = [(pow(45, i, 257) - 1) % 256 for i in range(256)]
LOG_TABLE = [0] * 256
for i, v in enumerate(EXP_TABLE):
    LOG_TABLE[v] = i

def add_mod(x, y):
    return (x + y) % 256

def sub_mod(x, y):
    return (x - y) % 256

def exp(x):
    return EXP_TABLE[x]

def log(x):
    return LOG_TABLE[x]
# ============================================================
# ГЕНЕРАЦИЯ ПОДКЛЮЧЕЙ SAFER-K64
# ============================================================

def rotate_left(b: List[int], n=3):
    return b[n:] + b[:n]

def key_schedule(key: bytes, rounds=6):
    if len(key) != 8:
        raise ValueError("Ключ должен быть 8 байт")

    keys = []
    k = list(key)

    for r in range(1, rounds + 1):
        keys.append([(k[i] + r) % 256 for i in range(8)])
        k = rotate_left(k)

    return keys
# ============================================================
# ШИФРОВАНИЕ / ДЕШИФРОВАНИЕ БЛОКА
# ============================================================

def encrypt_block(block: List[int], subkeys):
    x = block[:]

    for k in subkeys:
        x[0] = exp(x[0] ^ k[0])
        x[1] = log(x[1] + k[1])
        x[2] = log(x[2] + k[2])
        x[3] = exp(x[3] ^ k[3])
        x[4] = exp(x[4] ^ k[4])
        x[5] = log(x[5] + k[5])
        x[6] = log(x[6] + k[6])
        x[7] = exp(x[7] ^ k[7])

        x = [
            add_mod(x[0], x[1]),
            add_mod(x[2], x[3]),
            add_mod(x[4], x[5]),
            add_mod(x[6], x[7]),
            x[1], x[3], x[5], x[7]
        ]

    return x
