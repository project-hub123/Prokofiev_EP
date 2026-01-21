# ============================================================
# SAFER-K64 — Шифрование / Дешифрование
# Полная исправленная версия (GUI + алгоритм)
# ============================================================

import tkinter as tk
from tkinter import scrolledtext, messagebox
from typing import List

# ============================================================
# EXP / LOG таблицы (исправленные)
# ============================================================

EXP_TABLE = [(pow(45, i, 257) - 1) % 256 for i in range(256)]
LOG_TABLE = [0] * 256
for i, v in enumerate(EXP_TABLE):
    LOG_TABLE[v] = i


def exp(x: int) -> int:
    return EXP_TABLE[x % 256]


def log(x: int) -> int:
    return LOG_TABLE[x % 256]


def add_mod(x, y):
    return (x + y) % 256


def sub_mod(x, y):
    return (x - y) % 256


# ============================================================
# Генерация подключей SAFER-K64
# ============================================================

def rotate_left(b: List[int], n=3):
    return b[n:] + b[:n]


def key_schedule(key: bytes, rounds=6):
    if len(key) != 8:
        raise ValueError("Ключ должен быть длиной 8 байт")

    keys = []
    k = list(key)

    for r in range(1, rounds + 1):
        keys.append([(k[i] + r) % 256 for i in range(8)])
        k = rotate_left(k)

    return keys


# ============================================================
# Шифрование и дешифрование блока
# ============================================================

def encrypt_block(block: List[int], subkeys):
    x = block[:]

    for k in subkeys:
        x[0] = exp(x[0] ^ k[0])
        x[1] = log((x[1] + k[1]) % 256)
        x[2] = log((x[2] + k[2]) % 256)
        x[3] = exp(x[3] ^ k[3])
        x[4] = exp(x[4] ^ k[4])
        x[5] = log((x[5] + k[5]) % 256)
        x[6] = log((x[6] + k[6]) % 256)
        x[7] = exp(x[7] ^ k[7])

        x = [
            add_mod(x[0], x[1]),
            add_mod(x[2], x[3]),
            add_mod(x[4], x[5]),
            add_mod(x[6], x[7]),
            x[1], x[3], x[5], x[7]
        ]

    return x


def decrypt_block(block: List[int], subkeys):
    x = block[:]

    for k in reversed(subkeys):
        x = [
            x[0],
            sub_mod(x[0], x[1]),
            x[1],
            sub_mod(x[2], x[3]),
            x[2],
            sub_mod(x[4], x[5]),
            x[3],
            sub_mod(x[6], x[7])
        ]

        x[0] = exp(x[0]) ^ k[0]
        x[1] = sub_mod(log(x[1]), k[1])
        x[2] = sub_mod(log(x[2]), k[2])
        x[3] = exp(x[3]) ^ k[3]
        x[4] = exp(x[4]) ^ k[4]
        x[5] = sub_mod(log(x[5]), k[5])
        x[6] = sub_mod(log(x[6]), k[6])
        x[7] = exp(x[7]) ^ k[7]

    return x


# ============================================================
# Работа с текстом
# ============================================================

def pad(data: bytes):
    while len(data) % 8 != 0:
        data += b'\x00'
    return data


def encrypt(text: str, key: str):
    key_b = key.encode("utf-8")[:8].ljust(8, b'\x00')
    subkeys = key_schedule(key_b)

    data = pad(text.encode("utf-8"))
    result = []

    for i in range(0, len(data), 8):
        block = list(data[i:i + 8])
        result.extend(encrypt_block(block, subkeys))

    return bytes(result).hex()


def decrypt(cipher_hex: str, key: str):
    key_b = key.encode("utf-8")[:8].ljust(8, b'\x00')
    subkeys = key_schedule(key_b)

    data = bytes.fromhex(cipher_hex)
    result = []

    for i in range(0, len(data), 8):
        block = list(data[i:i + 8])
        result.extend(decrypt_block(block, subkeys))

    return bytes(result).rstrip(b'\x00').decode("utf-8", errors="ignore")


# ============================================================
# GUI
# ============================================================

class SAFERApp:
    def __init__(self, root):
        root.title("SAFER-K64 — Шифрование / Дешифрование")
        root.geometry("900x600")

        tk.Label(root, text="Ключ (до 8 символов):").pack()
        self.key_entry = tk.Entry(root, width=40)
        self.key_entry.pack()

        tk.Label(root, text="Открытый текст:").pack()
        self.input_text = scrolledtext.ScrolledText(root, height=8)
        self.input_text.pack(fill=tk.BOTH, padx=10)

        tk.Label(root, text="Зашифрованный текст (HEX):").pack()
        self.enc_text = scrolledtext.ScrolledText(root, height=8)
        self.enc_text.pack(fill=tk.BOTH, padx=10)

        tk.Label(root, text="Расшифрованный текст:").pack()
        self.dec_text = scrolledtext.ScrolledText(root, height=8)
        self.dec_text.pack(fill=tk.BOTH, padx=10)

        frame = tk.Frame(root)
        frame.pack(pady=10)

        tk.Button(frame, text="Зашифровать", width=20, command=self.encrypt).pack(side=tk.LEFT, padx=5)
        tk.Button(frame, text="Расшифровать", width=20, command=self.decrypt).pack(side=tk.LEFT, padx=5)

    def encrypt(self):
        try:
            key = self.key_entry.get()
            if not key:
                raise ValueError("Введите ключ")

            text = self.input_text.get("1.0", tk.END).rstrip()
            if not text:
                raise ValueError("Введите открытый текст")

            self.enc_text.delete("1.0", tk.END)
            self.enc_text.insert(tk.END, encrypt(text, key))
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def decrypt(self):
        try:
            key = self.key_entry.get()
            if not key:
                raise ValueError("Введите ключ")

            cipher = self.enc_text.get("1.0", tk.END).strip()
            if not cipher:
                raise ValueError("Введите зашифрованный текст")

            self.dec_text.delete("1.0", tk.END)
            self.dec_text.insert(tk.END, decrypt(cipher, key))
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))


# ============================================================
# Запуск
# ============================================================

if __name__ == "__main__":
    root = tk.Tk()
    SAFERApp(root)
    root.mainloop()
