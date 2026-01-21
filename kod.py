# ============================================================
# SAFER-K64 (УЧЕБНАЯ СТРОГО ОБРАТИМАЯ РЕАЛИЗАЦИЯ)
# Шифрование / Дешифрование + GUI (Tkinter)
# ============================================================

import tkinter as tk
from tkinter import scrolledtext, messagebox
from typing import List

# ============================================================
# ОБРАТИМАЯ S-BOX (вместо EXP/LOG)
# ============================================================

SBOX = [(i * 197 + 123) % 256 for i in range(256)]
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i


# ============================================================
# ГЕНЕРАЦИЯ ПОДКЛЮЧЕЙ
# ============================================================

def rotate_left(b: List[int], n=3):
    return b[n:] + b[:n]


def key_schedule(key: bytes, rounds=6):
    keys = []
    k = list(key)

    for r in range(rounds):
        keys.append([(k[i] + r) % 256 for i in range(8)])
        k = rotate_left(k)

    return keys


# ============================================================
# ШИФРОВАНИЕ / ДЕШИФРОВАНИЕ БЛОКА
# ============================================================

def encrypt_block(block: List[int], subkeys):
    x = block[:]

    for k in subkeys:
        # наложение ключа
        for i in range(8):
            x[i] = (x[i] + k[i]) % 256

        # нелинейность
        x = [SBOX[b] for b in x]

        # обратимое перемешивание
        x = [
            (x[0] + x[1]) % 256,
            (x[1] + x[2]) % 256,
            (x[2] + x[3]) % 256,
            (x[3] + x[4]) % 256,
            (x[4] + x[5]) % 256,
            (x[5] + x[6]) % 256,
            (x[6] + x[7]) % 256,
            (x[7] + x[0]) % 256
        ]

    return x


def decrypt_block(block: List[int], subkeys):
    x = block[:]

    for k in reversed(subkeys):
        # обратное перемешивание
        x = [
            (x[7] - x[0]) % 256,
            (x[0] - x[1]) % 256,
            (x[1] - x[2]) % 256,
            (x[2] - x[3]) % 256,
            (x[3] - x[4]) % 256,
            (x[4] - x[5]) % 256,
            (x[5] - x[6]) % 256,
            (x[6] - x[7]) % 256
        ]

        # обратная нелинейность
        x = [INV_SBOX[b] for b in x]

        # снятие ключа
        for i in range(8):
            x[i] = (x[i] - k[i]) % 256

    return x


# ============================================================
# РАБОТА С ТЕКСТОМ
# ============================================================

def pad(data: bytes):
    while len(data) % 8 != 0:
        data += b'\x00'
    return data


def encrypt(text: str, key: str) -> str:
    key_b = key.encode("utf-8")[:8].ljust(8, b'\x00')
    subkeys = key_schedule(key_b)

    data = pad(text.encode("utf-8"))
    result = []

    for i in range(0, len(data), 8):
        result.extend(encrypt_block(list(data[i:i + 8]), subkeys))

    return bytes(result).hex()


def decrypt(cipher_hex: str, key: str) -> str:
    key_b = key.encode("utf-8")[:8].ljust(8, b'\x00')
    subkeys = key_schedule(key_b)

    data = bytes.fromhex(cipher_hex)
    result = []

    for i in range(0, len(data), 8):
        result.extend(decrypt_block(list(data[i:i + 8]), subkeys))

    return bytes(result).rstrip(b'\x00').decode("utf-8", errors="ignore")


# ============================================================
# GUI (ВСТАВКА ВО ВСЕ ПОЛЯ РАЗРЕШЕНА)
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
            self.enc_text.delete("1.0", tk.END)
            self.dec_text.delete("1.0", tk.END)

            key = self.key_entry.get()
            text = self.input_text.get("1.0", tk.END).rstrip()

            if not key or not text:
                raise ValueError("Ключ и текст должны быть заполнены")

            self.enc_text.insert(tk.END, encrypt(text, key))
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def decrypt(self):
        try:
            self.dec_text.delete("1.0", tk.END)

            key = self.key_entry.get()
            cipher = self.enc_text.get("1.0", tk.END).strip()

            if not key or not cipher:
                raise ValueError("Ключ и зашифрованный текст должны быть заполнены")

            self.dec_text.insert(tk.END, decrypt(cipher, key))
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))


# ============================================================
# ЗАПУСК
# ============================================================

if __name__ == "__main__":
    root = tk.Tk()
    SAFERApp(root)
    root.mainloop()
