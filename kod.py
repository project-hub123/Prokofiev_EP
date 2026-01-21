# ============================================================
# SAFER-K64 — УЧЕБНАЯ СТРОГО ОБРАТИМАЯ РЕАЛИЗАЦИЯ
# Шифрование / Дешифрование + GUI (Tkinter)
# ============================================================

import tkinter as tk
from tkinter import scrolledtext, messagebox

# ============================================================
# ОБРАТИМАЯ НЕЛИНЕЙНОСТЬ (S-BOX)
# ============================================================

SBOX = [(i * 73 + 41) % 256 for i in range(256)]
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

# ============================================================
# ГЕНЕРАЦИЯ ПОДКЛЮЧЕЙ
# ============================================================

def key_schedule(key: bytes, rounds=6):
    k = list(key)
    subkeys = []
    for r in range(rounds):
        subkeys.append([(k[i] + r) % 256 for i in range(8)])
        k = k[1:] + k[:1]  # циклический сдвиг
    return subkeys

# ============================================================
# ОБРАТИМОЕ ПЕРЕМЕШИВАНИЕ
# ============================================================

def mix(x):
    return [
        (x[0] + x[1]) % 256,
        (x[1] + x[2]) % 256,
        (x[2] + x[3]) % 256,
        (x[3] + x[4]) % 256,
        (x[4] + x[5]) % 256,
        (x[5] + x[6]) % 256,
        (x[6] + x[7]) % 256,
        x[7]
    ]

def inv_mix(x):
    return [
        (x[0] - x[1]) % 256,
        (x[1] - x[2]) % 256,
        (x[2] - x[3]) % 256,
        (x[3] - x[4]) % 256,
        (x[4] - x[5]) % 256,
        (x[5] - x[6]) % 256,
        (x[6] - x[7]) % 256,
        x[7]
    ]

# ============================================================
# ШИФРОВАНИЕ / ДЕШИФРОВАНИЕ БЛОКА
# ============================================================

def encrypt_block(block, subkeys):
    x = block[:]
    for k in subkeys:
        for i in range(8):
            x[i] = (x[i] + k[i]) % 256
        x = [SBOX[b] for b in x]
        x = mix(x)
    return x

def decrypt_block(block, subkeys):
    x = block[:]
    for k in reversed(subkeys):
        x = inv_mix(x)
        x = [INV_SBOX[b] for b in x]
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
        block = list(data[i:i+8])
        result.extend(encrypt_block(block, subkeys))

    return bytes(result).hex()

def decrypt(cipher_hex: str, key: str) -> str:
    key_b = key.encode("utf-8")[:8].ljust(8, b'\x00')
    subkeys = key_schedule(key_b)

    data = bytes.fromhex(cipher_hex)
    result = []

    for i in range(0, len(data), 8):
        block = list(data[i:i+8])
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
            text = self.input_text.get("1.0", tk.END).rstrip()
            if not key or not text:
                raise ValueError("Введите ключ и текст")
            self.enc_text.delete("1.0", tk.END)
            self.dec_text.delete("1.0", tk.END)
            self.enc_text.insert(tk.END, encrypt(text, key))
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def decrypt(self):
        try:
            key = self.key_entry.get()
            cipher = self.enc_text.get("1.0", tk.END).strip()
            if not key or not cipher:
                raise ValueError("Введите ключ и зашифрованный текст")
            self.dec_text.delete("1.0", tk.END)
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
