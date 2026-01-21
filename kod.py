import tkinter as tk
from tkinter import scrolledtext, messagebox

# ============================================================
# НАСТРОЙКИ
# ============================================================

BLOCK_SIZE = 8
ROUNDS = 8

# ============================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================

def pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def rotate_left(b: bytes, n: int):
    return b[n:] + b[:n]

# ============================================================
# ГЕНЕРАЦИЯ ПОДКЛЮЧЕЙ
# ============================================================

def key_schedule(key: bytes):
    key = key.ljust(BLOCK_SIZE, b'\x00')[:BLOCK_SIZE]
    keys = []
    k = key
    for _ in range(ROUNDS):
        keys.append(k)
        k = rotate_left(k, 1)
    return keys

# ============================================================
# ШИФРОВАНИЕ / ДЕШИФРОВАНИЕ БЛОКА (FEISTEL)
# ============================================================

def encrypt_block(block: bytes, subkeys):
    left = block[:4]
    right = block[4:]

    for k in subkeys:
        f = xor_bytes(right, k[:4])
        left, right = right, xor_bytes(left, f)

    return left + right

def decrypt_block(block: bytes, subkeys):
    left = block[:4]
    right = block[4:]

    for k in reversed(subkeys):
        f = xor_bytes(left, k[:4])
        left, right = xor_bytes(right, f), left

    return left + right

# ============================================================
# ШИФРОВАНИЕ / ДЕШИФРОВАНИЕ ТЕКСТА
# ============================================================

def encrypt(text: str, key: str) -> str:
    data = pad(text.encode("utf-8"))
    key_bytes = key.encode("utf-8")
    subkeys = key_schedule(key_bytes)

    out = b""
    for i in range(0, len(data), BLOCK_SIZE):
        out += encrypt_block(data[i:i+BLOCK_SIZE], subkeys)

    return out.hex()

def decrypt(cipher_hex: str, key: str) -> str:
    data = bytes.fromhex(cipher_hex)
    key_bytes = key.encode("utf-8")
    subkeys = key_schedule(key_bytes)

    out = b""
    for i in range(0, len(data), BLOCK_SIZE):
        out += decrypt_block(data[i:i+BLOCK_SIZE], subkeys)

    return unpad(out).decode("utf-8", errors="ignore")

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
