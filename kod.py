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
