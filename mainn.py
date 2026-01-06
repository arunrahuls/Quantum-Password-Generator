 import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import math
import time
import secrets
import urllib.request
import urllib.error

ANU_URL = "https://qrng.anu.edu.au/API/jsonI.php?length={length}&type=uint8"

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/"


def fetch_anu_uint8(n: int, timeout_sec: float = 4.0):
    """Return (url_used, list_of_ints[0..255]) or raise RuntimeError on failure."""
    if not (1 <= n <= 1024):
        raise ValueError("ANU length must be between 1 and 1024.")
    url = ANU_URL.format(length=n)

    req = urllib.request.Request(
        url, headers={"User-Agent": "QuantumPasswordGenerator/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            payload = resp.read().decode("utf-8", errors="replace")
        data = json.loads(payload)

        if not isinstance(data, dict) or not data.get("success", False):
            raise RuntimeError(f"ANU returned non-success response: {data}")

        if "data" not in data or not isinstance(data["data"], list):
            raise RuntimeError(f"Unexpected ANU response format: {data}")

        return url, data["data"]
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as e:
        raise RuntimeError(f"ANU QRNG request failed: {e}")


def fallback_uint8(n: int):
    """Return list of n ints 0..255 using cryptographic local RNG."""
    return list(secrets.token_bytes(n))


def build_pool(include_symbols: bool):
    pool = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz" + "0123456789"
    if include_symbols:
        pool += SYMBOLS
    return pool


def entropy_bits(pool_size: int, length: int):
    return length * math.log2(pool_size)


def fisher_yates_shuffle(items, rand_bytes):
    n = len(items)
    if n <= 1:
        return items
    j = 0
    for i in range(n - 1, 0, -1):
        if j >= len(rand_bytes):
            rand_bytes.extend(fallback_uint8(64))
        r = rand_bytes[j]
        j += 1
        k = r % (i + 1)
        items[i], items[k] = items[k], items[i]
    return items


def strength_from_entropy(entropy: float):

    if entropy < 40:
        label = "Weak"
        desc = "Vulnerable to guessing/brute-force. Increase length and complexity."
    elif entropy < 60:
        label = "Moderate"
        desc = "Acceptable for low-risk accounts; better with more length/symbols."
    elif entropy < 80:
        label = "Strong"
        desc = "Good for most accounts. High resistance to brute-force."
    else:
        label = "Very Strong"
        desc = "Excellent strength. Very high entropy and unpredictability."

    progress = int(min(100, (entropy / 100) * 100))
    return label, progress, desc


def generate_password(length: int, include_symbols: bool, prefer_quantum: bool):
    pool = build_pool(include_symbols)
    pool_size = len(pool)

    required_sets = [
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
    ]

    if length < 8:
        raise ValueError("Password length must be at least 8.")
    if length > 32:
        raise ValueError("Password length must be at most 32 for this demo.")

    needed = min(1024, max(128, length * 6))

    method = "Cryptographic fallback (local)"
    url_used = None

    if prefer_quantum:
        try:
            url_used, rand = fetch_anu_uint8(needed)
            method = "Quantum (ANU QRNG API)"
        except Exception:
            rand = fallback_uint8(needed)
            method = "Fallback used (ANU unavailable) → Cryptographic local RNG"
    else:
        rand = fallback_uint8(needed)

    idx = 0

    def next_byte():
        nonlocal idx, rand
        if idx >= len(rand):
            rand.extend(fallback_uint8(64))
        b = rand[idx]
        idx += 1
        return b

    chars = []
    for charset in required_sets:
        chars.append(charset[next_byte() % len(charset)])

    remaining = length - len(chars)
    for _ in range(remaining):
        chars.append(pool[next_byte() % pool_size])

    fisher_yates_shuffle(chars, rand[idx:])

    password = "".join(chars)
    ent = entropy_bits(pool_size, length)
    strength_label, strength_progress, strength_desc = strength_from_entropy(
        ent)

    return {
        "password": password,
        "method": method,
        "url": url_used,
        "sample_bytes": rand[:16],
        "pool_size": pool_size,
        "entropy": ent,
        "strength": strength_label,
        "strength_progress": strength_progress,
        "strength_desc": strength_desc,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }



class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Quantum Password Generator (ANU QRNG + Strength Meter)")
        self.geometry("920x560")
        self.resizable(False, False)

        try:
            ttk.Style(self).theme_use("clam")
        except Exception:
            pass

        self.length_var = tk.IntVar(value=12)
        self.symbols_var = tk.BooleanVar(value=True)
        self.source_var = tk.StringVar(value="quantum")  # quantum | local

        self.password_var = tk.StringVar(value="")
        self.entropy_var = tk.StringVar(value="Entropy: —")
        self.status_var = tk.StringVar(value="Ready.")

        self.strength_text_var = tk.StringVar(value="Strength: —")
        self.strength_desc_var = tk.StringVar(value="")

        self._build_ui()

    def _build_ui(self):
        pad = 10
        root = ttk.Frame(self, padding=pad)
        root.pack(fill="both", expand=True)

        title = ttk.Label(root, text="Quantum Password Generator",
                          font=("Segoe UI", 18, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))

        # Controls
        controls = ttk.LabelFrame(root, text="Controls", padding=pad)
        controls.grid(row=1, column=0, sticky="nsew", padx=(0, 10))

        ttk.Label(controls, text="Password length (8–32):").grid(
            row=0, column=0, sticky="w")
        ttk.Spinbox(controls, from_=8, to=32, textvariable=self.length_var, width=6).grid(
            row=0, column=1, sticky="w")

        ttk.Checkbutton(controls, text="Include symbols", variable=self.symbols_var).grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))

        ttk.Label(controls, text="Randomness source:").grid(
            row=2, column=0, sticky="w", pady=(10, 0))
        ttk.Radiobutton(controls, text="ANU Quantum (Online)", value="quantum",
                        variable=self.source_var).grid(row=3, column=0, columnspan=2, sticky="w")
        ttk.Radiobutton(controls, text="Local (Cryptographic)", value="local",
                        variable=self.source_var).grid(row=4, column=0, columnspan=2, sticky="w")

        gen_btn = ttk.Button(controls, text="Generate",
                             command=self.on_generate)
        gen_btn.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(14, 0))

        copy_btn = ttk.Button(controls, text="Copy", command=self.on_copy)
        copy_btn.grid(row=6, column=0, sticky="ew", pady=(6, 0))

        save_btn = ttk.Button(
            controls, text="Save to file", command=self.on_save)
        save_btn.grid(row=6, column=1, sticky="ew", pady=(6, 0), padx=(6, 0))

        # Output
        output = ttk.LabelFrame(root, text="Output", padding=pad)
        output.grid(row=1, column=1, sticky="nsew")

        ttk.Label(output, text="Generated password:").grid(
            row=0, column=0, sticky="w")

        entry = ttk.Entry(output, textvariable=self.password_var,
                          font=("Consolas", 14), width=38)
        entry.grid(row=1, column=0, sticky="w", pady=(4, 8))

        strength_row = ttk.Frame(output)
        strength_row.grid(row=2, column=0, sticky="w")

        strength_label = ttk.Label(
            strength_row, textvariable=self.strength_text_var, font=("Segoe UI", 10, "bold"))
        strength_label.grid(row=0, column=0, sticky="w", padx=(0, 12))

        self.strength_bar = ttk.Progressbar(
            strength_row, length=220, maximum=100)
        self.strength_bar.grid(row=0, column=1, sticky="w")

        ttk.Label(output, textvariable=self.strength_desc_var, wraplength=520).grid(
            row=3, column=0, sticky="w", pady=(6, 6))

        ttk.Label(output, textvariable=self.entropy_var, font=(
            "Segoe UI", 10, "bold")).grid(row=4, column=0, sticky="w")

        ttk.Separator(output).grid(row=5, column=0, sticky="ew", pady=10)

        ttk.Label(output, text="How it works (evidence):").grid(
            row=6, column=0, sticky="w")

        self.evidence = tk.Text(
            output, height=13, width=68, font=("Consolas", 10))
        self.evidence.grid(row=7, column=0, sticky="nsew")
        self.evidence.insert(
            "end", "Click Generate to fetch quantum bytes and build the password.\n")

        status = ttk.Label(
            root, textvariable=self.status_var, foreground="blue")
        status.grid(row=2, column=0, columnspan=3, sticky="w", pady=(10, 0))

        root.columnconfigure(1, weight=1)
        root.rowconfigure(1, weight=1)

    def on_generate(self):
        self.status_var.set("Generating…")
        self.update_idletasks()

        try:
            length = int(self.length_var.get())
            include_symbols = bool(self.symbols_var.get())
            prefer_quantum = (self.source_var.get() == "quantum")

            info = generate_password(length, include_symbols, prefer_quantum)

            self.password_var.set(info["password"])
            self.entropy_var.set(
                f"Entropy: {info['entropy']:.2f} bits  |  Pool size: {info['pool_size']}")

            self.strength_text_var.set(f"Strength: {info['strength']}")
            self.strength_desc_var.set(info["strength_desc"])
            self.strength_bar["value"] = info["strength_progress"]

            self.evidence.delete("1.0", "end")
            self.evidence.insert("end", f"Timestamp: {info['timestamp']}\n")
            self.evidence.insert("end", f"Method:    {info['method']}\n")
            if info["url"]:
                self.evidence.insert("end", f"ANU URL:   {info['url']}\n")
                self.status_var.set("Used ANU QRNG ✅")
            else:
                self.evidence.insert("end", "ANU URL:   (not used)\n")
                self.status_var.set("Used Local RNG (or fallback) ⚠️")

            self.evidence.insert(
                "end", f"Sample bytes (first 16): {info['sample_bytes']}\n\n")
            self.evidence.insert("end", "Steps:\n")
            self.evidence.insert(
                "end", "1) Fetch uint8 random numbers (ANU quantum or local fallback)\n")
            self.evidence.insert(
                "end", "2) Guarantee 1 upper + 1 lower + 1 digit\n")
            self.evidence.insert(
                "end", "3) Fill remaining characters from full pool\n")
            self.evidence.insert(
                "end", "4) Shuffle (Fisher–Yates) using same randomness\n")
            self.evidence.insert(
                "end", "5) Compute entropy and display strength meter\n")

        except Exception as e:
            self.status_var.set("Error.")
            messagebox.showerror("Generation failed", str(e))

    def on_copy(self):
        pw = self.password_var.get()
        if not pw:
            return
        self.clipboard_clear()
        self.clipboard_append(pw)
        self.status_var.set("Copied to clipboard.")

    def on_save(self):
        pw = self.password_var.get()
        if not pw:
            messagebox.showinfo("Nothing to save",
                                "Generate a password first.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt")],
            title="Save password"
        )
        if not path:
            return

        evidence_text = self.evidence.get("1.0", "end").strip()
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("Quantum Password Generator\n")
                f.write("=" * 28 + "\n\n")
                f.write(f"Password: {pw}\n")
                f.write(f"{self.strength_text_var.get()}\n")
                f.write(f"{self.entropy_var.get()}\n\n")
                f.write(evidence_text + "\n")
            self.status_var.set(f"Saved: {path}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))


if __name__ == "__main__":
    App().mainloop()
