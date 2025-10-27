"""
Enterprise Secure File Storage System (AES-256-GCM) - v4.1
----------------------------------------------------------
Features:
• AES-256-GCM streaming encryption/decryption
• Accurate progress bar & live percentage
• Correct .enc handling (no filename errors)
• SHA-256 integrity verification
• SQLite metadata logging (auto-upgrades schema)
• Responsive GUI (threaded operations)
• Secure key generation & reuse

Dependencies:
    pip install cryptography
"""

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import sqlite3, datetime, threading, hashlib, secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time

# ---------------- CONFIG ----------------
MASTER_KEY_FILE = "master.key"
DB_FILE = "storage_metadata.db"
CHUNK_SIZE = 64 * 1024  # 64KB chunks

# ---------------- KEY MANAGEMENT ----------------
def create_or_load_master_key():
    """Ensure a secure 32-byte AES key exists."""
    if not os.path.exists(MASTER_KEY_FILE):
        key = secrets.token_bytes(32)
        with open(MASTER_KEY_FILE, "wb") as f:
            f.write(key)
        os.chmod(MASTER_KEY_FILE, 0o600)
    else:
        with open(MASTER_KEY_FILE, "rb") as f:
            key = f.read()
        if len(key) != 32:
            key = secrets.token_bytes(32)
            with open(MASTER_KEY_FILE, "wb") as f:
                f.write(key)
    return key

MASTER_KEY = create_or_load_master_key()

# ---------------- DATABASE (Auto-Upgrade) ----------------
def init_db():
    """Create or upgrade DB to required schema."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Step 1: Ensure base table exists
    c.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            operation TEXT,
            timestamp TEXT
        )
    """)
    # Step 2: Check existing columns
    c.execute("PRAGMA table_info(files)")
    cols = [row[1] for row in c.fetchall()]
    # Step 3: Add missing columns
    required = {
        "orig_sha256": "TEXT",
        "enc_sha256": "TEXT",
        "nonce": "BLOB",
        "tag": "BLOB"
    }
    for name, ctype in required.items():
        if name not in cols:
            try:
                c.execute(f"ALTER TABLE files ADD COLUMN {name} {ctype}")
                print(f"[DB Upgrade] Added column: {name}")
            except Exception as e:
                print(f"[DB Upgrade] Could not add {name}: {e}")
    conn.commit()
    conn.close()

def log_entry(filename, operation, orig_sha256=None, enc_sha256=None, nonce=None, tag=None):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO files (filename, operation, orig_sha256, enc_sha256, nonce, tag, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (filename, operation, orig_sha256, enc_sha256, nonce, tag,
         datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

init_db()

# ---------------- UTILITIES ----------------
def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def human_size(b):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"

def run_in_thread(fn, *a, **kw):
    threading.Thread(target=fn, args=a, kwargs=kw, daemon=True).start()

# ---------------- AES-GCM STREAM ENCRYPTION ----------------
def encrypt_stream(in_path, out_path, key, progress_cb=None):
    file_size = os.path.getsize(in_path)
    nonce = secrets.token_bytes(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce),
                       backend=default_backend()).encryptor()

    orig_h = hashlib.sha256()
    total = 0
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(nonce)
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            orig_h.update(chunk)
            fout.write(encryptor.update(chunk))
            total += len(chunk)
            if progress_cb:
                progress_cb(total, file_size)
        encryptor.finalize()
        fout.write(encryptor.tag)

    return orig_h.hexdigest(), sha256_of_file(out_path), nonce, encryptor.tag

def decrypt_stream(in_path, out_path, key, progress_cb=None):
    size = os.path.getsize(in_path)
    if size < 28:
        raise ValueError("File too small to decrypt")
    with open(in_path, "rb") as f:
        nonce = f.read(12)
        ciphertext_len = size - 12 - 16
        temp_path = in_path + ".tmp"
        with open(temp_path, "wb") as tf:
            remaining = ciphertext_len
            while remaining > 0:
                data = f.read(min(CHUNK_SIZE, remaining))
                if not data:
                    break
                tf.write(data)
                remaining -= len(data)
        tag = f.read(16)
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag),
                       backend=default_backend()).decryptor()

    dec_h = hashlib.sha256()
    processed = 0
    with open(temp_path, "rb") as cin, open(out_path, "wb") as fout:
        while True:
            chunk = cin.read(CHUNK_SIZE)
            if not chunk:
                break
            pt = decryptor.update(chunk)
            fout.write(pt)
            dec_h.update(pt)
            processed += len(chunk)
            if progress_cb:
                progress_cb(processed, ciphertext_len)
        decryptor.finalize()
    os.remove(temp_path)
    return dec_h.hexdigest(), nonce, tag

# ---------------- GUI APPLICATION ----------------
class SecureStorageApp:
    def __init__(self, root):
        self.root = root
        root.title("Enterprise Secure File Storage System (AES-256-GCM) - v4.1")
        root.geometry("650x400")
        root.resizable(False, False)

        style = ttk.Style()
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6)
        style.configure("TLabel", font=("Segoe UI", 10))

        ttk.Label(root, text="🔒 Enterprise Secure File Storage System (AES-256-GCM)",
                  font=("Segoe UI", 14, "bold")).pack(pady=(12, 8))

        frame = ttk.Frame(root)
        frame.pack(pady=10)
        self.encrypt_btn = ttk.Button(frame, text="Encrypt File", width=34,
                                      command=self.select_encrypt)
        self.encrypt_btn.grid(row=0, column=0, padx=8, pady=8)
        self.decrypt_btn = ttk.Button(frame, text="Decrypt File", width=34,
                                      command=self.select_decrypt)
        self.decrypt_btn.grid(row=1, column=0, padx=8, pady=8)
        self.viewlog_btn = ttk.Button(frame, text="View Logs", width=34,
                                      command=self.show_logs)
        self.viewlog_btn.grid(row=2, column=0, padx=8, pady=8)

        self.status = tk.StringVar(value="Ready")
        ttk.Label(root, textvariable=self.status, font=("Segoe UI", 10)).pack(pady=(8, 3))

        self.progress = ttk.Progressbar(root, mode="determinate", length=540)
        self.progress.pack(pady=(2, 6))

        self.fileinfo = tk.StringVar(value="")
        ttk.Label(root, textvariable=self.fileinfo, font=("Segoe UI", 9, "italic")).pack()

        ttk.Label(root, text="AES-256 | GCM | SHA-256 | Auto-Healing DB",
                  font=("Segoe UI", 9, "italic")).pack(side="bottom", pady=8)

        self.selected = None
        print("✅ Secure File Storage v4.1 initialized. DB ready.")

    # ---------- UI helpers ----------
    def set_busy(self, busy=True, msg=None):
        widgets = [self.encrypt_btn, self.decrypt_btn, self.viewlog_btn]
        for w in widgets:
            w.config(state=("disabled" if busy else "normal"))
        self.progress["value"] = 0
        self.status.set(msg or ("Processing..." if busy else "Ready"))
        self.root.update_idletasks()

    def update_progress(self, processed, total):
        if total:
            pct = min(100, int((processed / total) * 100))
        else:
            pct = 0
        self.progress["value"] = pct
        self.status.set(f"{pct}% ({human_size(processed)}/{human_size(total)})")
        self.root.update_idletasks()

    # ---------- Actions ----------
    def select_encrypt(self):
        p = filedialog.askopenfilename(title="Select file to encrypt")
        if p:
            self.selected = p
            self.fileinfo.set(f"Encrypting: {os.path.basename(p)} | {human_size(os.path.getsize(p))}")
            run_in_thread(self._encrypt)

    def select_decrypt(self):
        p = filedialog.askopenfilename(title="Select encrypted (.enc) file")
        if p:
            self.selected = p
            self.fileinfo.set(f"Decrypting: {os.path.basename(p)} | {human_size(os.path.getsize(p))}")
            run_in_thread(self._decrypt)

    def _encrypt(self):
        try:
            self.set_busy(True, "Encrypting...")
            inp = self.selected
            outp = inp + ".enc"
            orig, enc, nonce, tag = encrypt_stream(inp, outp, MASTER_KEY, self.update_progress)
            log_entry(os.path.basename(outp), "ENCRYPTED", orig, enc, nonce, tag)
            self.set_busy(False, "Encryption done")
            messagebox.showinfo("Done", f"Encrypted → {outp}\nSHA256 (orig): {orig}\nSHA256 (enc): {enc}")
        except Exception as e:
            self.set_busy(False, "Error")
            messagebox.showerror("Encryption Error", str(e))

    def _decrypt(self):
        try:
            self.set_busy(True, "Decrypting...")
            inp = self.selected
            # correct filename restore
            base = os.path.basename(inp)
            if base.lower().endswith(".enc"):
                original_name = base[:-4]
            else:
                original_name = base
            name, ext = os.path.splitext(original_name)
            dec_name = f"{name}_decrypted{ext or ''}"
            outp = os.path.join(os.path.dirname(inp), dec_name)

            dec_hash, nonce, tag = decrypt_stream(inp, outp, MASTER_KEY, self.update_progress)
            enc_hash = sha256_of_file(inp)
            # lookup stored original hash
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT orig_sha256 FROM files WHERE filename=? ORDER BY id DESC LIMIT 1",
                      (os.path.basename(inp),))
            row = c.fetchone()
            conn.close()
            orig_stored = row[0] if row else None
            integrity = "N/A"
            if orig_stored:
                integrity = "PASSED ✅" if constant_time.bytes_eq(dec_hash.encode(), orig_stored.encode()) else "FAILED ❌"
            log_entry(os.path.basename(outp), "DECRYPTED", orig_stored, enc_hash, nonce, tag)
            self.set_busy(False, "Decryption done")
            messagebox.showinfo("Decryption Complete",
                                f"Output: {outp}\nSHA256 (dec): {dec_hash}\nIntegrity: {integrity}")
        except Exception as e:
            self.set_busy(False, "Error")
            messagebox.showerror("Decryption Error", str(e))

    def show_logs(self):
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT filename, operation, orig_sha256, enc_sha256, timestamp FROM files ORDER BY id DESC")
            rows = c.fetchall()
            conn.close()
            w = tk.Toplevel(self.root)
            w.title("Activity Logs")
            w.geometry("1000x420")
            tree = ttk.Treeview(w, columns=("Filename", "Operation", "OrigSHA", "EncSHA", "Timestamp"), show="headings")
            for col in ("Filename", "Operation", "OrigSHA", "EncSHA", "Timestamp"):
                tree.heading(col, text=col)
            tree.column("Filename", width=250)
            tree.column("Operation", width=100, anchor="center")
            tree.column("OrigSHA", width=260)
            tree.column("EncSHA", width=260)
            tree.column("Timestamp", width=140, anchor="center")
            tree.pack(fill="both", expand=True)
            for r in rows:
                tree.insert("", tk.END, values=r)
        except Exception as e:
            messagebox.showerror("Logs Error", str(e))

# ---------------- RUN ----------------
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureStorageApp(root)
    root.mainloop()
