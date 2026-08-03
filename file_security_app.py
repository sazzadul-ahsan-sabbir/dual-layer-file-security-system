"""
Dual-Layer File Security System Using Symmetric Cryptography
--------------------------------------------------------------
A desktop GUI application (Tkinter) that lets a user:
  1. Generate a secure secret key, protected by a user-chosen PASSWORD
     (this is the "dual-layer" part: Layer 1 = password -> wraps ->
      Layer 2 = the actual Fernet key -> wraps -> the file content)
  2. Encrypt one or MULTIPLE files at once using that key
     (Fernet / AES-128-CBC + HMAC-SHA256)
  3. Decrypt one or MULTIPLE previously encrypted files using the
     matching key + correct password

Author: Sazzadul
Language: Python 3.x
Libraries: cryptography (Fernet, PBKDF2HMAC), tkinter, os, base64, json
"""

import os
import json
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PBKDF2_ITERATIONS = 390_000  # OWASP-recommended minimum (2024) for PBKDF2-HMAC-SHA256


class WrongPasswordError(Exception):
    """Raised when a key file cannot be unlocked with the given password."""


# ---------------------------------------------------------------------------
# Module 2: Key Management  (now password-protected — "dual layer")
# ---------------------------------------------------------------------------
def _derive_wrapping_key(password: str, salt: bytes) -> bytes:
    """Turn a human password + random salt into a Fernet-compatible key
    using PBKDF2-HMAC-SHA256. This 'wrapping key' is never stored — it is
    re-derived from the password each time the key file is opened."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def generate_key(save_path: str, password: str) -> None:
    """
    Generate a new secret Fernet key (Layer 2), then encrypt ("wrap") that
    key using a password-derived key (Layer 1) before saving to disk.
    The file on disk never contains the real key in plaintext.
    """
    actual_key = Fernet.generate_key()
    salt = os.urandom(16)
    wrapping_key = _derive_wrapping_key(password, salt)
    encrypted_key = Fernet(wrapping_key).encrypt(actual_key)

    payload = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "key": base64.b64encode(encrypted_key).decode("ascii"),
        "kdf_iterations": PBKDF2_ITERATIONS,
    }
    with open(save_path, "w", encoding="utf-8") as f:
        json.dump(payload, f)


def load_key(key_path: str, password: str) -> bytes:
    """
    Read a password-protected key file and recover the real Fernet key.
    Raises WrongPasswordError if the password is incorrect.
    """
    with open(key_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    salt = base64.b64decode(payload["salt"])
    encrypted_key = base64.b64decode(payload["key"])
    iterations = payload.get("kdf_iterations", PBKDF2_ITERATIONS)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
    )
    wrapping_key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    try:
        return Fernet(wrapping_key).decrypt(encrypted_key)
    except InvalidToken:
        raise WrongPasswordError("Incorrect password for this key file.")


# ---------------------------------------------------------------------------
# Module 3: File Processing Engine
# ---------------------------------------------------------------------------
def encrypt_file(file_path: str, key: bytes) -> None:
    """Read a file as raw bytes, encrypt it with Fernet, overwrite in place."""
    fernet = Fernet(key)
    with open(file_path, "rb") as f:
        original_data = f.read()
    encrypted_data = fernet.encrypt(original_data)
    with open(file_path, "wb") as f:
        f.write(encrypted_data)


def decrypt_file(file_path: str, key: bytes) -> None:
    """Read an encrypted file, verify + decrypt with Fernet, overwrite in place.
    Raises InvalidToken if the key is wrong or the ciphertext was tampered with."""
    fernet = Fernet(key)
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
    decrypted_data = fernet.decrypt(encrypted_data)  # raises InvalidToken on failure
    with open(file_path, "wb") as f:
        f.write(decrypted_data)


# ---------------------------------------------------------------------------
# Module 3b: Batch Processing (multiple files in one go)
# ---------------------------------------------------------------------------
def process_files_batch(file_paths, key: bytes, mode: str):
    """
    Run encrypt or decrypt over a list of files.
    Returns (successes, failures) where failures is a list of
    (file_path, error_message) tuples. One failure does not stop the batch.
    """
    action = encrypt_file if mode == "encrypt" else decrypt_file
    successes, failures = [], []

    for path in file_paths:
        try:
            action(path, key)
            successes.append(path)
        except InvalidToken:
            failures.append((path, "Invalid key or file has been tampered with / corrupted."))
        except Exception as e:
            failures.append((path, str(e)))

    return successes, failures


# ---------------------------------------------------------------------------
# Module 1: Graphical User Interface (GUI)
# ---------------------------------------------------------------------------
class FileSecurityApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Dual-Layer File Security System")
        self.root.geometry("560x500")
        self.root.resizable(False, False)

        self.key_path_var = tk.StringVar(value="No key selected")
        self.selected_files = []  # list of full paths, backs the listbox

        self._build_ui()

    # ---- UI construction -------------------------------------------------
    def _build_ui(self):
        title = tk.Label(
            self.root, text="Dual-Layer File Security System",
            font=("Segoe UI", 14, "bold"),
        )
        title.pack(pady=(18, 4))

        subtitle = tk.Label(
            self.root,
            text="Password-Protected Key + Fernet (AES-128 / HMAC-SHA256) — Batch Mode",
            font=("Segoe UI", 9), fg="gray",
        )
        subtitle.pack(pady=(0, 15))

        # --- Key selection row ---
        key_frame = tk.LabelFrame(self.root, text="Secret Key (password-protected)", padx=10, pady=8)
        key_frame.pack(fill="x", padx=20, pady=6)

        tk.Label(key_frame, textvariable=self.key_path_var, fg="blue", wraplength=380).pack(
            side="left", fill="x", expand=True
        )
        tk.Button(key_frame, text="Browse Key", command=self.browse_key).pack(side="right")

        # --- File selection (multi) ---
        file_frame = tk.LabelFrame(self.root, text="Target Files", padx=10, pady=8)
        file_frame.pack(fill="both", padx=20, pady=6, expand=True)

        list_container = tk.Frame(file_frame)
        list_container.pack(fill="both", expand=True)

        scrollbar = tk.Scrollbar(list_container, orient="vertical")
        self.file_listbox = tk.Listbox(
            list_container, selectmode=tk.EXTENDED, height=8, yscrollcommand=scrollbar.set,
        )
        scrollbar.config(command=self.file_listbox.yview)
        self.file_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        file_btn_frame = tk.Frame(file_frame)
        file_btn_frame.pack(fill="x", pady=(8, 0))

        tk.Button(file_btn_frame, text="Add File(s)", command=self.browse_files).pack(side="left", padx=(0, 6))
        tk.Button(file_btn_frame, text="Remove Selected", command=self.remove_selected_files).pack(side="left", padx=6)
        tk.Button(file_btn_frame, text="Clear All", command=self.clear_files).pack(side="left", padx=6)

        # --- Action buttons ---
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=18)

        tk.Button(
            btn_frame, text="🔑 Generate Key", width=16, height=2, command=self.on_generate_key,
        ).grid(row=0, column=0, padx=6)

        tk.Button(
            btn_frame, text="🔒 Encrypt All", width=16, height=2,
            bg="#2e7d32", fg="white", command=self.on_encrypt,
        ).grid(row=0, column=1, padx=6)

        tk.Button(
            btn_frame, text="🔓 Decrypt All", width=16, height=2,
            bg="#c62828", fg="white", command=self.on_decrypt,
        ).grid(row=0, column=2, padx=6)

        # --- Status bar ---
        self.status_var = tk.StringVar(value="Ready.")
        status = tk.Label(
            self.root, textvariable=self.status_var, bd=1, relief="sunken",
            anchor="w", font=("Segoe UI", 9),
        )
        status.pack(side="bottom", fill="x")

    # ---- Browsing helpers --------------------------------------------------
    def browse_key(self):
        path = filedialog.askopenfilename(
            title="Select Key File", filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        if path:
            self.key_path_var.set(path)

    def browse_files(self):
        paths = filedialog.askopenfilenames(title="Select File(s) to Encrypt/Decrypt")
        if not paths:
            return
        added = 0
        for p in paths:
            if p not in self.selected_files:
                self.selected_files.append(p)
                self.file_listbox.insert(tk.END, p)
                added += 1
        self.status_var.set(f"Added {added} file(s). Total: {len(self.selected_files)}")

    def remove_selected_files(self):
        selected_indices = list(self.file_listbox.curselection())
        if not selected_indices:
            return
        for index in reversed(selected_indices):
            self.file_listbox.delete(index)
            del self.selected_files[index]
        self.status_var.set(f"Removed {len(selected_indices)} file(s). Total: {len(self.selected_files)}")

    def clear_files(self):
        self.file_listbox.delete(0, tk.END)
        self.selected_files.clear()
        self.status_var.set("File list cleared.")

    # ---- Password prompts ---------------------------------------------------
    def _ask_new_password(self):
        """Prompt for a new password twice and confirm they match."""
        while True:
            pw1 = simpledialog.askstring(
                "Set a Password", "Enter a password to protect this key:", show="*", parent=self.root
            )
            if pw1 is None:
                return None  # user cancelled
            if len(pw1) < 6:
                messagebox.showwarning("Weak Password", "Use at least 6 characters.")
                continue
            pw2 = simpledialog.askstring(
                "Confirm Password", "Re-enter the same password:", show="*", parent=self.root
            )
            if pw2 is None:
                return None
            if pw1 != pw2:
                messagebox.showerror("Mismatch", "Passwords did not match. Try again.")
                continue
            return pw1

    def _ask_existing_password(self):
        return simpledialog.askstring(
            "Unlock Key", "Enter the password for this key file:", show="*", parent=self.root
        )

    # ---- Button actions ----------------------------------------------------
    def on_generate_key(self):
        save_path = filedialog.asksaveasfilename(
            title="Save New Key As", defaultextension=".key",
            filetypes=[("Key files", "*.key")], initialfile="secret.key",
        )
        if not save_path:
            return

        password = self._ask_new_password()
        if password is None:
            self.status_var.set("Key generation cancelled.")
            return

        try:
            generate_key(save_path, password)
            self.key_path_var.set(save_path)
            self.status_var.set(f"New password-protected key generated: {os.path.basename(save_path)}")
            messagebox.showinfo(
                "Success",
                "A new secret key has been generated and locked with your password.\n\n"
                "Keep BOTH the .key file and the password safe — losing either one "
                "makes the data unrecoverable.",
            )
        except Exception as e:
            messagebox.showerror("Error", f"Could not generate key:\n{e}")

    def on_encrypt(self):
        self._run_batch(mode="encrypt")

    def on_decrypt(self):
        self._run_batch(mode="decrypt")

    def _run_batch(self, mode: str):
        key_path = self.key_path_var.get()
        if not key_path or key_path == "No key selected" or not os.path.isfile(key_path):
            messagebox.showwarning("Missing Key", "Please select a valid .key file first.")
            return
        if not self.selected_files:
            messagebox.showwarning("No Files", "Please add at least one file to process.")
            return

        password = self._ask_existing_password()
        if password is None:
            self.status_var.set(f"{mode.capitalize()} cancelled.")
            return

        try:
            key = load_key(key_path, password)
        except WrongPasswordError:
            messagebox.showerror("Wrong Password", "That password does not unlock this key file.")
            self.status_var.set("Wrong password — operation cancelled.")
            return
        except Exception as e:
            messagebox.showerror("Error", f"Could not read key file:\n{e}")
            return

        total = len(self.selected_files)
        self.status_var.set(f"{mode.capitalize()}ing {total} file(s)...")
        self.root.update_idletasks()

        successes, failures = process_files_batch(self.selected_files, key, mode)

        verb = "encrypted" if mode == "encrypt" else "decrypted"
        summary_lines = [f"{len(successes)} of {total} file(s) {verb} successfully."]
        if failures:
            summary_lines.append("\nFailed:")
            for path, err in failures:
                summary_lines.append(f"  • {os.path.basename(path)} — {err}")

        summary_text = "\n".join(summary_lines)
        self.status_var.set(f"{len(successes)}/{total} {verb}. {len(failures)} failed.")

        if failures:
            messagebox.showwarning(f"{mode.capitalize()} Completed with Errors", summary_text)
        else:
            messagebox.showinfo(f"{mode.capitalize()} Complete", summary_text)


def main():
    root = tk.Tk()
    app = FileSecurityApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
