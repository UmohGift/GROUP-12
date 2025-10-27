import tkinter as tk
from tkinter import messagebox
import json
import os
import base64
import pyperclip
import time
import threading
import secrets
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class PasswordVaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Vault")
        self.root.geometry("450x500")
        self.root.resizable(False, False)

        self.storage_file = "storage.json"
        self.key = None
        self.data = {}

        self.master_password_var = tk.StringVar()
        self.entry_name_var = tk.StringVar()
        self.entry_username_var = tk.StringVar()
        self.entry_password_var = tk.StringVar()

        self.create_login_ui()

    # ------------------------- UI SETUP ------------------------- #
    def create_login_ui(self):
        self.clear_frame()
        tk.Label(self.root, text="🔐 Password Vault", font=("Arial", 18, "bold")).pack(pady=20)
        tk.Label(self.root, text="Enter Master Password:").pack(pady=10)
        tk.Entry(self.root, textvariable=self.master_password_var, show="*").pack()
        tk.Button(self.root, text="Login", command=self.login).pack(pady=10)
        tk.Label(self.root, text="(A new vault will be created if none exists)").pack()

    def create_main_ui(self):
        self.clear_frame()
        tk.Label(self.root, text="Vault Dashboard", font=("Arial", 16, "bold")).pack(pady=10)
        tk.Button(self.root, text="➕ Add New Entry", width=20, command=self.add_entry_ui).pack(pady=5)
        tk.Button(self.root, text="📋 View All Entries", width=20, command=self.view_entries_ui).pack(pady=5)
        tk.Button(self.root, text="🚪 Logout", width=20, command=self.logout).pack(pady=20)

    def add_entry_ui(self):
        self.clear_frame()
        tk.Label(self.root, text="Add New Entry", font=("Arial", 16, "bold")).pack(pady=10)

        tk.Label(self.root, text="Site Name:").pack()
        tk.Entry(self.root, textvariable=self.entry_name_var).pack()

        tk.Label(self.root, text="Username:").pack()
        tk.Entry(self.root, textvariable=self.entry_username_var).pack()

        tk.Label(self.root, text="Password:").pack()
        tk.Entry(self.root, textvariable=self.entry_password_var, show="*").pack()

        tk.Button(self.root, text="Generate Strong Password", command=self.fill_generated_password).pack(pady=5)

        self.strength_label = tk.Label(self.root, text="Strength: N/A")
        self.strength_label.pack(pady=2)
        self.entry_password_var.trace("w", lambda *args: self.update_strength_label())

        tk.Button(self.root, text="Save Entry", command=self.save_entry).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.create_main_ui).pack()

    def view_entries_ui(self):
        self.clear_frame()
        tk.Label(self.root, text="Stored Entries", font=("Arial", 16, "bold")).pack(pady=10)

        for site, creds in self.data.items():
            frame = tk.Frame(self.root)
            frame.pack(fill="x", padx=20, pady=3)
            tk.Label(frame, text=f"{site} ({creds['username']})", anchor="w", width=25).pack(side="left")
            tk.Button(frame, text="Copy Password", command=lambda p=creds['password']: self.copy_password(p)).pack(side="left", padx=5)
            tk.Button(frame, text="Delete", command=lambda s=site: self.delete_entry(s)).pack(side="left", padx=5)

        tk.Button(self.root, text="Back", command=self.create_main_ui).pack(pady=10)

    def clear_frame(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    # ------------------------- AUTH / VAULT ------------------------- #
    def login(self):
        master_pwd = self.master_password_var.get()
        if not master_pwd:
            messagebox.showerror("Error", "Enter master password!")
            return

        self.key = self.derive_key(master_pwd)

        if not os.path.exists(self.storage_file):
            self.save_data({})
            self.data = {}
            messagebox.showinfo("New Vault", "New vault created successfully.")
            self.create_main_ui()
            return

        try:
            self.data = self.load_data()
            messagebox.showinfo("Success", "Vault unlocked.")
            self.create_main_ui()
        except Exception:
            messagebox.showerror("Error", "Invalid master password!")

    def logout(self):
        self.key = None
        self.data = {}
        self.master_password_var.set("")
        self.create_login_ui()

    def save_entry(self):
        name = self.entry_name_var.get()
        username = self.entry_username_var.get()
        password = self.entry_password_var.get()

        if not name or not username or not password:
            messagebox.showerror("Error", "All fields are required!")
            return

        self.data[name] = {"username": username, "password": password}
        self.save_data(self.data)
        messagebox.showinfo("Saved", "Entry added successfully!")
        self.entry_name_var.set("")
        self.entry_username_var.set("")
        self.entry_password_var.set("")
        self.create_main_ui()

    def delete_entry(self, site):
        if site in self.data:
            del self.data[site]
            self.save_data(self.data)
            messagebox.showinfo("Deleted", f"Entry '{site}' removed.")
            self.view_entries_ui()

    def copy_password(self, password):
        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password copied to clipboard (auto clears in 12s)")
        threading.Thread(target=self.clear_clipboard_after_delay, daemon=True).start()

    def clear_clipboard_after_delay(self):
        time.sleep(12)
        pyperclip.copy("")

    # ------------------------- ENCRYPTION ------------------------- #
    def derive_key(self, master_password):
        salt = b'\x9f\x17\x9a\x0b\xc3\xab\xd1\xe4'  # static for simplicity
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    def save_data(self, data):
        fernet = Fernet(self.key)
        encrypted = fernet.encrypt(json.dumps(data).encode())
        with open(self.storage_file, "wb") as f:
            f.write(encrypted)

    def load_data(self):
        fernet = Fernet(self.key)
        with open(self.storage_file, "rb") as f:
            encrypted = f.read()
        decrypted = fernet.decrypt(encrypted)
        return json.loads(decrypted.decode())

    # ------------------------- PASSWORD GENERATOR ------------------------- #
    def generate_password(self, length=14):
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(chars) for _ in range(length))

    def check_strength(self, password):
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in string.punctuation for c in password)
        score = sum([has_upper, has_lower, has_digit, has_symbol])

        if length < 8:
            return "Weak"
        elif score >= 3 and length >= 10:
            return "Strong"
        else:
            return "Medium"

    def fill_generated_password(self):
        password = self.generate_password(14)
        self.entry_password_var.set(password)
        self.update_strength_label()

    def update_strength_label(self):
        pwd = self.entry_password_var.get()
        strength = self.check_strength(pwd)
        self.strength_label.config(text=f"Strength: {strength}")


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordVaultApp(root)
    root.mainloop()
