import base64
import hashlib
import os
import tkinter as tk
from tkinter import TclError, messagebox, simpledialog

PASSWORD_FILE = "password.dat"
DATA_FILE = "sfr.txt"


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def encrypt_method_1(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii")


def decrypt_method_1(data: str) -> str:
    return base64.urlsafe_b64decode(data.encode("ascii")).decode("utf-8")


def encrypt_method_2(text: str) -> str:
    key = b"S3cUrE"
    text_bytes = text.encode("utf-8")
    xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(text_bytes))
    return xored.hex()


def decrypt_method_2(data: str) -> str:
    key = b"S3cUrE"
    raw = bytes.fromhex(data) if data else b""
    decoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return decoded.decode("utf-8")


def encrypt_method_3(text: str) -> str:
    shift = 4
    result = []
    for ch in text:
        if 32 <= ord(ch) <= 126:
            shifted = (ord(ch) - 32 + shift) % 95 + 32
            result.append(chr(shifted))
        else:
            result.append(ch)
    return "".join(result)


def decrypt_method_3(data: str) -> str:
    shift = 4
    result = []
    for ch in data:
        if 32 <= ord(ch) <= 126:
            shifted = (ord(ch) - 32 - shift) % 95 + 32
            result.append(chr(shifted))
        else:
            result.append(ch)
    return "".join(result)


ENCRYPTION_METHODS = {
    1: (encrypt_method_1, decrypt_method_1, "Base64"),
    2: (encrypt_method_2, decrypt_method_2, "XOR Hex"),
    3: (encrypt_method_3, decrypt_method_3, "Caesar Shift"),
}


class PasswordKeeperApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure Password Keeper")
        self.method_var = tk.IntVar(value=1)

        self._build_ui()
        self._load_data()

    def _build_ui(self) -> None:
        frame = tk.Frame(self.root)
        frame.pack(fill=tk.BOTH, expand=True)

        method_frame = tk.Frame(frame)
        method_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(method_frame, text="Encryption method:").pack(side=tk.LEFT)

        for method_id, (_, _, name) in ENCRYPTION_METHODS.items():
            tk.Radiobutton(
                method_frame,
                text=f"{method_id} - {name}",
                variable=self.method_var,
                value=method_id,
            ).pack(side=tk.LEFT, padx=5)

        text_frame = tk.Frame(frame)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self.text_widget = tk.Text(text_frame, wrap=tk.NONE, undo=True)
        self.text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar_y = tk.Scrollbar(text_frame, command=self.text_widget.yview)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_widget.configure(yscrollcommand=scrollbar_y.set)

        scrollbar_x = tk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.text_widget.xview)
        scrollbar_x.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.text_widget.configure(xscrollcommand=scrollbar_x.set)

        button_frame = tk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        save_button = tk.Button(button_frame, text="Save", command=self.save_data)
        save_button.pack(side=tk.LEFT)

        change_password_button = tk.Button(
            button_frame, text="Change Password", command=self.change_password
        )
        change_password_button.pack(side=tk.LEFT, padx=5)

    def _load_data(self) -> None:
        if not os.path.exists(DATA_FILE):
            return

        decrypted_lines = []
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.rstrip("\n")
                if not line:
                    decrypted_lines.append("")
                    continue
                method_digit = line[0]
                if not method_digit.isdigit():
                    decrypted_lines.append(line)
                    continue
                method = int(method_digit)
                encrypted_segment = line[1:]
                method_info = ENCRYPTION_METHODS.get(method)
                if not method_info:
                    decrypted_lines.append(encrypted_segment)
                    continue
                decrypt_func = method_info[1]
                try:
                    decrypted_lines.append(decrypt_func(encrypted_segment))
                except Exception:
                    decrypted_lines.append(f"<Error decrypting with method {method}>")
        self.text_widget.delete("1.0", tk.END)
        self.text_widget.insert(tk.END, "\n".join(decrypted_lines))

    def save_data(self) -> None:
        content = self.text_widget.get("1.0", tk.END).rstrip("\n")
        lines = content.split("\n") if content else []
        method = self.method_var.get()
        encrypt_func = ENCRYPTION_METHODS[method][0]

        with open(DATA_FILE, "w", encoding="utf-8") as f:
            for line in lines:
                encrypted = encrypt_func(line)
                f.write(f"{method}{encrypted}\n")
        messagebox.showinfo("Saved", "Entries saved securely.")

    def change_password(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Change Password")
        dialog.resizable(False, False)
        dialog.grab_set()

        tk.Label(dialog, text="Current password:").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        current_entry = tk.Entry(dialog, show="*")
        current_entry.grid(row=0, column=1, pady=5, padx=5)

        tk.Label(dialog, text="New password (4 digits):").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
        new_entry = tk.Entry(dialog, show="*")
        new_entry.grid(row=1, column=1, pady=5, padx=5)

        tk.Label(dialog, text="Confirm new password:").grid(row=2, column=0, sticky=tk.W, pady=5, padx=5)
        confirm_entry = tk.Entry(dialog, show="*")
        confirm_entry.grid(row=2, column=1, pady=5, padx=5)

        def submit_change() -> None:
            current = current_entry.get()
            new_password = new_entry.get()
            confirm = confirm_entry.get()

            if not verify_password(current):
                messagebox.showerror("Error", "Current password is incorrect.")
                return

            if not (new_password.isdigit() and len(new_password) == 4):
                messagebox.showerror("Error", "New password must be a 4-digit number.")
                return

            if new_password != confirm:
                messagebox.showerror("Error", "New password and confirmation do not match.")
                return

            store_password_hash(new_password)
            messagebox.showinfo("Success", "Password updated successfully.")
            dialog.destroy()

        tk.Button(dialog, text="Update", command=submit_change).grid(row=3, column=0, columnspan=2, pady=10)

        dialog.bind("<Return>", lambda event: submit_change())
        current_entry.focus_set()


def store_password_hash(password: str) -> None:
    with open(PASSWORD_FILE, "w", encoding="utf-8") as f:
        f.write(hash_password(password))


def verify_password(password: str) -> bool:
    if not os.path.exists(PASSWORD_FILE):
        return False
    with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
        stored_hash = f.read().strip()
    return hash_password(password) == stored_hash


def ensure_password() -> bool:
    if not os.path.exists(PASSWORD_FILE):
        while True:
            new_password = simpledialog.askstring(
                "Set Password", "Create a 4-digit password:", show="*"
            )
            if new_password is None:
                return False
            if new_password.isdigit() and len(new_password) == 4:
                store_password_hash(new_password)
                messagebox.showinfo("Password Set", "Password created successfully.")
                break
            messagebox.showerror("Invalid", "Password must be exactly 4 digits.")

    attempts = 3
    while attempts > 0:
        password = simpledialog.askstring("Password Required", "Enter 4-digit password:", show="*")
        if password is None:
            return False
        if verify_password(password):
            return True
        attempts -= 1
        messagebox.showerror("Error", f"Incorrect password. {attempts} attempts remaining.")
    return False


def main() -> None:

    try:
        root = tk.Tk()
    except TclError as exc:
        print("Unable to start the Tkinter interface:", exc)
        print(
            "This application requires a graphical display."
            " Ensure $DISPLAY is set when running in a headless environment."
        )
        return
    root.withdraw()

    if not ensure_password():
        root.destroy()
        return

    root.deiconify()
    app = PasswordKeeperApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
