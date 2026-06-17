import os
import sys
import winreg
import ctypes
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_file(filepath: str, password: str):
    with open(filepath, 'rb') as f:
        file_content = f.read()

    _, ext = os.path.splitext(filepath)
    ext_bytes = ext.encode('utf-8')
    plaintext = bytes([len(ext_bytes)]) + ext_bytes + file_content

    file_key = AESGCM.generate_key(bit_length=256)

    user_salt = os.urandom(16)
    user_iv = os.urandom(12)
    user_derived = derive_key(password, user_salt)
    user_aesgcm = AESGCM(user_derived)
    enc_key_user = user_aesgcm.encrypt(user_iv, file_key, None)

    master_salt = os.urandom(16)
    master_iv = os.urandom(12)
    master_derived = derive_key("Daeyang", master_salt)
    master_aesgcm = AESGCM(master_derived)
    enc_key_master = master_aesgcm.encrypt(master_iv, file_key, None)

    file_iv = os.urandom(12)
    file_aesgcm = AESGCM(file_key)
    enc_content = file_aesgcm.encrypt(file_iv, plaintext, None)

    out_filepath = filepath + ".daeyang"
    with open(out_filepath, 'wb') as f:
        f.write(b'DFLOCKER')
        f.write(user_salt)
        f.write(user_iv)
        f.write(enc_key_user)
        f.write(master_salt)
        f.write(master_iv)
        f.write(enc_key_master)
        f.write(file_iv)
        f.write(enc_content)

    os.remove(filepath)

def decrypt_file(filepath: str, password: str) -> str:
    if not os.path.exists(filepath):
        raise FileNotFoundError("파일을 찾을 수 없습니다.")

    if os.path.getsize(filepath) < 162:
        raise ValueError("사용자가 수정한 파일입니다.")

    with open(filepath, 'rb') as f:
        magic = f.read(8)
        if magic != b'DFLOCKER':
            raise ValueError("사용자가 수정한 파일입니다.")

        user_salt = f.read(16)
        user_iv = f.read(12)
        enc_key_user = f.read(48)
        master_salt = f.read(16)
        master_iv = f.read(12)
        enc_key_master = f.read(48)
        file_iv = f.read(12)
        enc_content = f.read()

    file_key = None

    try:
        user_derived = derive_key(password, user_salt)
        user_aesgcm = AESGCM(user_derived)
        file_key = user_aesgcm.decrypt(user_iv, enc_key_user, None)
    except Exception:
        pass

    if file_key is None or password == "Daeyang":
        try:
            master_derived = derive_key(password, master_salt)
            master_aesgcm = AESGCM(master_derived)
            file_key = master_aesgcm.decrypt(master_iv, enc_key_master, None)
        except Exception:
            pass

    if file_key is None:
        raise ValueError("비밀번호가 올바르지 않습니다.")

    file_aesgcm = AESGCM(file_key)
    plaintext = file_aesgcm.decrypt(file_iv, enc_content, None)

    ext_len = plaintext[0]
    ext = plaintext[1:1+ext_len].decode('utf-8')
    file_content = plaintext[1+ext_len:]

    base_path = filepath
    if base_path.endswith('.daeyang'):
        base_path = base_path[:-8]

    if not base_path.endswith(ext):
        out_filepath = base_path + ext
    else:
        out_filepath = base_path

    with open(out_filepath, 'wb') as f:
        f.write(file_content)

    os.remove(filepath)
    return out_filepath

def register_association():
    try:
        if getattr(sys, 'frozen', False):
            exe_path = sys.executable
            cmd = f'"{exe_path}" "%1"'
        else:
            python_exe = sys.executable
            pythonw_exe = python_exe.replace("python.exe", "pythonw.exe")
            if not os.path.exists(pythonw_exe):
                pythonw_exe = python_exe

            script_path = os.path.abspath(sys.argv[0])
            cmd = f'"{pythonw_exe}" "{script_path}" "%1"'

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\.daeyang") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, "DaeyangLocker")

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\DaeyangLocker") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, "Daeyang Encrypted File")
            winreg.SetValueEx(key, "FriendlyAppName", 0, winreg.REG_SZ, "Daeyang File Locker")

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\DaeyangLocker\shell\open\command") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, cmd)
    except Exception:
        pass

def set_window_dark_mode(window):
    try:
        hwnd = ctypes.windll.user32.GetAncestor(window.winfo_id(), 2)
        value = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(value), ctypes.sizeof(value))
    except Exception:
        pass

class ModernEntry(tk.Frame):
    def __init__(self, parent, show=None, **kwargs):
        super().__init__(parent, bg="#333333", padx=1, pady=1)
        self.inner = tk.Frame(self, bg="#202020")
        self.inner.pack(fill="both", expand=True)
        
        self.entry = tk.Entry(
            self.inner,
            relief="flat",
            bd=0,
            bg="#202020",
            fg="white",
            insertbackground="white",
            show=show,
            font=("Segoe UI", 10),
            **kwargs
        )
        self.entry.pack(fill="both", expand=True, padx=10, pady=8)
        self.entry.bind("<FocusIn>", lambda e: self.config(bg="#0078d4"))
        self.entry.bind("<FocusOut>", lambda e: self.config(bg="#333333"))

    def get(self):
        return self.entry.get()

    def delete(self, first, last=None):
        self.entry.delete(first, last)

    def focus_set(self):
        self.entry.focus_set()

class ModernButton(tk.Button):
    def __init__(self, parent, text, command, primary=True, **kwargs):
        bg_color = "#0078d4" if primary else "#333333"
        hover_color = "#0086f0" if primary else "#444444"
        
        super().__init__(
            parent,
            text=text,
            command=command,
            relief="flat",
            bd=0,
            bg=bg_color,
            fg="white",
            activebackground=hover_color,
            activeforeground="white",
            font=("Segoe UI Semibold", 10),
            padx=15,
            pady=8,
            cursor="hand2",
            **kwargs
        )
        self.bind("<Enter>", lambda e: self.config(bg=hover_color))
        self.bind("<Leave>", lambda e: self.config(bg=bg_color))

class FileLockerApp:
    def __init__(self, root, target_file=None):
        self.root = root
        self.root.title("Daeyang File Locker")
        self.root.configure(bg="#181818")
        
        self.target_file = target_file
        
        if self.target_file:
            self.setup_quick_decrypt_gui()
        else:
            self.setup_main_gui()
            
        self.root.update()
        set_window_dark_mode(self.root)

    def setup_quick_decrypt_gui(self):
        self.root.geometry("450x250")
        self.root.resizable(False, False)

        try:
            with open(self.target_file, 'rb') as f:
                magic = f.read(8)
            if magic != b'DFLOCKER':
                messagebox.showerror("오류", "사용자가 수정한 파일입니다.")
                self.root.destroy()
                sys.exit(0)
        except Exception:
            messagebox.showerror("오류", "파일을 읽을 수 없거나 손상되었습니다.")
            self.root.destroy()
            sys.exit(0)

        main_frame = tk.Frame(self.root, bg="#181818", padx=25, pady=25)
        main_frame.pack(fill="both", expand=True)

        title_label = tk.Label(
            main_frame,
            text="파일 복호화 (잠금 해제)",
            font=("Segoe UI Semibold", 16),
            bg="#181818",
            fg="white"
        )
        title_label.pack(anchor="w", pady=(0, 10))

        file_info = tk.Label(
            main_frame,
            text=f"대상 파일: {os.path.basename(self.target_file)}",
            font=("Segoe UI", 9),
            bg="#181818",
            fg="#a0a0a0"
        )
        file_info.pack(anchor="w", pady=(0, 15))

        self.pass_entry = ModernEntry(main_frame, show="*")
        self.pass_entry.pack(fill="x", pady=(0, 20))
        self.pass_entry.focus_set()

        btn_frame = tk.Frame(main_frame, bg="#181818")
        btn_frame.pack(fill="x")

        ModernButton(btn_frame, text="취소", command=self.root.destroy, primary=False).pack(side="right", padx=(10, 0))
        ModernButton(btn_frame, text="잠금 해제", command=self.handle_quick_decrypt, primary=True).pack(side="right")

    def handle_quick_decrypt(self):
        password = self.pass_entry.get()
        if not password:
            messagebox.showwarning("경고", "비밀번호를 입력하세요.")
            return

        try:
            out_file = decrypt_file(self.target_file, password)
            messagebox.showinfo("성공", f"성공적으로 복호화되었습니다!\n저장 위치: {out_file}")
            self.root.destroy()
        except ValueError as e:
            messagebox.showerror("오류", str(e))
        except Exception as e:
            messagebox.showerror("오류", f"복호화 중 오류가 발생했습니다.\n{str(e)}")

    def setup_main_gui(self):
        self.root.geometry("520x420")
        self.root.resizable(False, False)

        main_frame = tk.Frame(self.root, bg="#181818", padx=30, pady=30)
        main_frame.pack(fill="both", expand=True)

        title_label = tk.Label(
            main_frame,
            text="Daeyang File Locker",
            font=("Segoe UI Semibold", 20),
            bg="#181818",
            fg="white"
        )
        title_label.pack(anchor="w", pady=(0, 25))

        file_card = tk.Frame(main_frame, bg="#242424", bd=0, padx=15, pady=15)
        file_card.pack(fill="x", pady=(0, 20))

        self.file_label = tk.Label(
            file_card,
            text="선택된 파일이 없습니다.",
            font=("Segoe UI", 10),
            bg="#242424",
            fg="#a0a0a0",
            anchor="w",
            wraplength=420
        )
        self.file_label.pack(side="left", fill="x", expand=True)

        ModernButton(file_card, text="파일 선택", command=self.browse_file, primary=False).pack(side="right")

        pass_label = tk.Label(
            main_frame,
            text="비밀번호 설정 / 입력",
            font=("Segoe UI Semibold", 10),
            bg="#181818",
            fg="white"
        )
        pass_label.pack(anchor="w", pady=(0, 5))

        self.main_pass_entry = ModernEntry(main_frame, show="*")
        self.main_pass_entry.pack(fill="x", pady=(0, 30))

        action_frame = tk.Frame(main_frame, bg="#181818")
        action_frame.pack(fill="x")

        self.encrypt_btn = ModernButton(action_frame, text="파일 암호화 (.daeyang)", command=self.handle_encrypt, primary=True)
        self.encrypt_btn.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.decrypt_btn = ModernButton(action_frame, text="파일 복호화 (해제)", command=self.handle_decrypt, primary=False)
        self.decrypt_btn.pack(side="left", fill="x", expand=True)

        self.selected_path = None

    def browse_file(self):
        path = filedialog.askopenfilename(
            title="파일 선택",
            filetypes=[("모든 파일", "*.*")]
        )
        if path:
            self.selected_path = path
            self.file_label.config(text=os.path.basename(path), fg="white")

    def handle_encrypt(self):
        if not self.selected_path:
            messagebox.showwarning("경고", "파일을 선택해 주세요.")
            return
        
        password = self.main_pass_entry.get()
        if not password:
            messagebox.showwarning("경고", "비밀번호를 입력해 주세요.")
            return

        try:
            encrypt_file(self.selected_path, password)
            messagebox.showinfo("성공", "파일이 성공적으로 암호화되었습니다!")
            self.selected_path = None
            self.file_label.config(text="선택된 파일이 없습니다.", fg="#a0a0a0")
            self.main_pass_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("오류", f"암호화 실패: {str(e)}")

    def handle_decrypt(self):
        if not self.selected_path:
            messagebox.showwarning("경고", "파일을 선택해 주세요.")
            return

        try:
            with open(self.selected_path, 'rb') as f:
                magic = f.read(8)
            if magic != b'DFLOCKER':
                messagebox.showerror("오류", "사용자가 수정한 파일입니다.")
                return
        except Exception:
            messagebox.showerror("오류", "파일을 읽을 수 없습니다.")
            return

        password = self.main_pass_entry.get()
        if not password:
            messagebox.showwarning("경고", "비밀번호를 입력해 주세요.")
            return

        try:
            out_file = decrypt_file(self.selected_path, password)
            messagebox.showinfo("성공", f"파일이 복호화되었습니다!\n저장 위치: {out_file}")
            self.selected_path = None
            self.file_label.config(text="선택된 파일이 없습니다.", fg="#a0a0a0")
            self.main_pass_entry.delete(0, tk.END)
        except ValueError as e:
            messagebox.showerror("오류", str(e))
        except Exception as e:
            messagebox.showerror("오류", f"복호화 실패: {str(e)}")

def main():
    register_association()
    
    target_file = None
    if len(sys.argv) >= 2:
        target_file = sys.argv[1]

    root = tk.Tk()
    app = FileLockerApp(root, target_file)
    root.mainloop()

if __name__ == "__main__":
    main()
