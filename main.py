from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import os
import re
import uuid
import shutil
from datetime import datetime

APP_TITLE = "Terminal SSH Profile Creator"
SCHEMA_URL = "https://aka.ms/terminal-profiles-schema"

MS_STORE = Path(os.path.expandvars(r"%LOCALAPPDATA%\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"))
MS_STORE_PREVIEW = Path(os.path.expandvars(r"%LOCALAPPDATA%\Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json"))
UNPACKAGED = Path(os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows Terminal\settings.json"))

def detect_settings_paths():
    paths = []
    for p in [MS_STORE, MS_STORE_PREVIEW, UNPACKAGED]:
        try:
            if p.exists():
                paths.append(p)
        except Exception:
            pass
    if not paths:
        paths = [UNPACKAGED]
    return paths

def strip_json_comments(s: str) -> str:
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    s = re.sub(r"(^|\s)//.*?$", r"\1", s, flags=re.M)
    s = re.sub(r",(\s*[}\]])", r"\1", s)
    return s

def load_settings(path: Path) -> dict:
    if not path.exists():
        return {
            "$schema": SCHEMA_URL,
            "profiles": {"list": []},
            "schemes": []
        }
    raw = path.read_text(encoding="utf-8", errors="ignore")
    cleaned = strip_json_comments(raw)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise ValueError(f"Không thể parse settings.json tại {path}.\nLỗi JSON: {e}")
    if "profiles" not in data or not isinstance(data["profiles"], dict):
        data["profiles"] = {"list": []}
    if "list" not in data["profiles"] or not isinstance(data["profiles"]["list"], list):
        data["profiles"]["list"] = []
    return data

def save_settings(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = path.with_suffix(f".backup-{ts}.json")
        shutil.copy2(path, backup)
    text = json.dumps(data, indent=2, ensure_ascii=False)
    path.write_text(text, encoding="utf-8")

def build_commandline(user, host, port, auth_method, key_path, extra_opts):
    base = f"ssh {user}@{host}" if user else f"ssh {host}"
    if port and str(port).strip():
        base += f" -p {port}"
    if auth_method == "key" and key_path:
        base += f' -i "{key_path}"'
    if extra_opts and extra_opts.strip():
        base += " " + extra_opts.strip()
    return base

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("760x560")
        self.resizable(True, True)

        self.selected_path = tk.StringVar()
        self.profile_name = tk.StringVar()
        self.username = tk.StringVar()
        self.host = tk.StringVar()
        self.port = tk.StringVar(value="22")
        self.auth_method = tk.StringVar(value="key")  # key | agent | password
        self.key_path = tk.StringVar()
        self.icon_path = tk.StringVar()
        self.start_dir = tk.StringVar()
        self.tab_title = tk.StringVar()
        self.extra_opts = tk.StringVar(value='-o ServerAliveInterval=30 -o ServerAliveCountMax=3')
        self.close_on_exit = tk.BooleanVar(value=True)

        self._build_ui()
        self._populate_settings_paths()

    def _build_ui(self):
        pad = {"padx": 10, "pady": 6}

        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True)

        row0 = ttk.LabelFrame(frm, text="Chọn settings.json của Windows Terminal")
        row0.pack(fill="x", **pad)

        ttk.Label(row0, text="Đường dẫn:").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        self.cmb_paths = ttk.Combobox(row0, textvariable=self.selected_path, state="readonly", width=95)
        self.cmb_paths.grid(row=0, column=1, sticky="we", padx=6, pady=6)
        row0.grid_columnconfigure(1, weight=1)
        ttk.Button(row0, text="Duyệt...", command=self.browse_settings).grid(row=0, column=2, padx=6, pady=6)

        row1 = ttk.LabelFrame(frm, text="Thông tin SSH")
        row1.pack(fill="x", **pad)

        ttk.Label(row1, text="Tên profile *").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        ttk.Entry(row1, textvariable=self.profile_name, width=30).grid(row=0, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(row1, text="Host/IP *").grid(row=1, column=0, sticky="w", padx=6, pady=6)
        ttk.Entry(row1, textvariable=self.host, width=30).grid(row=1, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(row1, text="User").grid(row=2, column=0, sticky="w", padx=6, pady=6)
        ttk.Entry(row1, textvariable=self.username, width=30).grid(row=2, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(row1, text="Port").grid(row=3, column=0, sticky="w", padx=6, pady=6)
        ttk.Entry(row1, textvariable=self.port, width=10).grid(row=3, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(row1, text="Xác thực").grid(row=0, column=2, sticky="w", padx=6, pady=6)
        auth_frame = ttk.Frame(row1)
        auth_frame.grid(row=0, column=3, rowspan=2, sticky="w", padx=6, pady=6)
        ttk.Radiobutton(auth_frame, text="Key file", value="key", variable=self.auth_method, command=self._toggle_auth_widgets).pack(side="left", padx=6)
        ttk.Radiobutton(auth_frame, text="Agent/Credential", value="agent", variable=self.auth_method, command=self._toggle_auth_widgets).pack(side="left", padx=6)
        ttk.Radiobutton(auth_frame, text="Password (prompt)", value="password", variable=self.auth_method, command=self._toggle_auth_widgets).pack(side="left", padx=6)

        ttk.Label(row1, text="Key path").grid(row=2, column=2, sticky="w", padx=6, pady=6)
        key_row = ttk.Frame(row1)
        key_row.grid(row=2, column=3, sticky="we", padx=6, pady=6)
        self.ent_key = ttk.Entry(key_row, textvariable=self.key_path, width=46)
        self.ent_key.pack(side="left", fill="x", expand=True)
        ttk.Button(key_row, text="Chọn...", command=self.browse_key).pack(side="left", padx=6)

        ttk.Label(row1, text="Extra ssh options").grid(row=3, column=2, sticky="w", padx=6, pady=6)
        ttk.Entry(row1, textvariable=self.extra_opts, width=50).grid(row=3, column=3, sticky="we", padx=6, pady=6)

        row2 = ttk.LabelFrame(frm, text="Tuỳ chọn hiển thị (tuỳ chọn)")
        row2.pack(fill="x", **pad)

        ttk.Label(row2, text="Tab title").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        ttk.Entry(row2, textvariable=self.tab_title, width=30).grid(row=0, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(row2, text="Icon path (.ico/.png)").grid(row=1, column=0, sticky="w", padx=6, pady=6)
        icon_row = ttk.Frame(row2)
        icon_row.grid(row=1, column=1, sticky="we", padx=6, pady=6)
        ttk.Entry(icon_row, textvariable=self.icon_path, width=46).pack(side="left", fill="x", expand=True)
        ttk.Button(icon_row, text="Chọn...", command=self.browse_icon).pack(side="left", padx=6)

        ttk.Label(row2, text="Starting directory").grid(row=2, column=0, sticky="w", padx=6, pady=6)
        start_row = ttk.Frame(row2)
        start_row.grid(row=2, column=1, sticky="we", padx=6, pady=6)
        ttk.Entry(start_row, textvariable=self.start_dir, width=46).pack(side="left", fill="x", expand=True)
        ttk.Button(start_row, text="Chọn...", command=self.browse_start_dir).pack(side="left", padx=6)

        ttk.Checkbutton(row2, text="Đóng tab sau khi thoát (closeOnExit)", variable=self.close_on_exit).grid(row=3, column=0, sticky="w", padx=6, pady=6)

        row3 = ttk.Frame(frm)
        row3.pack(fill="x", **pad)
        ttk.Button(row3, text="Xem lệnh ssh", command=self.preview_command).pack(side="left", padx=6)
        ttk.Button(row3, text="Tạo profile", command=self.create_profile).pack(side="right", padx=6)
        ttk.Button(row3, text="Thoát", command=self.destroy).pack(side="right", padx=6)

        note = (
            "Lưu ý bảo mật: Không nên lưu mật khẩu vào profile. Với 'Password', Windows OpenSSH sẽ hỏi khi kết nối.\n"
            "Khuyên dùng key file hoặc agent (Pageant/ssh-agent) để đăng nhập an toàn."
        )
        ttk.Label(frm, text=note, foreground="#666").pack(fill="x", padx=12, pady=(0,10))

        for r in (row1, row2):
            for c in range(4):
                r.grid_columnconfigure(c, weight=1)
        self._toggle_auth_widgets()

    def _populate_settings_paths(self):
        paths = detect_settings_paths()
        self.cmb_paths["values"] = [str(p) for p in paths]
        if paths:
            self.cmb_paths.current(0)

    def browse_settings(self):
        fp = filedialog.askopenfilename(
            title="Chọn settings.json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir=str(Path.home())
        )
        if fp:
            self.selected_path.set(fp)

    def browse_key(self):
        fp = filedialog.askopenfilename(
            title="Chọn private key (id_rsa / id_ed25519)",
            filetypes=[("Key files", "*.*")]
        )
        if fp:
            self.key_path.set(fp)

    def browse_icon(self):
        fp = filedialog.askopenfilename(
            title="Chọn icon",
            filetypes=[("Images", "*.ico;*.png;*.jpg;*.jpeg;*.bmp"), ("All files", "*.*")]
        )
        if fp:
            self.icon_path.set(fp)

    def browse_start_dir(self):
        d = filedialog.askdirectory(title="Chọn thư mục bắt đầu")
        if d:
            self.start_dir.set(d)

    def _toggle_auth_widgets(self):
        method = self.auth_method.get()
        state = "normal" if method == "key" else "disabled"
        try:
            self.ent_key.configure(state=state)
        except Exception:
            pass

    def preview_command(self):
        cmd = build_commandline(
            self.username.get().strip(),
            self.host.get().strip(),
            self.port.get().strip(),
            self.auth_method.get(),
            self.key_path.get().strip(),
            self.extra_opts.get().strip()
        )
        messagebox.showinfo("SSH command", cmd)

    def _validate(self):
        if not self.profile_name.get().strip():
            return "Vui lòng nhập Tên profile."
        if not self.host.get().strip():
            return "Vui lòng nhập Host/IP."
        if self.auth_method.get() == "key" and not self.key_path.get().strip():
            return "Vui lòng chọn Key path hoặc đổi sang Agent/Password."
        if not self.selected_path.get().strip():
            return "Vui lòng chọn đường dẫn settings.json."
        return None

    def create_profile(self):
        err = self._validate()
        if err:
            messagebox.showerror("Thiếu thông tin", err)
            return

        settings_path = Path(self.selected_path.get())
        try:
            data = load_settings(settings_path)
        except Exception as e:
            messagebox.showerror("Lỗi đọc settings.json", str(e))
            return

        profiles = data.get("profiles", {}).get("list", [])

        name = self.profile_name.get().strip()
        for p in profiles:
            if isinstance(p, dict) and p.get("name") == name:
                ok = messagebox.askyesno(
                    "Profile trùng tên",
                    "Đã có profile cùng tên. Bạn có muốn tạo thêm một profile khác (sẽ có tên trùng) không?"
                )
                if not ok:
                    return
                break

        guid = "{" + str(uuid.uuid4()) + "}"
        cmd = build_commandline(
            self.username.get().strip(),
            self.host.get().strip(),
            self.port.get().strip(),
            self.auth_method.get(),
            self.key_path.get().strip(),
            self.extra_opts.get().strip()
        )

        profile = {
            "guid": guid,
            "name": name,
            "commandline": cmd,
            "hidden": False
        }
        if self.tab_title.get().strip():
            profile["tabTitle"] = self.tab_title.get().strip()
        if self.icon_path.get().strip():
            profile["icon"] = self.icon_path.get().strip()
        if self.start_dir.get().strip():
            profile["startingDirectory"] = self.start_dir.get().strip()
        profile["closeOnExit"] = "always" if self.close_on_exit.get() else "graceful"

        if "$schema" not in data:
            data["$schema"] = SCHEMA_URL

        data["profiles"]["list"].append(profile)
        try:
            save_settings(settings_path, data)
        except Exception as e:
            messagebox.showerror("Lỗi ghi settings.json", str(e))
            return

        messagebox.showinfo(
            "Thành công",
            f"Đã thêm profile:\n\n- Tên: {name}\n- GUID: {guid}\n\nBạn có thể mở Windows Terminal và dùng profile này ngay."
        )

if __name__ == "__main__":
    app = App()
    app.mainloop()
