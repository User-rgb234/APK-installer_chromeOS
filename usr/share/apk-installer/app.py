import os
import json
import glob
import time
import subprocess
import threading
from dataclasses import dataclass
from tkinter import *
from tkinter import ttk, filedialog, messagebox, simpledialog

APP_NAME = "apk-installer"

DEFAULTS = {
    # APK install tab
    "chromeos_mode": True,
    "chromeos_target": "100.115.92.2:5555",
    "install_flags": "-r",
    "advanced_mode": False,
    "custom_connect": "adb connect {target}",
    "custom_install": "adb -s {serial} install {flags} \"{apk}\"",

    # Quick Update tab
    "apk_folder": "",
    "countdown_seconds": 3,
    "recent_minutes": 10,
    "require_hint": False,      # safer if True
    "fallback_to_newest": True, # if hint doesn't match, use newest anyway
    "instances": []             # list of dicts: {name,url,hint}
}

HELP_TEXT = """APK Installer – Quick Help

1) First-time setup
- Install ADB (APK Install tab)
- Connect a device:
  • ChromeOS mode: ADB Connect (100.115.92.2:5555)
  • Phone/tablet: enable Developer Options -> USB/Wireless debugging -> connect

2) APK Install tab
- Pick device from dropdown
- Choose APK -> Install APK

3) Quick Update tab
- Choose an APK folder (use a folder ONLY for APK downloads)
- Add Instance (Name + URL + optional Hint)
- Click Open Page to download the APK
- Click Update to install the newest matching APK from that folder

Hint tips
- Use short hint like: wha, whatsapp, discord, etc.
- If Require Hint is enabled, Update will only install APKs matching the hint.

Safety
- This app installs APKs you download. Use trusted sources.
- Delete downloaded APKs removes ONLY *.apk inside the selected folder.

Common errors
- Unauthorized: approve the USB debugging popup on device
- More than one device/emulator: pick the correct device in the dropdown
"""

def config_path():
    home = os.path.expanduser("~")
    return os.path.join(home, ".config", APP_NAME, "settings.json")

def load_cfg():
    path = config_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cfg = DEFAULTS.copy()
        # Merge known keys only
        for k in DEFAULTS:
            if k in data:
                cfg[k] = data[k]
        # ensure list
        if not isinstance(cfg.get("instances"), list):
            cfg["instances"] = []
        return cfg
    except Exception:
        return DEFAULTS.copy()

def save_cfg(cfg):
    path = config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

def adb_devices():
    try:
        out = subprocess.check_output(["adb", "devices"], text=True, stderr=subprocess.STDOUT)
    except Exception:
        return []
    devices = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices

def safe_run(cmd_list, log_widget):
    log_widget.insert(END, "\n$ " + " ".join(cmd_list) + "\n")
    log_widget.see(END)
    try:
        p = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in p.stdout:
            log_widget.insert(END, line)
            log_widget.see(END)
        p.wait()
        return p.returncode
    except FileNotFoundError:
        log_widget.insert(END, "Error: command not found. Is adb installed?\n")
        log_widget.see(END)
        return 127

def build_cmd_from_template(template, target, serial, flags, apk):
    t = template.strip()
    if not (t.startswith("adb ") or t.startswith("adb\t") or t == "adb"):
        raise ValueError("For safety, custom commands must start with: adb ...")
    t = t.replace("{target}", target).replace("{serial}", serial).replace("{flags}", flags).replace("{apk}", apk)
    return ["bash", "-lc", t]

@dataclass
class InstanceItem:
    name: str
    url: str
    hint: str = ""

def now_mtime(path):
    try:
        return os.path.getmtime(path)
    except Exception:
        return 0

def find_best_apk(folder, hint, recent_minutes, require_hint, fallback_to_newest):
    """
    Returns (apk_path, reason_string) or (None, reason_string).
    - Scans for *.apk in folder
    - Only consider recently modified within recent_minutes (if >0)
    - If hint provided, prefer those containing hint (case-insensitive)
    """
    if not folder or not os.path.isdir(folder):
        return None, "APK folder is not set or not a folder."

    apks = glob.glob(os.path.join(folder, "*.apk"))
    if not apks:
        return None, "No .apk files found in the folder."

    # recent filter
    if recent_minutes and recent_minutes > 0:
        cutoff = time.time() - (recent_minutes * 60)
        apks_recent = [p for p in apks if now_mtime(p) >= cutoff]
        if apks_recent:
            apks = apks_recent
        else:
            # none recent; still allow if user wants
            pass

    apks_sorted = sorted(apks, key=now_mtime, reverse=True)
    hint = (hint or "").strip()
    if hint:
        h = hint.lower()
        matches = [p for p in apks_sorted if h in os.path.basename(p).lower()]
        if matches:
            return matches[0], f"Matched hint '{hint}'."
        if require_hint:
            return None, f"No APK filename matched hint '{hint}'."
        if fallback_to_newest and apks_sorted:
            return apks_sorted[0], f"No hint match; using newest APK."
        return None, "No APK selected."
    else:
        # No hint, just newest
        return apks_sorted[0], "Using newest APK."

class APKInstallerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("APK Installer (ChromeOS + Android via ADB)")
        self.root.geometry("900x560")

        self.cfg = load_cfg()

        self.nb = ttk.Notebook(root)
        self.nb.pack(fill=BOTH, expand=True)

        self.tab_install = Frame(self.nb)
        self.tab_quick = Frame(self.nb)
        self.tab_toolbox = Frame(self.nb)
        self.tab_log = Frame(self.nb)
        self.tab_settings = Frame(self.nb)

        self.nb.add(self.tab_install, text="APK Install")
        self.nb.add(self.tab_quick, text="Quick Update")
        self.nb.add(self.tab_toolbox, text="ADB Toolbox")
        self.nb.add(self.tab_log, text="Terminal / Logs")
        self.nb.add(self.tab_settings, text="Settings")

        # Logs
        self.log = Text(self.tab_log, wrap="word")
        self.log.pack(fill=BOTH, expand=True)
        self.log.insert(END, "Logs will appear here.\n")

        # Shared top bar with Help
        self._add_help_buttons()

        # Vars
        self.chromeos_mode = BooleanVar(value=bool(self.cfg["chromeos_mode"]))
        self.target_var = StringVar(value=self.cfg["chromeos_target"])
        self.flags_var = StringVar(value=self.cfg["install_flags"])
        self.advanced_mode = BooleanVar(value=bool(self.cfg["advanced_mode"]))
        self.custom_connect_var = StringVar(value=self.cfg["custom_connect"])
        self.custom_install_var = StringVar(value=self.cfg["custom_install"])

        # Device chooser (shared)
        self.device_var = StringVar(value="")
        self.device_values = []

        # Quick Update vars
        self.apk_folder_var = StringVar(value=self.cfg.get("apk_folder", ""))
        self.countdown_var = IntVar(value=int(self.cfg.get("countdown_seconds", 3)))
        self.recent_minutes_var = IntVar(value=int(self.cfg.get("recent_minutes", 10)))
        self.require_hint_var = BooleanVar(value=bool(self.cfg.get("require_hint", False)))
        self.fallback_var = BooleanVar(value=bool(self.cfg.get("fallback_to_newest", True)))

        self.instances = self._load_instances()

        # Build tabs
        self._build_install_tab()
        self._build_quick_tab()
        self._build_toolbox_tab()
        self._build_settings_tab()

        # initial
        self.refresh_devices()

        # countdown state
        self._countdown_cancel = False
        self._countdown_thread = None

    def _add_help_buttons(self):
        # Add a help button to each main tab top area for convenience
        for tab in [self.tab_install, self.tab_quick, self.tab_toolbox, self.tab_settings]:
            bar = Frame(tab)
            bar.pack(fill=X, padx=10, pady=(8, 0))
            Button(bar, text="Help", command=self.show_help).pack(side=RIGHT)

    def show_help(self):
        win = Toplevel(self.root)
        win.title("Help / Tutorial")
        win.geometry("700x460")
        txt = Text(win, wrap="word")
        txt.pack(fill=BOTH, expand=True)
        txt.insert(END, HELP_TEXT)
        txt.configure(state="disabled")
        Button(win, text="Close", command=win.destroy).pack(pady=6)

    def log_info(self, msg):
        self.log.insert(END, msg + "\n")
        self.log.see(END)

    def thread_cmd(self, cmd_list):
        def work():
            code = safe_run(cmd_list, self.log)
            if code != 0:
                self.log_info(f"(exit code {code})")
        threading.Thread(target=work, daemon=True).start()
        self.nb.select(self.tab_log)

    def _load_instances(self):
        out = []
        for it in self.cfg.get("instances", []):
            try:
                out.append(InstanceItem(
                    name=str(it.get("name", "")).strip() or "Untitled",
                    url=str(it.get("url", "")).strip(),
                    hint=str(it.get("hint", "")).strip()
                ))
            except Exception:
                pass
        return out

    def _save_all_settings(self):
        # Save core settings
        self.cfg["chromeos_mode"] = bool(self.chromeos_mode.get())
        self.cfg["chromeos_target"] = self.target_var.get().strip() or DEFAULTS["chromeos_target"]
        self.cfg["install_flags"] = self.flags_var.get().strip()
        self.cfg["advanced_mode"] = bool(self.advanced_mode.get())
        self.cfg["custom_connect"] = self.custom_connect_var.get().strip() or DEFAULTS["custom_connect"]
        self.cfg["custom_install"] = self.custom_install_var.get().strip() or DEFAULTS["custom_install"]

        # Quick Update settings
        self.cfg["apk_folder"] = self.apk_folder_var.get().strip()
        self.cfg["countdown_seconds"] = int(self.countdown_var.get())
        self.cfg["recent_minutes"] = int(self.recent_minutes_var.get())
        self.cfg["require_hint"] = bool(self.require_hint_var.get())
        self.cfg["fallback_to_newest"] = bool(self.fallback_var.get())

        # Instances
        self.cfg["instances"] = [{"name": i.name, "url": i.url, "hint": i.hint} for i in self.instances]

        save_cfg(self.cfg)

    # -------------------- APK INSTALL TAB --------------------
    def _build_install_tab(self):
        area = Frame(self.tab_install)
        area.pack(fill=BOTH, expand=True, padx=12, pady=10)

        Checkbutton(
            area,
            text="ChromeOS mode (prefer ChromeOS ADB target)",
            variable=self.chromeos_mode,
            command=self.refresh_devices
        ).pack(anchor="w")

        row = Frame(area)
        row.pack(fill=X, pady=(8, 2))

        Button(row, text="Install ADB (recommended)", command=self.install_adb).pack(side=LEFT, padx=(0, 8))
        Button(row, text="ADB Connect (ChromeOS)", command=self.adb_connect).pack(side=LEFT, padx=(0, 8))
        Button(row, text="Refresh Devices", command=self.refresh_devices).pack(side=LEFT)

        devrow = Frame(area)
        devrow.pack(fill=X, pady=(10, 2))
        Label(devrow, text="Device:").pack(side=LEFT)
        self.device_menu = ttk.Combobox(devrow, textvariable=self.device_var, state="readonly", width=46, values=[])
        self.device_menu.pack(side=LEFT, padx=8)

        pick = Frame(area)
        pick.pack(fill=X, pady=(10, 2))
        self.apk_path = StringVar(value="")
        Button(pick, text="Choose APK", command=self.choose_apk).pack(side=LEFT)
        Label(pick, textvariable=self.apk_path, anchor="w").pack(side=LEFT, padx=10, fill=X, expand=True)

        Button(area, text="Install APK", height=2, command=self.install_apk).pack(anchor="w", pady=10)
        Label(area, text="Tip: Logs tab shows exact ADB output and errors.").pack(anchor="w")

    def install_adb(self):
        self.thread_cmd(["bash", "-lc", "sudo apt update && sudo apt install -y adb"])

    def adb_connect(self):
        target = self.target_var.get().strip() or DEFAULTS["chromeos_target"]
        if self.advanced_mode.get():
            try:
                cmd = build_cmd_from_template(self.custom_connect_var.get(), target, "", "", "")
            except ValueError as e:
                messagebox.showerror("Settings error", str(e))
                return
            self.thread_cmd(cmd)
        else:
            self.thread_cmd(["adb", "connect", target])

        self.root.after(1500, self.refresh_devices)

    def refresh_devices(self):
        devices = adb_devices()
        target = self.target_var.get().strip() or DEFAULTS["chromeos_target"]

        preferred = ""
        if self.chromeos_mode.get() and target in devices:
            preferred = target
        elif devices:
            preferred = devices[0]

        self.device_values = devices
        self.device_menu["values"] = devices
        self.device_var.set(preferred)

        self.log_info("# Detected devices: " + (", ".join(devices) if devices else "none"))

    def choose_apk(self):
        path = filedialog.askopenfilename(filetypes=[("APK files", "*.apk")])
        if path:
            self.apk_path.set(path)

    def install_apk(self):
        apk = self.apk_path.get().strip()
        if not apk.lower().endswith(".apk"):
            messagebox.showerror("Pick an APK", "Please choose a .apk file first.")
            return

        serial = self.device_var.get().strip()
        if not serial:
            messagebox.showerror("No device", "No ADB device found.\nTry ADB Connect or plug in a device.")
            return

        flags = self.flags_var.get().strip()
        target = self.target_var.get().strip() or DEFAULTS["chromeos_target"]

        if self.advanced_mode.get():
            try:
                cmd = build_cmd_from_template(self.custom_install_var.get(), target, serial, flags, apk)
            except ValueError as e:
                messagebox.showerror("Settings error", str(e))
                return
            self.thread_cmd(cmd)
        else:
            cmd = ["adb", "-s", serial, "install"]
            if flags:
                cmd += flags.split()
            cmd += [apk]
            self.thread_cmd(cmd)

    # -------------------- QUICK UPDATE TAB --------------------
    def _build_quick_tab(self):
        area = Frame(self.tab_quick)
        area.pack(fill=BOTH, expand=True, padx=12, pady=10)

        # Folder row
        fr = Frame(area)
        fr.pack(fill=X, pady=(0, 10))

        Label(fr, text="APK Folder:").pack(side=LEFT)
        Entry(fr, textvariable=self.apk_folder_var, width=60).pack(side=LEFT, padx=8, fill=X, expand=True)
        Button(fr, text="Choose Folder", command=self.choose_apk_folder).pack(side=LEFT, padx=(0, 6))
        Button(fr, text="Save", command=self.save_settings_only).pack(side=LEFT)

        # Instances controls
        ctrl = Frame(area)
        ctrl.pack(fill=X, pady=(0, 8))

        Button(ctrl, text="Add Instance", command=self.add_instance).pack(side=LEFT)
        Button(ctrl, text="Edit Selected", command=self.edit_selected_instance).pack(side=LEFT, padx=8)
        Button(ctrl, text="Remove Selected", command=self.remove_selected_instance).pack(side=LEFT)

        Button(ctrl, text="Delete downloaded APKs", fg="white", bg="#c0392b", command=self.delete_apks).pack(side=RIGHT)

        # Listbox
        box = Frame(area)
        box.pack(fill=BOTH, expand=True)

        self.instance_list = Listbox(box, height=10)
        self.instance_list.pack(side=LEFT, fill=BOTH, expand=True)

        sb = Scrollbar(box, orient=VERTICAL, command=self.instance_list.yview)
        sb.pack(side=RIGHT, fill=Y)
        self.instance_list.config(yscrollcommand=sb.set)

        # Action buttons
        act = Frame(area)
        act.pack(fill=X, pady=10)

        Button(act, text="Open Page (selected)", command=self.open_selected_url).pack(side=LEFT)
        Button(act, text="Update (selected)", height=2, command=self.quick_update_selected).pack(side=LEFT, padx=8)

        self.quick_status = StringVar(value="")
        Label(area, textvariable=self.quick_status, anchor="w").pack(fill=X)

        self._refresh_instance_list()

    def choose_apk_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.apk_folder_var.set(folder)
            self.save_settings_only()

    def _refresh_instance_list(self):
        self.instance_list.delete(0, END)
        for i in self.instances:
            hint = f" (hint: {i.hint})" if i.hint else ""
            self.instance_list.insert(END, f"{i.name}{hint}")

    def _selected_instance_index(self):
        sel = self.instance_list.curselection()
        if not sel:
            return None
        return int(sel[0])

    def add_instance(self):
        name = simpledialog.askstring("New Instance", "App name (ex: WhatsApp):", parent=self.root)
        if not name:
            return
        url = simpledialog.askstring("New Instance", "URL (download page or direct apk link):", parent=self.root)
        if not url:
            return
        hint = simpledialog.askstring("Optional Hint", "APK hint (optional, improves accuracy):", parent=self.root)
        hint = (hint or "").strip()
        self.instances.append(InstanceItem(name=name.strip(), url=url.strip(), hint=hint))
        self._refresh_instance_list()
        self.save_settings_only()

    def edit_selected_instance(self):
        idx = self._selected_instance_index()
        if idx is None:
            messagebox.showinfo("Select one", "Select an instance first.")
            return
        inst = self.instances[idx]

        name = simpledialog.askstring("Edit Instance", "App name:", initialvalue=inst.name, parent=self.root)
        if not name:
            return
        url = simpledialog.askstring("Edit Instance", "URL:", initialvalue=inst.url, parent=self.root)
        if not url:
            return
        hint = simpledialog.askstring("Edit Instance", "Hint (optional):", initialvalue=inst.hint, parent=self.root)
        hint = (hint or "").strip()

        self.instances[idx] = InstanceItem(name=name.strip(), url=url.strip(), hint=hint)
        self._refresh_instance_list()
        self.save_settings_only()

    def remove_selected_instance(self):
        idx = self._selected_instance_index()
        if idx is None:
            messagebox.showinfo("Select one", "Select an instance first.")
            return
        if messagebox.askyesno("Remove", "Remove selected instance?"):
            self.instances.pop(idx)
            self._refresh_instance_list()
            self.save_settings_only()

    def open_selected_url(self):
        idx = self._selected_instance_index()
        if idx is None:
            messagebox.showinfo("Select one", "Select an instance first.")
            return
        url = self.instances[idx].url
        if not url:
            messagebox.showerror("No URL", "This instance has no URL.")
            return
        # Use xdg-open to open default browser
        self.quick_status.set("Opening page...")
        self.thread_cmd(["xdg-open", url])

    def delete_apks(self):
        folder = self.apk_folder_var.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Folder not set", "Set a valid APK folder first.")
            return
        confirm = simpledialog.askstring("Confirm delete", "Type DELETE to remove all *.apk in the folder:", parent=self.root)
        if confirm != "DELETE":
            return

        apks = glob.glob(os.path.join(folder, "*.apk"))
        removed = 0
        for p in apks:
            try:
                os.remove(p)
                removed += 1
            except Exception:
                pass
        self.quick_status.set(f"Deleted {removed} APK(s).")

    def quick_update_selected(self):
        idx = self._selected_instance_index()
        if idx is None:
            messagebox.showinfo("Select one", "Select an instance first.")
            return

        folder = self.apk_folder_var.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showerror("APK Folder required", "Choose an APK folder first (Quick Update tab).")
            return

        serial = self.device_var.get().strip()
        if not serial:
            messagebox.showerror("No device", "No ADB device found.\nGo to APK Install tab and connect a device.")
            return

        inst = self.instances[idx]
        apk, reason = find_best_apk(
            folder=folder,
            hint=inst.hint,
            recent_minutes=int(self.recent_minutes_var.get()),
            require_hint=bool(self.require_hint_var.get()),
            fallback_to_newest=bool(self.fallback_var.get())
        )

        if not apk:
            self.quick_status.set(f"Update failed: {reason}")
            return

        fname = os.path.basename(apk)
        self.quick_status.set(f"Found: {fname} — {reason}")

        # Countdown then install
        seconds = max(0, int(self.countdown_var.get()))
        self._countdown_cancel = False
        self._start_countdown_install(apk, serial, seconds)

    def _start_countdown_install(self, apk, serial, seconds):
        # Create small popup with countdown + cancel
        win = Toplevel(self.root)
        win.title("Quick Update")
        win.geometry("520x180")
        win.transient(self.root)

        label = Label(win, text="", justify=LEFT)
        label.pack(padx=12, pady=12, anchor="w")

        btnrow = Frame(win)
        btnrow.pack(fill=X, padx=12, pady=(0, 10))

        def cancel():
            self._countdown_cancel = True
            try:
                win.destroy()
            except Exception:
                pass

        Button(btnrow, text="Cancel", command=cancel).pack(side=LEFT)

        def tick(t):
            if self._countdown_cancel:
                return
            if t <= 0:
                try:
                    win.destroy()
                except Exception:
                    pass
                self._do_install_path(apk, serial)
                return
            label.config(text=f"About to install:\n  {os.path.basename(apk)}\n\nStarting in {t} seconds...")
            win.after(1000, lambda: tick(t - 1))

        tick(seconds)

    def _do_install_path(self, apk, serial):
        flags = self.flags_var.get().strip()
        target = self.target_var.get().strip() or DEFAULTS["chromeos_target"]

        self.quick_status.set(f"Installing: {os.path.basename(apk)}")
        # Always use -s to avoid multi-device error
        if self.advanced_mode.get():
            try:
                cmd = build_cmd_from_template(self.custom_install_var.get(), target, serial, flags, apk)
            except ValueError as e:
                messagebox.showerror("Settings error", str(e))
                return
            self.thread_cmd(cmd)
        else:
            cmd = ["adb", "-s", serial, "install"]
            if flags:
                cmd += flags.split()
            cmd += [apk]
            self.thread_cmd(cmd)

    # -------------------- ADB TOOLBOX TAB (safe basics) --------------------
    def _build_toolbox_tab(self):
        area = Frame(self.tab_toolbox)
        area.pack(fill=BOTH, expand=True, padx=12, pady=10)

        top = Frame(area)
        top.pack(fill=X, pady=(0, 10))
        Button(top, text="Refresh Devices", command=self.refresh_devices).pack(side=LEFT)

        tools = Frame(area)
        tools.pack(fill=X, pady=(0, 10))

        Button(tools, text="Device Info", command=self.tb_device_info).pack(side=LEFT, padx=(0, 8))
        Button(tools, text="Battery Info", command=self.tb_battery).pack(side=LEFT, padx=(0, 8))
        Button(tools, text="Screenshot -> Pull", command=self.tb_screenshot).pack(side=LEFT, padx=(0, 8))
        Button(tools, text="Open /sdcard/Download", command=self.tb_list_download).pack(side=LEFT)

        custom = ttk.LabelFrame(area, text="Custom ADB Command (safe)")
        custom.pack(fill=X, pady=(8, 0))

        self.custom_cmd_var = StringVar(value="adb devices")
        Entry(custom, textvariable=self.custom_cmd_var, width=90).pack(side=LEFT, padx=8, pady=10, fill=X, expand=True)
        Button(custom, text="Run", command=self.tb_run_custom).pack(side=LEFT, padx=8, pady=10)

        Label(area, text="Note: This toolbox avoids risky commands (no flashing/fastboot). Output is in Logs tab.").pack(anchor="w")

    def _require_serial(self):
        serial = self.device_var.get().strip()
        if not serial:
            messagebox.showerror("No device", "No ADB device found.\nConnect a device first.")
            return None
        return serial

    def tb_device_info(self):
        serial = self._require_serial()
        if not serial:
            return
        cmd = ["bash", "-lc", f"adb -s {serial} shell getprop ro.product.model; adb -s {serial} shell getprop ro.build.version.release; adb -s {serial} shell getprop ro.product.manufacturer"]
        self.thread_cmd(cmd)

    def tb_battery(self):
        serial = self._require_serial()
        if not serial:
            return
        self.thread_cmd(["adb", "-s", serial, "shell", "dumpsys", "battery"])

    def tb_screenshot(self):
        serial = self._require_serial()
        if not serial:
            return
        # Save to /sdcard then pull to home
        ts = int(time.time())
        remote = f"/sdcard/screen_{ts}.png"
        local = os.path.expanduser(f"~/screen_{ts}.png")
        self.thread_cmd(["bash", "-lc", f"adb -s {serial} shell screencap -p {remote} && adb -s {serial} pull {remote} \"{local}\" && adb -s {serial} shell rm {remote}"])

    def tb_list_download(self):
        serial = self._require_serial()
        if not serial:
            return
        self.thread_cmd(["adb", "-s", serial, "shell", "ls", "-la", "/sdcard/Download"])

    def tb_run_custom(self):
        cmd = self.custom_cmd_var.get().strip()
        if not cmd:
            return
        if not (cmd.startswith("adb ") or cmd == "adb"):
            messagebox.showerror("Blocked", "For safety, custom commands must start with: adb ...")
            return
        self.thread_cmd(["bash", "-lc", cmd])

    # -------------------- SETTINGS TAB --------------------
    def _build_settings_tab(self):
        area = Frame(self.tab_settings)
        area.pack(fill=BOTH, expand=True, padx=12, pady=10)

        # Basic ADB settings
        basic = ttk.LabelFrame(area, text="Basic")
        basic.pack(fill=X, pady=(0, 12))

        Label(basic, text="ChromeOS target (IP:port):").grid(row=0, column=0, sticky="w", padx=8, pady=8)
        Entry(basic, textvariable=self.target_var, width=32).grid(row=0, column=1, sticky="w", padx=8, pady=8)

        Label(basic, text="Install flags (ex: -r -g):").grid(row=1, column=0, sticky="w", padx=8, pady=8)
        Entry(basic, textvariable=self.flags_var, width=32).grid(row=1, column=1, sticky="w", padx=8, pady=8)

        # Quick Update settings
        quick = ttk.LabelFrame(area, text="Quick Update")
        quick.pack(fill=X, pady=(0, 12))

        Label(quick, text="Countdown seconds:").grid(row=0, column=0, sticky="w", padx=8, pady=8)
        Spinbox(quick, from_=0, to=30, textvariable=self.countdown_var, width=8).grid(row=0, column=1, sticky="w", padx=8, pady=8)

        Label(quick, text="Prefer APKs modified within (minutes):").grid(row=1, column=0, sticky="w", padx=8, pady=8)
        Spinbox(quick, from_=0, to=120, textvariable=self.recent_minutes_var, width=8).grid(row=1, column=1, sticky="w", padx=8, pady=8)
        Label(quick, text="(0 = disable time window)").grid(row=1, column=2, sticky="w", padx=8, pady=8)

        Checkbutton(quick, text="Require hint match (safer)", variable=self.require_hint_var).grid(row=2, column=0, columnspan=2, sticky="w", padx=8, pady=8)
        Checkbutton(quick, text="If no hint match, fall back to newest APK", variable=self.fallback_var).grid(row=3, column=0, columnspan=2, sticky="w", padx=8, pady=8)

        # Advanced ADB templates
        adv = ttk.LabelFrame(area, text="Advanced (optional)")
        adv.pack(fill=X, pady=(0, 12))

        Checkbutton(adv, text="Enable custom ADB command templates (power users)", variable=self.advanced_mode).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=8, pady=8
        )

        Label(adv, text="Custom connect template:").grid(row=1, column=0, sticky="w", padx=8, pady=6)
        Entry(adv, textvariable=self.custom_connect_var, width=70).grid(row=1, column=1, sticky="w", padx=8, pady=6)

        Label(adv, text="Custom install template:").grid(row=2, column=0, sticky="w", padx=8, pady=6)
        Entry(adv, textvariable=self.custom_install_var, width=70).grid(row=2, column=1, sticky="w", padx=8, pady=6)

        Label(adv, text="Placeholders: {target} {serial} {flags} {apk} | Safety: must start with adb ...", justify=LEFT).grid(
            row=3, column=0, columnspan=2, sticky="w", padx=8, pady=(2, 8)
        )

        # Buttons
        btns = Frame(area)
        btns.pack(fill=X)
        Button(btns, text="Save Settings", command=self.save_settings_only).pack(side=LEFT, padx=(0, 8))
        Button(btns, text="Reset to Defaults", command=self.reset_defaults).pack(side=LEFT)

    def save_settings_only(self):
        try:
            self._save_all_settings()
            self.log_info(f"# Saved settings to: {config_path()}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))
        self.refresh_devices()

    def reset_defaults(self):
        self.cfg = DEFAULTS.copy()
        # Apply defaults to vars
        self.chromeos_mode.set(self.cfg["chromeos_mode"])
        self.target_var.set(self.cfg["chromeos_target"])
        self.flags_var.set(self.cfg["install_flags"])
        self.advanced_mode.set(self.cfg["advanced_mode"])
        self.custom_connect_var.set(self.cfg["custom_connect"])
        self.custom_install_var.set(self.cfg["custom_install"])

        self.apk_folder_var.set(self.cfg["apk_folder"])
        self.countdown_var.set(self.cfg["countdown_seconds"])
        self.recent_minutes_var.set(self.cfg["recent_minutes"])
        self.require_hint_var.set(self.cfg["require_hint"])
        self.fallback_var.set(self.cfg["fallback_to_newest"])

        self.instances = []
        self._refresh_instance_list()
        self.save_settings_only()

if __name__ == "__main__":
    root = Tk()
    APKInstallerApp(root)
    root.mainloop()
