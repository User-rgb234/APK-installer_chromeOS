import os
import json
import subprocess
import threading
from tkinter import *
from tkinter import ttk, filedialog, messagebox

APP_NAME = "apk-installer"
DEFAULTS = {
    "chromeos_mode": True,
    "chromeos_target": "100.115.92.2:5555",
    "install_flags": "-r",
    "advanced_mode": False,
    "custom_connect": "adb connect {target}",
    "custom_install": "adb -s {serial} install {flags} \"{apk}\"",
}

def config_path():
    home = os.path.expanduser("~")
    return os.path.join(home, ".config", APP_NAME, "settings.json")

def load_cfg():
    path = config_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cfg = DEFAULTS.copy()
        cfg.update({k: v for k, v in data.items() if k in DEFAULTS})
        return cfg
    except Exception:
        return DEFAULTS.copy()

def save_cfg(cfg):
    path = config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

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

def build_cmd_from_template(template, target, serial, flags, apk):
    """
    Advanced templates are allowed but restricted to starting with 'adb ' or 'adb\t'.
    """
    t = template.strip()
    if not (t.startswith("adb ") or t.startswith("adb\t") or t == "adb"):
        raise ValueError("For safety, custom commands must start with: adb ...")

    # Replace placeholders
    t = t.replace("{target}", target).replace("{serial}", serial).replace("{flags}", flags).replace("{apk}", apk)

    # Run via bash -lc so quotes work consistently
    return ["bash", "-lc", t]

class APKInstallerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("APK Installer (ChromeOS + Android via ADB)")
        self.root.geometry("820x520")

        self.cfg = load_cfg()

        self.nb = ttk.Notebook(root)
        self.nb.pack(fill=BOTH, expand=True)

        self.tab_install = Frame(self.nb)
        self.tab_log = Frame(self.nb)
        self.tab_settings = Frame(self.nb)

        self.nb.add(self.tab_install, text="APK Install")
        self.nb.add(self.tab_log, text="Terminal / Logs")
        self.nb.add(self.tab_settings, text="Settings")

        # Logs
        self.log = Text(self.tab_log, wrap="word")
        self.log.pack(fill=BOTH, expand=True)
        self.log.insert(END, "Logs will appear here.\n")

        # ---------- INSTALL TAB ----------
        top = Frame(self.tab_install)
        top.pack(fill=X, padx=12, pady=10)

        self.chromeos_mode = BooleanVar(value=bool(self.cfg["chromeos_mode"]))
        Checkbutton(
            top,
            text="ChromeOS mode (prefer ChromeOS ADB target)",
            variable=self.chromeos_mode,
            command=self.on_mode_change
        ).pack(anchor="w")

        btns = Frame(top)
        btns.pack(fill=X, pady=8)

        Button(btns, text="Install ADB (recommended)", command=self.install_adb).pack(side=LEFT, padx=(0, 8))
        Button(btns, text="ADB Connect (ChromeOS)", command=self.adb_connect).pack(side=LEFT, padx=(0, 8))
        Button(btns, text="Refresh Devices", command=self.refresh_devices).pack(side=LEFT)

        mid = Frame(self.tab_install)
        mid.pack(fill=X, padx=12, pady=8)

        Label(mid, text="Device:").pack(side=LEFT)
        self.device_var = StringVar(value="")
        self.device_menu = ttk.Combobox(mid, textvariable=self.device_var, state="readonly", width=46, values=[])
        self.device_menu.pack(side=LEFT, padx=8)

        pick = Frame(self.tab_install)
        pick.pack(fill=X, padx=12, pady=8)

        self.apk_path = StringVar(value="")
        Button(pick, text="Choose APK", command=self.choose_apk).pack(side=LEFT)
        Label(pick, textvariable=self.apk_path, anchor="w").pack(side=LEFT, padx=10, fill=X, expand=True)

        actions = Frame(self.tab_install)
        actions.pack(fill=X, padx=12, pady=10)

        Button(actions, text="Install APK", height=2, command=self.install_apk).pack(side=LEFT)
        Label(
            actions,
            text="Tip: If install fails, open the Logs tab and copy the error."
        ).pack(side=LEFT, padx=12)

        # ---------- SETTINGS TAB ----------
        s = Frame(self.tab_settings)
        s.pack(fill=BOTH, expand=True, padx=12, pady=12)

        # Basic settings
        basic = ttk.LabelFrame(s, text="Basic")
        basic.pack(fill=X, pady=(0, 12))

        Label(basic, text="ChromeOS target (IP:port):").grid(row=0, column=0, sticky="w", padx=8, pady=8)
        self.target_var = StringVar(value=self.cfg["chromeos_target"])
        Entry(basic, textvariable=self.target_var, width=30).grid(row=0, column=1, sticky="w", padx=8, pady=8)

        Label(basic, text="Install flags (ex: -r -g):").grid(row=1, column=0, sticky="w", padx=8, pady=8)
        self.flags_var = StringVar(value=self.cfg["install_flags"])
        Entry(basic, textvariable=self.flags_var, width=30).grid(row=1, column=1, sticky="w", padx=8, pady=8)

        # Advanced settings
        adv = ttk.LabelFrame(s, text="Advanced (optional)")
        adv.pack(fill=X, pady=(0, 12))

        self.advanced_mode = BooleanVar(value=bool(self.cfg["advanced_mode"]))
        Checkbutton(
            adv,
            text="Enable custom ADB command templates (power users)",
            variable=self.advanced_mode,
            command=self.on_adv_toggle
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=8, pady=8)

        Label(adv, text="Custom connect template:").grid(row=1, column=0, sticky="w", padx=8, pady=6)
        self.custom_connect_var = StringVar(value=self.cfg["custom_connect"])
        self.custom_connect_entry = Entry(adv, textvariable=self.custom_connect_var, width=70)
        self.custom_connect_entry.grid(row=1, column=1, sticky="w", padx=8, pady=6)

        Label(adv, text="Custom install template:").grid(row=2, column=0, sticky="w", padx=8, pady=6)
        self.custom_install_var = StringVar(value=self.cfg["custom_install"])
        self.custom_install_entry = Entry(adv, textvariable=self.custom_install_var, width=70)
        self.custom_install_entry.grid(row=2, column=1, sticky="w", padx=8, pady=6)

        hint = (
            "Placeholders:\n"
            "  {target} = ChromeOS ADB target\n"
            "  {serial} = chosen device\n"
            "  {flags}  = install flags\n"
            "  {apk}    = APK path\n"
            "Safety: templates must start with 'adb ...'\n"
        )
        Label(adv, text=hint, justify=LEFT).grid(row=3, column=0, columnspan=2, sticky="w", padx=8, pady=(2, 8))

        # Buttons
        btm = Frame(s)
        btm.pack(fill=X)

        Button(btm, text="Save Settings", command=self.save_settings).pack(side=LEFT, padx=(0, 8))
        Button(btm, text="Reset to Defaults", command=self.reset_defaults).pack(side=LEFT)

        self.on_adv_toggle()
        self.refresh_devices()

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

    def on_mode_change(self):
        self.refresh_devices()

    def on_adv_toggle(self):
        state = "normal" if self.advanced_mode.get() else "disabled"
        self.custom_connect_entry.configure(state=state)
        self.custom_install_entry.configure(state=state)

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

    def save_settings(self):
        self.cfg["chromeos_mode"] = bool(self.chromeos_mode.get())
        self.cfg["chromeos_target"] = self.target_var.get().strip() or DEFAULTS["chromeos_target"]
        self.cfg["install_flags"] = self.flags_var.get().strip()
        self.cfg["advanced_mode"] = bool(self.advanced_mode.get())
        self.cfg["custom_connect"] = self.custom_connect_var.get().strip() or DEFAULTS["custom_connect"]
        self.cfg["custom_install"] = self.custom_install_var.get().strip() or DEFAULTS["custom_install"]

        try:
            save_cfg(self.cfg)
            messagebox.showinfo("Saved", f"Saved to:\n{config_path()}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

        self.refresh_devices()

    def reset_defaults(self):
        self.cfg = DEFAULTS.copy()
        self.chromeos_mode.set(self.cfg["chromeos_mode"])
        self.target_var.set(self.cfg["chromeos_target"])
        self.flags_var.set(self.cfg["install_flags"])
        self.advanced_mode.set(self.cfg["advanced_mode"])
        self.custom_connect_var.set(self.cfg["custom_connect"])
        self.custom_install_var.set(self.cfg["custom_install"])
        self.on_adv_toggle()
        self.save_settings()

if __name__ == "__main__":
    root = Tk()
    APKInstallerApp(root)
    root.mainloop()
