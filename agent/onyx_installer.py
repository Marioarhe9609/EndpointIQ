"""
Onyx Monitor — Instalador Profesional v1.0
============================================
Instalador con interfaz gráfica personalizada para el servicio
OnyxMonitor de Windows. Maneja la migración desde versiones
anteriores (Tarea Programada) automáticamente.

Compilar:  pyinstaller --onefile --windowed --icon=onyx.ico --name=OnyxSetup onyx_installer.py
"""

import os
import sys
import json
import shutil
import ctypes
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
import base64
import tempfile

# ===========================================================================
# Configuration
# ===========================================================================
APP_NAME = "Onyx Monitor"
APP_VERSION = "2.1.0"
COMPANY = "Agentica"
SERVICE_NAME = "OnyxMonitor"
INSTALL_DIR = Path(r"C:\Onyx\agent")
SERVER_URL = "https://proy-anla-poc-175647544738.us-central1.run.app"

# Files to install (relative to the installer location or bundled)
AGENT_FILES = [
    "onyx_agent.py",
    "onyx_service.py",
    "onyx_config.json",
    "onyx_credentials.json",
    "onyx_launcher.vbs",
    "onyx_logo.jpeg",
]

# ===========================================================================
# Admin Check
# ===========================================================================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def run_as_admin():
    """Re-launch the script as administrator."""
    if getattr(sys, 'frozen', False):
        exe = sys.executable
    else:
        exe = sys.executable
    params = " ".join([f'"{arg}"' for arg in sys.argv])
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    except Exception:
        pass
    sys.exit(0)


# ===========================================================================
# Dark Theme Colors
# ===========================================================================
BG_DARK = "#0a0e1a"
BG_CARD = "#111827"
BG_SURFACE = "#1a2035"
TEXT_PRIMARY = "#e2e8f0"
TEXT_SECONDARY = "#94a3b8"
ACCENT_BLUE = "#3b82f6"
ACCENT_GREEN = "#10b981"
ACCENT_RED = "#ef4444"
ACCENT_AMBER = "#f59e0b"
BORDER_COLOR = "#1e293b"


# ===========================================================================
# Installer Application
# ===========================================================================
class OnyxInstaller:
    def __init__(self, root, mode="install"):
        self.root = root
        self.mode = mode  # "install" or "uninstall"
        self.root.title(f"{'Instalar' if mode == 'install' else 'Desinstalar'} — {APP_NAME}")
        self.root.geometry("600x520")
        self.root.resizable(False, False)
        self.root.configure(bg=BG_DARK)

        # Center window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - 600) // 2
        y = (self.root.winfo_screenheight() - 520) // 2
        self.root.geometry(f"600x520+{x}+{y}")

        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("Dark.TFrame", background=BG_DARK)
        self.style.configure("Card.TFrame", background=BG_CARD)
        self.style.configure("Dark.TLabel", background=BG_DARK, foreground=TEXT_PRIMARY,
                           font=("Segoe UI", 10))
        self.style.configure("Title.TLabel", background=BG_DARK, foreground=TEXT_PRIMARY,
                           font=("Segoe UI", 18, "bold"))
        self.style.configure("Subtitle.TLabel", background=BG_DARK, foreground=TEXT_SECONDARY,
                           font=("Segoe UI", 10))
        self.style.configure("Status.TLabel", background=BG_DARK, foreground=ACCENT_GREEN,
                           font=("Segoe UI", 9))
        self.style.configure("Blue.TButton", background=ACCENT_BLUE, foreground="white",
                           font=("Segoe UI", 11, "bold"), padding=(20, 10))
        self.style.configure("Red.TButton", background=ACCENT_RED, foreground="white",
                           font=("Segoe UI", 11, "bold"), padding=(20, 10))
        self.style.configure("Ghost.TButton", background=BG_SURFACE, foreground=TEXT_SECONDARY,
                           font=("Segoe UI", 9), padding=(10, 5))
        self.style.configure("green.Horizontal.TProgressbar",
                           troughcolor=BG_SURFACE, background=ACCENT_GREEN)

        self.current_step = 0
        self.log_lines = []

        if mode == "install":
            self.build_install_ui()
        else:
            self.build_uninstall_ui()

    # ── Install UI ──
    def build_install_ui(self):
        # Header
        header = tk.Frame(self.root, bg=BG_DARK, height=100)
        header.pack(fill="x", padx=30, pady=(20, 5))
        header.pack_propagate(False)

        # Logo + Title
        try:
            source_dir = self._get_source_dir()
            logo_path = source_dir / "onyx_logo.jpeg"
            if logo_path.exists():
                from PIL import Image, ImageTk
                img = Image.open(str(logo_path))
                img = img.resize((70, 70), Image.LANCZOS)
                self.logo_img = ImageTk.PhotoImage(img)
                logo_label = tk.Label(header, image=self.logo_img, bg=BG_DARK)
                logo_label.pack(side="left", padx=(0, 15))
        except Exception:
            # Fallback: text logo
            logo_text = tk.Label(header, text="👁", font=("Segoe UI", 36), bg=BG_DARK, fg=ACCENT_BLUE)
            logo_text.pack(side="left", padx=(0, 15))

        title_frame = tk.Frame(header, bg=BG_DARK)
        title_frame.pack(side="left", fill="y", padx=0)

        tk.Label(title_frame, text="ONYX", font=("Segoe UI", 24, "bold"),
                bg=BG_DARK, fg=TEXT_PRIMARY).pack(anchor="w")
        tk.Label(title_frame, text=f"Monitor Agent v{APP_VERSION} · By {COMPANY}",
                font=("Segoe UI", 9), bg=BG_DARK, fg=TEXT_SECONDARY).pack(anchor="w")

        # Separator
        sep = tk.Frame(self.root, bg=BORDER_COLOR, height=1)
        sep.pack(fill="x", padx=30, pady=10)

        # Info panel
        info_frame = tk.Frame(self.root, bg=BG_CARD, highlightbackground=BORDER_COLOR,
                            highlightthickness=1, padx=16, pady=12)
        info_frame.pack(fill="x", padx=30, pady=(0, 10))

        tk.Label(info_frame, text="📦  Este instalador realizará las siguientes acciones:",
                font=("Segoe UI", 9, "bold"), bg=BG_CARD, fg=TEXT_PRIMARY, anchor="w").pack(fill="x")

        steps = [
            "✓  Verificar e instalar dependencias (psutil, pywin32, BigQuery SDK)",
            "✓  Migrar desde Tarea Programada (si existe) sin conflictos",
            "✓  Instalar el servicio Windows 'OnyxMonitor'",
            "✓  Configurar auto-inicio y auto-recovery",
            "✓  Registrar en Agregar/Quitar Programas"
        ]
        for step in steps:
            tk.Label(info_frame, text=step, font=("Consolas", 8),
                    bg=BG_CARD, fg=TEXT_SECONDARY, anchor="w").pack(fill="x", padx=(10, 0))

        # Destination
        dest_frame = tk.Frame(self.root, bg=BG_DARK)
        dest_frame.pack(fill="x", padx=30, pady=5)
        tk.Label(dest_frame, text="📁 Directorio de instalación:",
                font=("Segoe UI", 9), bg=BG_DARK, fg=TEXT_SECONDARY).pack(anchor="w")
        tk.Label(dest_frame, text=str(INSTALL_DIR),
                font=("Consolas", 10, "bold"), bg=BG_DARK, fg=ACCENT_BLUE).pack(anchor="w")

        # Progress area
        self.progress_frame = tk.Frame(self.root, bg=BG_DARK)
        self.progress_frame.pack(fill="x", padx=30, pady=10)

        self.progress_bar = ttk.Progressbar(
            self.progress_frame, style="green.Horizontal.TProgressbar",
            mode="determinate", maximum=100
        )
        self.progress_bar.pack(fill="x", pady=(0, 5))

        self.status_label = tk.Label(
            self.progress_frame, text="Listo para instalar",
            font=("Segoe UI", 9), bg=BG_DARK, fg=TEXT_SECONDARY, anchor="w"
        )
        self.status_label.pack(fill="x")

        # Log area (hidden initially)
        self.log_frame = tk.Frame(self.root, bg=BG_DARK)
        self.log_frame.pack(fill="both", expand=True, padx=30, pady=(0, 5))

        self.log_text = tk.Text(
            self.log_frame, height=5, bg=BG_SURFACE, fg=TEXT_SECONDARY,
            font=("Consolas", 8), relief="flat", state="disabled",
            insertbackground=TEXT_PRIMARY, selectbackground=ACCENT_BLUE
        )
        self.log_text.pack(fill="both", expand=True)

        # Buttons
        btn_frame = tk.Frame(self.root, bg=BG_DARK)
        btn_frame.pack(fill="x", padx=30, pady=(5, 15))

        self.cancel_btn = tk.Button(
            btn_frame, text="Cancelar", font=("Segoe UI", 10),
            bg=BG_SURFACE, fg=TEXT_SECONDARY, relief="flat",
            cursor="hand2", padx=20, pady=8,
            command=self.root.destroy
        )
        self.cancel_btn.pack(side="left")

        self.install_btn = tk.Button(
            btn_frame, text="⚡ Instalar Ahora", font=("Segoe UI", 11, "bold"),
            bg=ACCENT_BLUE, fg="white", relief="flat",
            cursor="hand2", padx=25, pady=8, activebackground="#2563eb",
            command=self.start_install
        )
        self.install_btn.pack(side="right")

    # ── Uninstall UI ──
    def build_uninstall_ui(self):
        # Header
        header = tk.Frame(self.root, bg=BG_DARK, height=80)
        header.pack(fill="x", padx=30, pady=(30, 10))
        header.pack_propagate(False)

        tk.Label(header, text="🗑️", font=("Segoe UI", 36), bg=BG_DARK).pack(side="left", padx=(0, 15))

        title_frame = tk.Frame(header, bg=BG_DARK)
        title_frame.pack(side="left")
        tk.Label(title_frame, text="Desinstalar ONYX Monitor",
                font=("Segoe UI", 18, "bold"), bg=BG_DARK, fg=TEXT_PRIMARY).pack(anchor="w")
        tk.Label(title_frame, text="Se eliminará el servicio y los archivos del agente",
                font=("Segoe UI", 9), bg=BG_DARK, fg=TEXT_SECONDARY).pack(anchor="w")

        sep = tk.Frame(self.root, bg=BORDER_COLOR, height=1)
        sep.pack(fill="x", padx=30, pady=15)

        # Warning
        warn_frame = tk.Frame(self.root, bg="#1c1008", highlightbackground=ACCENT_AMBER,
                            highlightthickness=1, padx=16, pady=12)
        warn_frame.pack(fill="x", padx=30, pady=10)
        tk.Label(warn_frame, text="⚠️  Esta acción detendrá el monitoreo en esta máquina.",
                font=("Segoe UI", 10, "bold"), bg="#1c1008", fg=ACCENT_AMBER).pack(anchor="w")
        tk.Label(warn_frame, text="El equipo dejará de enviar métricas a la plataforma Onyx.",
                font=("Segoe UI", 9), bg="#1c1008", fg=TEXT_SECONDARY).pack(anchor="w")

        # Progress
        self.progress_frame = tk.Frame(self.root, bg=BG_DARK)
        self.progress_frame.pack(fill="x", padx=30, pady=15)
        self.progress_bar = ttk.Progressbar(self.progress_frame, style="green.Horizontal.TProgressbar",
                                           mode="determinate", maximum=100)
        self.progress_bar.pack(fill="x", pady=(0, 5))
        self.status_label = tk.Label(self.progress_frame, text="",
                                    font=("Segoe UI", 9), bg=BG_DARK, fg=TEXT_SECONDARY, anchor="w")
        self.status_label.pack(fill="x")

        self.log_frame = tk.Frame(self.root, bg=BG_DARK)
        self.log_frame.pack(fill="both", expand=True, padx=30, pady=(0, 5))
        self.log_text = tk.Text(self.log_frame, height=6, bg=BG_SURFACE, fg=TEXT_SECONDARY,
                              font=("Consolas", 8), relief="flat", state="disabled")
        self.log_text.pack(fill="both", expand=True)

        # Buttons
        btn_frame = tk.Frame(self.root, bg=BG_DARK)
        btn_frame.pack(fill="x", padx=30, pady=(5, 15))
        self.cancel_btn = tk.Button(btn_frame, text="Cancelar", font=("Segoe UI", 10),
                                   bg=BG_SURFACE, fg=TEXT_SECONDARY, relief="flat",
                                   cursor="hand2", padx=20, pady=8, command=self.root.destroy)
        self.cancel_btn.pack(side="left")
        self.install_btn = tk.Button(btn_frame, text="🗑️ Desinstalar", font=("Segoe UI", 11, "bold"),
                                    bg=ACCENT_RED, fg="white", relief="flat", cursor="hand2",
                                    padx=25, pady=8, command=self.start_uninstall)
        self.install_btn.pack(side="right")

    # ── Logging ──
    def log(self, msg, color=None):
        self.log_text.config(state="normal")
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")
        self.status_label.config(text=msg)
        self.root.update()

    def set_progress(self, value):
        self.progress_bar["value"] = value
        self.root.update()

    def _get_source_dir(self):
        """Get the directory where agent files are located."""
        if getattr(sys, 'frozen', False):
            # Running as compiled exe - files are bundled
            return Path(sys._MEIPASS) if hasattr(sys, '_MEIPASS') else Path(sys.executable).parent
        else:
            return Path(__file__).parent.resolve()

    def _run_cmd(self, cmd, shell=True, timeout=60):
        """Run a command and return (success, output)."""
        try:
            result = subprocess.run(
                cmd, shell=shell, capture_output=True, text=True,
                timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW
            )
            output = (result.stdout + result.stderr).strip()
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, "Timeout"
        except Exception as e:
            return False, str(e)

    # ===========================================================================
    # Installation Steps
    # ===========================================================================
    def start_install(self):
        self.install_btn.config(state="disabled", text="Instalando...")
        self.cancel_btn.config(state="disabled")
        threading.Thread(target=self._install_thread, daemon=True).start()

    def _install_thread(self):
        try:
            total_steps = 7
            step = 0

            # Step 1: Check Python
            step += 1
            self.set_progress(step / total_steps * 100)
            self.log(f"[{step}/{total_steps}] Verificando Python...")
            ok, out = self._run_cmd("python --version")
            if ok:
                self.log(f"   ✅ {out.strip()}")
            else:
                self.log("   ❌ Python no encontrado. Instálalo desde python.org")
                self._finish_error()
                return

            # Step 2: Install dependencies
            step += 1
            self.set_progress(step / total_steps * 100)
            self.log(f"[{step}/{total_steps}] Instalando dependencias...")

            pkg_imports = {
                "psutil": "psutil",
                "pywin32": "win32serviceutil",
                "google-cloud-bigquery": "google.cloud.bigquery"
            }
            for pkg in ["psutil", "pywin32", "google-cloud-bigquery"]:
                self.log(f"   📦 Verificando {pkg}...")
                import_name = pkg_imports[pkg]
                check_cmd = f'python -c "import {import_name}"'
                ok, _ = self._run_cmd(check_cmd)
                if not ok:
                    self.log(f"   ⬇️  Instalando {pkg}...")
                    ok2, out2 = self._run_cmd(f"pip install {pkg} --quiet", timeout=120)
                    if ok2:
                        self.log(f"   ✅ {pkg} instalado")
                    else:
                        self.log(f"   ⚠️  Error instalando {pkg}: {out2[:100]}")
                else:
                    self.log(f"   ✅ {pkg} ya instalado")

            # Step 3: Stop old service/task
            step += 1
            self.set_progress(step / total_steps * 100)
            self.log(f"[{step}/{total_steps}] Migrando desde versión anterior...")

            # Stop existing service
            ok, _ = self._run_cmd(f"sc query {SERVICE_NAME}")
            if ok:
                self.log("   🔄 Servicio existente encontrado. Deteniendo...")
                self._run_cmd(f"net stop {SERVICE_NAME}")
                time.sleep(2)
                self._run_cmd(f"sc delete {SERVICE_NAME}")
                time.sleep(2)
                self.log("   ✅ Servicio anterior eliminado")

            # Disable old scheduled task
            ok, _ = self._run_cmd('schtasks /Query /TN "Onyx Agent"')
            if ok:
                self.log("   🔄 Tarea Programada encontrada. Desactivando...")
                self._run_cmd('schtasks /Change /TN "Onyx Agent" /Disable')
                self.log("   ✅ Tarea Programada desactivada (no eliminada)")
            else:
                self.log("   ℹ️  No hay versión anterior instalada")

            # Step 4: Copy files
            step += 1
            self.set_progress(step / total_steps * 100)
            self.log(f"[{step}/{total_steps}] Copiando archivos a {INSTALL_DIR}...")

            INSTALL_DIR.mkdir(parents=True, exist_ok=True)
            source_dir = self._get_source_dir()
            copied = 0
            for fname in AGENT_FILES:
                src = source_dir / fname
                dst = INSTALL_DIR / fname
                if src.exists():
                    shutil.copy2(str(src), str(dst))
                    copied += 1
                    self.log(f"   📄 {fname}")
                else:
                    self.log(f"   ⚠️  {fname} no encontrado en {source_dir}")

            # Also copy credentials if not already there
            creds_src = source_dir / "onyx_credentials.json"
            creds_dst = INSTALL_DIR / "onyx_credentials.json"
            if creds_src.exists() and not creds_dst.exists():
                shutil.copy2(str(creds_src), str(creds_dst))
                self.log("   🔑 Credenciales copiadas")

            self.log(f"   ✅ {copied} archivos instalados")

            # Step 5: Install service
            step += 1
            self.set_progress(step / total_steps * 100)
            self.log(f"[{step}/{total_steps}] Registrando servicio Windows...")

            service_py = INSTALL_DIR / "onyx_service.py"
            ok, out = self._run_cmd(f'python "{service_py}" install')
            if ok or "already" in out.lower():
                self.log("   ✅ Servicio OnyxMonitor registrado")
            else:
                self.log(f"   ⚠️  {out[:100]}")
                # Try alternative method
                self.log("   🔄 Intentando método alternativo...")
                ok2, out2 = self._run_cmd(f'python "{service_py}" --startup auto install')
                if ok2:
                    self.log("   ✅ Servicio registrado (método alternativo)")

            # Configure recovery
            self._run_cmd(f"sc failure {SERVICE_NAME} reset= 86400 actions= restart/60000/restart/60000/restart/120000")
            self._run_cmd(f"sc config {SERVICE_NAME} start= delayed-auto")
            self._run_cmd(f'sc description {SERVICE_NAME} "Agente de monitoreo Onyx - By Agentica"')
            self.log("   ✅ Auto-recovery configurado (reinicio tras 60s)")

            # Step 6: Register in Add/Remove Programs
            step += 1
            self.set_progress(step / total_steps * 100)
            self.log(f"[{step}/{total_steps}] Registrando en Agregar/Quitar Programas...")

            self._register_uninstall()
            self.log("   ✅ Registrado en Panel de Control")

            # Step 7: Start service
            step += 1
            self.set_progress(step / total_steps * 100)
            self.log(f"[{step}/{total_steps}] Iniciando servicio OnyxMonitor...")

            ok, out = self._run_cmd(f"net start {SERVICE_NAME}")
            if ok:
                self.log("   ✅ Servicio iniciado exitosamente")
            else:
                self.log(f"   ⚠️  {out[:80]}")
                self._run_cmd(f"sc start {SERVICE_NAME}")

            # Done!
            self.set_progress(100)
            self._finish_success()

        except Exception as e:
            self.log(f"❌ Error inesperado: {e}")
            self._finish_error()

    def _register_uninstall(self):
        """Register in Windows Add/Remove Programs."""
        try:
            import winreg
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OnyxMonitor"
            key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                                    winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY)

            if getattr(sys, 'frozen', False):
                exe_path = sys.executable
            else:
                exe_path = f'python "{Path(__file__).resolve()}"'

            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, f"Onyx Monitor v{APP_VERSION}")
            winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, APP_VERSION)
            winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, COMPANY)
            winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, str(INSTALL_DIR))
            winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ,
                            f'{exe_path} --uninstall')
            winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except Exception as e:
            self.log(f"   ⚠️  No se pudo registrar: {e}")

    def _finish_success(self):
        self.status_label.config(text="✅ Instalación completada exitosamente", fg=ACCENT_GREEN)
        self.install_btn.config(state="normal", text="✅ Completado", bg=ACCENT_GREEN)
        self.cancel_btn.config(state="normal", text="Cerrar")
        self.log("")
        self.log("═" * 50)
        self.log("  ✅ ONYX MONITOR INSTALADO EXITOSAMENTE")
        self.log(f"  Servicio: {SERVICE_NAME}")
        self.log(f"  Directorio: {INSTALL_DIR}")
        self.log("  Auto-inicio: Sí (al encender Windows)")
        self.log("  Auto-recovery: Sí (reinicio tras 60s)")
        self.log("═" * 50)

    def _finish_error(self):
        self.status_label.config(text="❌ Instalación con errores", fg=ACCENT_RED)
        self.install_btn.config(state="normal", text="Reintentar", bg=ACCENT_AMBER,
                              command=self.start_install)
        self.cancel_btn.config(state="normal")

    # ===========================================================================
    # Uninstall Steps
    # ===========================================================================
    def start_uninstall(self):
        if not messagebox.askyesno("Confirmar", "¿Estás seguro de desinstalar Onyx Monitor?\n\n"
                                  "El equipo dejará de enviar métricas a la plataforma."):
            return
        self.install_btn.config(state="disabled", text="Desinstalando...")
        self.cancel_btn.config(state="disabled")
        threading.Thread(target=self._uninstall_thread, daemon=True).start()

    def _uninstall_thread(self):
        try:
            self.set_progress(20)
            self.log("[1/4] Deteniendo servicio OnyxMonitor...")
            self._run_cmd(f"net stop {SERVICE_NAME}")
            time.sleep(2)

            self.set_progress(40)
            self.log("[2/4] Eliminando servicio...")
            service_py = INSTALL_DIR / "onyx_service.py"
            if service_py.exists():
                self._run_cmd(f'python "{service_py}" remove')
            self._run_cmd(f"sc delete {SERVICE_NAME}")
            time.sleep(1)

            self.set_progress(60)
            self.log("[3/4] Limpiando registro de Windows...")
            try:
                import winreg
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OnyxMonitor")
            except Exception:
                pass

            self.set_progress(80)
            self.log("[4/4] Eliminando archivos...")
            # Delete service-related files but keep credentials and config
            for fname in ["onyx_service.py", "onyx_service.log", "onyx_heartbeat.txt"]:
                fpath = INSTALL_DIR / fname
                if fpath.exists():
                    try:
                        fpath.unlink()
                        self.log(f"   🗑️ {fname}")
                    except Exception:
                        pass

            self.set_progress(100)
            self.status_label.config(text="✅ Desinstalación completada", fg=ACCENT_GREEN)
            self.install_btn.config(state="normal", text="✅ Completado", bg=ACCENT_GREEN)
            self.cancel_btn.config(state="normal", text="Cerrar")
            self.log("")
            self.log("✅ Onyx Monitor desinstalado exitosamente.")
            self.log("ℹ️  Las credenciales y config se conservaron en:")
            self.log(f"   {INSTALL_DIR}")

        except Exception as e:
            self.log(f"❌ Error: {e}")
            self.install_btn.config(state="normal", text="Reintentar", command=self.start_uninstall)
            self.cancel_btn.config(state="normal")


# ===========================================================================
# Entry Point
# ===========================================================================
def main():
    # Check admin
    if not is_admin():
        run_as_admin()
        return

    # Check mode
    mode = "install"
    if "--uninstall" in sys.argv or "--remove" in sys.argv:
        mode = "uninstall"

    root = tk.Tk()
    app = OnyxInstaller(root, mode=mode)
    root.mainloop()


if __name__ == "__main__":
    main()
