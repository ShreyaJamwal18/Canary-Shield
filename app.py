"""
Canary Shield — Enterprise Desktop Application (EDR / XDR Console).

Modern desktop GUI built with CustomTkinter:
- Real-time Shield Management (Arm / Disarm / Status)
- Live Threat Feed & Forensic Telemetry Console
- Interactive Decoy Honeytoken Vault & Management
- Forensic Incident Reports Viewer & Quarantine Vault Access
- Built-in Attack Simulation Demonstration Test Harness
- System & Engine Configuration Panel
"""

import os
import sys
import time
import json
import queue
import logging
import threading
import subprocess
import webbrowser
import ctypes
from typing import Optional, List, Dict, Any
from tkinter import messagebox

import customtkinter as ctk
from PIL import Image
import psutil

# Resource path helper supporting dev mode and PyInstaller bundles (sys._MEIPASS)
def resource_path(relative_path: str) -> str:
    """Get absolute path to resource, works for dev and for PyInstaller bundle."""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

# Set explicit Windows AppUserModelID so taskbar displays the custom application icon
try:
    myappid = "canaryshield.edr.desktop.1.0"
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
except Exception:
    pass

from config import (
    BASE_DIR,
    TEST_SANDBOX_DIR,
    LOG_FILE,
    INCIDENTS_DIR,
    QUARANTINE_DIR,
    CONFIG_FILE_PATH,
    is_test_mode,
    get_active_allowlist,
    get_watched_directories,
    load_config,
    CANARY_COUNT_PER_DIR,
)
from decoy import deploy_decoys, cleanup_decoys, load_decoy_manifest
from monitor import start_monitoring
from incident_manager import list_incidents
from notify import send_threat_alert
import service_runner

# Appearance & Theme Configuration
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Theme Palette (Modern Cybersecurity Obsidian & Sky)
COLOR_BG = "#080c14"
COLOR_SIDEBAR = "#0c1322"
COLOR_CARD = "#121a2c"
COLOR_CARD_HOVER = "#182238"
COLOR_CARD_BORDER = "#1e2c47"
COLOR_CARD_SUBTLE = "#0e1524"
COLOR_ACCENT = "#38bdf8"
COLOR_ACCENT_HOVER = "#0284c7"
COLOR_SUCCESS = "#10b981"
COLOR_SUCCESS_HOVER = "#059669"
COLOR_DANGER = "#f43f5e"
COLOR_DANGER_HOVER = "#e11d48"
COLOR_WARNING = "#f59e0b"
COLOR_TEXT_MAIN = "#f8fafc"
COLOR_TEXT_MUTED = "#94a3b8"
COLOR_TEXT_DIM = "#64748b"
COLOR_TERMINAL_BG = "#050811"


class QueueLogHandler(logging.Handler):
    """Thread-safe logging handler routing engine events directly into GUI queue."""
    def __init__(self, log_queue: queue.Queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        try:
            msg = self.format(record)
            self.log_queue.put((record.levelname, msg))
        except Exception:
            pass


class CanaryShieldApp(ctk.CTk):
    """Main Canary Shield Desktop Application Window."""

    def __init__(self):
        super().__init__()

        self.title("Canary Shield — Autonomous Endpoint Defense Console")
        self.geometry("1180x760")
        self.minsize(1000, 660)
        self.configure(fg_color=COLOR_BG)

        # Application & Taskbar Icon
        ico_file = resource_path(os.path.join("assets", "canary_shield.ico"))
        if os.path.exists(ico_file):
            try:
                self.iconbitmap(ico_file)
            except Exception:
                pass

        # Threading & Engine State
        self.log_queue = queue.Queue()
        self.is_armed = False
        self.observer = None
        self.vss_guard = None
        self.sim_proc: Optional[subprocess.Popen] = None
        self.self_healing_thread = None
        self.active_canaries: List[str] = []
        self.threats_blocked_count = 0
        self.current_view_name = "dashboard"
        self.view_frames: Dict[str, ctk.CTkFrame] = {}
        self.presentation_window: Optional[ctk.CTkToplevel] = None

        # Setup Logging Interception
        self._setup_logging()

        # Build UI Layout
        self._build_layout()

        # Initialize Default State
        self._refresh_system_status()
        self._poll_log_queue()

        # Protocol cleanup on window close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_logging(self):
        """Attach queue log handler to canary_shield logger hierarchy."""
        handler = QueueLogHandler(self.log_queue)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%H:%M:%S"))
        logger = logging.getLogger("canary_shield")
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)

    def _build_layout(self):
        """Construct sidebar and main workspace frames."""
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # =====================================================================
        # SIDEBAR FRAME
        # =====================================================================
        self.sidebar_frame = ctk.CTkFrame(
            self,
            width=230,
            corner_radius=0,
            fg_color=COLOR_SIDEBAR,
            border_width=0,
        )
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(10, weight=1)

        # Sidebar Header / Brand with PNG logo
        png_file = resource_path(os.path.join("assets", "canary_shield.png"))
        brand_top_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        brand_top_frame.grid(row=0, column=0, padx=16, pady=(22, 4), sticky="w")

        if os.path.exists(png_file):
            try:
                logo_pil = Image.open(png_file)
                self.sidebar_logo_img = ctk.CTkImage(
                    light_image=logo_pil,
                    dark_image=logo_pil,
                    size=(28, 28)
                )
                brand_label = ctk.CTkLabel(
                    brand_top_frame,
                    text=" CANARY SHIELD",
                    image=self.sidebar_logo_img,
                    compound="left",
                    font=ctk.CTkFont(family="Segoe UI", size=17, weight="bold"),
                    text_color=COLOR_TEXT_MAIN,
                )
            except Exception:
                brand_label = ctk.CTkLabel(
                    brand_top_frame,
                    text="CANARY SHIELD",
                    font=ctk.CTkFont(family="Segoe UI", size=17, weight="bold"),
                    text_color=COLOR_TEXT_MAIN,
                )
        else:
            brand_label = ctk.CTkLabel(
                brand_top_frame,
                text="CANARY SHIELD",
                font=ctk.CTkFont(family="Segoe UI", size=17, weight="bold"),
                text_color=COLOR_TEXT_MAIN,
            )
        brand_label.pack(side="left")

        # Subtitle badge pill
        badge_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        badge_frame.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="w")

        sub_tag = ctk.CTkLabel(
            badge_frame,
            text="EDR DECEPTION ENGINE",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=COLOR_ACCENT,
        )
        sub_tag.pack(side="left")

        # Subtle divider
        sep = ctk.CTkFrame(self.sidebar_frame, height=1, fg_color=COLOR_CARD_BORDER)
        sep.grid(row=2, column=0, padx=14, pady=(0, 14), sticky="ew")

        # Sidebar Navigation Buttons
        self.nav_buttons = {}
        nav_items = [
            ("dashboard", "📊  Dashboard"),
            ("decoys", "🎯  Decoy Vault"),
            ("threat_feed", "⚡  Threat Feed"),
            ("incidents", "📁  Forensics Vault"),
            ("simulator", "🧪  Attack Simulator"),
            ("settings", "⚙️  Configuration"),
        ]

        for idx, (view_id, label_text) in enumerate(nav_items, start=3):
            btn = ctk.CTkButton(
                self.sidebar_frame,
                text=label_text,
                anchor="w",
                font=ctk.CTkFont(family="Segoe UI", size=13, weight="normal"),
                fg_color="transparent",
                text_color=COLOR_TEXT_MUTED,
                hover_color=COLOR_CARD_HOVER,
                corner_radius=8,
                height=38,
                command=lambda v=view_id: self.switch_view(v),
            )
            btn.grid(row=idx, column=0, padx=12, pady=3, sticky="ew")
            self.nav_buttons[view_id] = btn

        # Presentation item in sidebar
        self.btn_presentation = ctk.CTkButton(
            self.sidebar_frame,
            text="📽️  Presentation",
            anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="normal"),
            fg_color="transparent",
            text_color=COLOR_TEXT_MUTED,
            hover_color=COLOR_CARD_HOVER,
            corner_radius=8,
            height=38,
            command=self.open_presentation,
        )
        self.btn_presentation.grid(row=9, column=0, padx=12, pady=3, sticky="ew")

        # Sidebar Bottom Status Card
        self.sidebar_status_card = ctk.CTkFrame(
            self.sidebar_frame,
            fg_color=COLOR_CARD,
            corner_radius=10,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
        )
        self.sidebar_status_card.grid(row=11, column=0, padx=12, pady=16, sticky="ew")

        self.sidebar_mode_badge = ctk.CTkLabel(
            self.sidebar_status_card,
            text="● TEST SANDBOX" if is_test_mode() else "● PRODUCTION",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=COLOR_WARNING if is_test_mode() else COLOR_ACCENT,
        )
        self.sidebar_mode_badge.pack(padx=12, pady=(10, 2), anchor="w")

        self.sidebar_shield_badge = ctk.CTkLabel(
            self.sidebar_status_card,
            text="○ SHIELD DISARMED",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=COLOR_TEXT_MUTED,
        )
        self.sidebar_shield_badge.pack(padx=12, pady=(2, 4), anchor="w")

        self.sidebar_procs_badge = ctk.CTkLabel(
            self.sidebar_status_card,
            text=f"Baseline: {len(get_active_allowlist())} Procs Safe",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=COLOR_TEXT_DIM,
        )
        self.sidebar_procs_badge.pack(padx=12, pady=(0, 10), anchor="w")

        # =====================================================================
        # MAIN WORKSPACE CONTAINER
        # =====================================================================
        self.main_container = ctk.CTkFrame(self, corner_radius=0, fg_color=COLOR_BG)
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_container.grid_rowconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)

        # Initialize View Frames
        self._init_views()
        self.switch_view("dashboard")

    def _init_views(self):
        """Construct all child views."""
        self.view_frames["dashboard"] = self._create_dashboard_view()
        self.view_frames["decoys"] = self._create_decoys_view()
        self.view_frames["threat_feed"] = self._create_threat_feed_view()
        self.view_frames["incidents"] = self._create_incidents_view()
        self.view_frames["simulator"] = self._create_simulator_view()
        self.view_frames["settings"] = self._create_settings_view()

    def switch_view(self, view_name: str):
        """Switch current visible view frame and update active navigation button."""
        self.current_view_name = view_name
        for name, frame in self.view_frames.items():
            if name == view_name:
                frame.grid(row=0, column=0, sticky="nsew")
            else:
                frame.grid_forget()

        for btn_name, btn in self.nav_buttons.items():
            if btn_name == view_name:
                btn.configure(
                    fg_color=COLOR_CARD,
                    text_color=COLOR_ACCENT,
                    font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                    border_width=1,
                    border_color=COLOR_CARD_BORDER,
                )
            else:
                btn.configure(
                    fg_color="transparent",
                    text_color=COLOR_TEXT_MUTED,
                    font=ctk.CTkFont(family="Segoe UI", size=13, weight="normal"),
                    border_width=0,
                )

        # Trigger auto-refreshes when entering tabs
        if view_name == "decoys":
            self._refresh_decoys_table()
        elif view_name == "incidents":
            self._refresh_incidents_list()

    def open_presentation(self):
        """Open or focus the in-app presentation window."""
        if hasattr(self, "presentation_window") and self.presentation_window is not None:
            try:
                if self.presentation_window.winfo_exists():
                    self.presentation_window.focus_window()
                    return
            except Exception:
                pass
        from presentation_view import PresentationWindow
        self.presentation_window = PresentationWindow(self)

    # =========================================================================
    # VIEW 1: DASHBOARD
    # =========================================================================
    def _create_dashboard_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        # Top Hero Card: Shield Status & Master Control
        hero_card = ctk.CTkFrame(
            frame,
            fg_color=COLOR_CARD,
            corner_radius=12,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
        )
        hero_card.grid(row=0, column=0, columnspan=4, sticky="ew", pady=(0, 16), padx=0)
        hero_card.grid_columnconfigure(0, weight=1)

        hero_inner = ctk.CTkFrame(hero_card, fg_color="transparent")
        hero_inner.pack(fill="x", padx=24, pady=20)

        hero_text_col = ctk.CTkFrame(hero_inner, fg_color="transparent")
        hero_text_col.pack(side="left", fill="both", expand=True)

        self.dash_status_badge = ctk.CTkLabel(
            hero_text_col,
            text="○ SHIELD DISARMED — PROTECTION STANDBY",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=COLOR_TEXT_MUTED,
        )
        self.dash_status_badge.pack(anchor="w", pady=(0, 4))

        self.dash_title = ctk.CTkLabel(
            hero_text_col,
            text="Autonomous Deception-Based Ransomware Interception",
            font=ctk.CTkFont(family="Segoe UI", size=21, weight="bold"),
            text_color=COLOR_TEXT_MAIN,
        )
        self.dash_title.pack(anchor="w", pady=(0, 6))

        target_dir = TEST_SANDBOX_DIR if is_test_mode() else ", ".join(get_watched_directories())
        self.dash_target_label = ctk.CTkLabel(
            hero_text_col,
            text=f"Protected Target: {target_dir}",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLOR_TEXT_MUTED,
        )
        self.dash_target_label.pack(anchor="w", pady=(0, 8))

        # Hero Telemetry Chips Row
        chips_frame = ctk.CTkFrame(hero_text_col, fg_color="transparent")
        chips_frame.pack(anchor="w")

        chip_cache = ctk.CTkLabel(
            chips_frame,
            text="Incremental Process Cache (~100ms)",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=COLOR_ACCENT,
            fg_color=COLOR_CARD_SUBTLE,
            corner_radius=6,
            padx=8,
            pady=3,
        )
        chip_cache.pack(side="left", padx=(0, 8))

        chip_allowlist = ctk.CTkLabel(
            chips_frame,
            text=f"Protected Windows Baseline: {len(get_active_allowlist())} Procs",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=COLOR_SUCCESS,
            fg_color=COLOR_CARD_SUBTLE,
            corner_radius=6,
            padx=8,
            pady=3,
        )
        chip_allowlist.pack(side="left")

        # Master Arm/Disarm Button
        self.dash_arm_button = ctk.CTkButton(
            hero_inner,
            text="ARM SHIELD",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            fg_color=COLOR_SUCCESS,
            hover_color=COLOR_SUCCESS_HOVER,
            height=48,
            width=180,
            corner_radius=10,
            command=self.toggle_shield,
        )
        self.dash_arm_button.pack(side="right", padx=(20, 0))

        # Metrics Row (4 Cards)
        self.metric_decoys = self._create_metric_card(
            frame, row=1, col=0,
            title="DECOY TRIPWIRES",
            value="0 Present",
            icon="🪤",
            subtitle="Mimicry Honeypots"
        )
        self.metric_allowlist = self._create_metric_card(
            frame, row=1, col=1,
            title="PROTECTED BASELINE",
            value=f"{len(get_active_allowlist())} Processes",
            icon="🛡️",
            subtitle="Frozen System Allowlist"
        )
        self.metric_threats = self._create_metric_card(
            frame, row=1, col=2,
            title="INCIDENTS CONTAINED",
            value="0 Logged",
            icon="🛑",
            subtitle="Rapid Containment"
        )
        self.metric_vss = self._create_metric_card(
            frame, row=1, col=3,
            title="VSS RECOVERY GUARD",
            value="Disabled (System)",
            icon="🔒",
            subtitle="Anti-Deletion Shield"
        )

        # Lower Split Row: Telemetry Feed Status & Quick Action Center
        split_row = ctk.CTkFrame(frame, fg_color="transparent")
        split_row.grid(row=2, column=0, columnspan=4, sticky="nsew", pady=(16, 0))
        frame.grid_rowconfigure(2, weight=1)
        split_row.grid_columnconfigure(0, weight=3)
        split_row.grid_columnconfigure(1, weight=2)
        split_row.grid_rowconfigure(0, weight=1)

        # Left: Live Threat Status Banner
        threat_panel = ctk.CTkFrame(
            split_row,
            fg_color=COLOR_CARD,
            corner_radius=12,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
        )
        threat_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        # Threat Panel Header Bar
        threat_header = ctk.CTkFrame(threat_panel, fg_color=COLOR_CARD_SUBTLE, height=36, corner_radius=8)
        threat_header.pack(fill="x", padx=10, pady=(10, 8))

        ctk.CTkLabel(
            threat_header,
            text="● ● ●  REAL-TIME DEFENSE TELEMETRY",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=COLOR_ACCENT,
        ).pack(side="left", padx=12, pady=6)

        self.dash_threat_detail = ctk.CTkLabel(
            threat_panel,
            text="Standby — shield is disarmed. Press ARM SHIELD to deploy active filesystem monitoring.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=COLOR_TEXT_MUTED,
            justify="left",
            wraplength=520,
        )
        self.dash_threat_detail.pack(anchor="w", padx=20, pady=(10, 12))

        # Telemetry capability status indicators
        telemetry_meta_frame = ctk.CTkFrame(threat_panel, fg_color="transparent")
        telemetry_meta_frame.pack(fill="x", padx=20, pady=(0, 16))

        self.lbl_telemetry_engine = ctk.CTkLabel(
            telemetry_meta_frame,
            text="• Filesystem Watchdog: Inactive (Armed upon start)",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLOR_TEXT_DIM,
        )
        self.lbl_telemetry_engine.pack(anchor="w", pady=1)

        self.lbl_telemetry_cache = ctk.CTkLabel(
            telemetry_meta_frame,
            text="• Process Attribution: Incremental PID Scanner (<100ms)",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLOR_TEXT_DIM,
        )
        self.lbl_telemetry_cache.pack(anchor="w", pady=1)

        self.lbl_telemetry_quarantine = ctk.CTkLabel(
            telemetry_meta_frame,
            text="• Evidence Vault: SHA-256 Hashing & HTML Forensic Reports",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLOR_TEXT_DIM,
        )
        self.lbl_telemetry_quarantine.pack(anchor="w", pady=1)

        # Right: Quick Demonstration & Action Center
        actions_panel = ctk.CTkFrame(
            split_row,
            fg_color=COLOR_CARD,
            corner_radius=12,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
        )
        actions_panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        actions_title = ctk.CTkLabel(
            actions_panel,
            text="RAPID OPERATIONS",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=COLOR_ACCENT,
        )
        actions_title.pack(anchor="w", padx=20, pady=(16, 12))

        btn_deploy = ctk.CTkButton(
            actions_panel,
            text="Deploy 10 Decoy Honeypots",
            fg_color=COLOR_CARD_SUBTLE,
            hover_color=COLOR_CARD_HOVER,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
            height=36,
            corner_radius=8,
            command=self.deploy_decoys_action,
        )
        btn_deploy.pack(fill="x", padx=20, pady=4)

        btn_test = ctk.CTkButton(
            actions_panel,
            text="🧪 Launch Attack Demo",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_ACCENT_HOVER,
            height=36,
            corner_radius=8,
            command=lambda: self.switch_view("simulator"),
        )
        btn_test.pack(fill="x", padx=20, pady=4)

        btn_reports = ctk.CTkButton(
            actions_panel,
            text="📁 Open Forensics Vault",
            fg_color=COLOR_CARD_SUBTLE,
            hover_color=COLOR_CARD_HOVER,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
            height=36,
            corner_radius=8,
            command=lambda: self.switch_view("incidents"),
        )
        btn_reports.pack(fill="x", padx=20, pady=4)

        btn_presentation = ctk.CTkButton(
            actions_panel,
            text="📽️ Open Presentation",
            fg_color=COLOR_CARD_SUBTLE,
            hover_color=COLOR_CARD_HOVER,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
            height=36,
            corner_radius=8,
            command=self.open_presentation,
        )
        btn_presentation.pack(fill="x", padx=20, pady=4)

        return frame

    def _create_metric_card(self, parent, row: int, col: int, title: str, value: str, icon: str, subtitle: str) -> Dict[str, Any]:
        """Construct standardized metric card with 1px border and refined typography."""
        card = ctk.CTkFrame(
            parent,
            fg_color=COLOR_CARD,
            corner_radius=10,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
        )
        card.grid(row=row, column=col, padx=4 if 0 < col < 3 else (0 if col == 0 else (4, 0)), sticky="ew")

        header_frame = ctk.CTkFrame(card, fg_color="transparent")
        header_frame.pack(fill="x", padx=16, pady=(14, 4))

        lbl_title = ctk.CTkLabel(
            header_frame,
            text=title,
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=COLOR_TEXT_MUTED,
        )
        lbl_title.pack(side="left")

        lbl_icon = ctk.CTkLabel(header_frame, text=icon, font=ctk.CTkFont(size=14))
        lbl_icon.pack(side="right")

        lbl_val = ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=COLOR_TEXT_MAIN,
        )
        lbl_val.pack(anchor="w", padx=16, pady=(0, 2))

        lbl_sub = ctk.CTkLabel(
            card,
            text=subtitle,
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=COLOR_TEXT_DIM,
        )
        lbl_sub.pack(anchor="w", padx=16, pady=(0, 14))

        return {"card": card, "title_label": lbl_title, "value_label": lbl_val, "subtitle_label": lbl_sub}

    # =========================================================================
    # VIEW 2: DECOY VAULT
    # =========================================================================
    def _create_decoys_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # Header & Actions
        header_frame = ctk.CTkFrame(frame, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        title = ctk.CTkLabel(
            header_frame,
            text="Decoy Honeytoken Vault",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=COLOR_TEXT_MAIN,
        )
        title.pack(side="left")

        btn_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        btn_box.pack(side="right")

        btn_deploy = ctk.CTkButton(
            btn_box,
            text="Deploy / Refresh Decoys",
            fg_color=COLOR_SUCCESS,
            hover_color=COLOR_SUCCESS_HOVER,
            height=32,
            corner_radius=8,
            command=self.deploy_decoys_action,
        )
        btn_deploy.pack(side="left", padx=4)

        btn_clean = ctk.CTkButton(
            btn_box,
            text="Purge Decoys",
            fg_color=COLOR_CARD_SUBTLE,
            hover_color=COLOR_CARD_HOVER,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
            height=32,
            corner_radius=8,
            command=self.clean_decoys_action,
        )
        btn_clean.pack(side="left", padx=4)

        btn_folder = ctk.CTkButton(
            btn_box,
            text="Open Folder",
            fg_color=COLOR_CARD,
            hover_color=COLOR_CARD_HOVER,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
            height=32,
            corner_radius=8,
            command=lambda: os.startfile(TEST_SANDBOX_DIR if is_test_mode() else get_watched_directories()[0]),
        )
        btn_folder.pack(side="left", padx=4)

        desc = ctk.CTkLabel(
            frame,
            text="Strategic honeypots planted across monitored directories. High-priority alphabetical prefixes ('!', '00_', '~$') "
                 "intercept ransomware traversals early. Realistic magic byte headers deceive content inspectors.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=COLOR_TEXT_MUTED,
            justify="left",
            wraplength=880,
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 12))

        # Scrollable Decoys List
        self.decoys_scroll = ctk.CTkScrollableFrame(
            frame,
            fg_color=COLOR_CARD,
            corner_radius=10,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
        )
        self.decoys_scroll.grid(row=2, column=0, sticky="nsew")
        self.decoys_scroll.grid_columnconfigure(1, weight=1)

        return frame

    def _refresh_decoys_table(self):
        """Populate the Decoy Vault view with files from the manifest."""
        for widget in self.decoys_scroll.winfo_children():
            widget.destroy()

        manifest_paths = load_decoy_manifest()
        canaries_found = []

        for p in manifest_paths:
            norm_p = os.path.normcase(os.path.normpath(p))
            locked_variant = norm_p + ".locked"
            if os.path.isfile(locked_variant):
                canaries_found.append((os.path.basename(locked_variant), locked_variant, os.path.getsize(locked_variant), True))
            elif os.path.isfile(norm_p):
                canaries_found.append((os.path.basename(norm_p), norm_p, os.path.getsize(norm_p), False))

        if not canaries_found:
            empty_lbl = ctk.CTkLabel(
                self.decoys_scroll,
                text="No active decoy honeytokens deployed yet.\nClick 'Deploy / Refresh Decoys' above to arm the directory.",
                font=ctk.CTkFont(family="Segoe UI", size=13),
                text_color=COLOR_TEXT_MUTED,
            )
            empty_lbl.pack(pady=40)
            return

        # Table Header
        header = ctk.CTkFrame(self.decoys_scroll, fg_color=COLOR_CARD_SUBTLE, corner_radius=6, height=32)
        header.pack(fill="x", padx=6, pady=(4, 8))
        ctk.CTkLabel(header, text="Status", width=84, font=ctk.CTkFont(size=11, weight="bold"), text_color=COLOR_TEXT_MUTED).pack(side="left", padx=8)
        ctk.CTkLabel(header, text="Honeytoken Filename", font=ctk.CTkFont(size=11, weight="bold"), text_color=COLOR_TEXT_MUTED).pack(side="left", fill="x", expand=True, padx=8)
        ctk.CTkLabel(header, text="Format", width=80, font=ctk.CTkFont(size=11, weight="bold"), text_color=COLOR_TEXT_MUTED).pack(side="left", padx=8)
        ctk.CTkLabel(header, text="Strategy", width=120, font=ctk.CTkFont(size=11, weight="bold"), text_color=COLOR_TEXT_MUTED).pack(side="left", padx=8)
        ctk.CTkLabel(header, text="Size", width=70, font=ctk.CTkFont(size=11, weight="bold"), text_color=COLOR_TEXT_MUTED).pack(side="right", padx=12)

        for fname, fpath, size_bytes, is_locked in canaries_found:
            row = ctk.CTkFrame(self.decoys_scroll, fg_color="transparent")
            row.pack(fill="x", padx=6, pady=3)

            if is_locked:
                status_text = "LOCKED"
                status_color = COLOR_DANGER
            elif self.is_armed and self.observer is not None:
                status_text = "ACTIVE"
                status_color = COLOR_SUCCESS
            else:
                status_text = "PRESENT"
                status_color = COLOR_TEXT_MUTED

            badge = ctk.CTkLabel(row, text=status_text, width=84, font=ctk.CTkFont(size=10, weight="bold"), text_color=status_color)
            badge.pack(side="left", padx=8)

            name_lbl = ctk.CTkLabel(row, text=fname, anchor="w", font=ctk.CTkFont(family="Consolas", size=12), text_color=COLOR_TEXT_MAIN)
            name_lbl.pack(side="left", fill="x", expand=True, padx=8)

            ext = os.path.splitext(fname.replace(".locked", ""))[1].upper() or "DOC"
            ext_lbl = ctk.CTkLabel(row, text=ext, width=80, font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), text_color=COLOR_ACCENT)
            ext_lbl.pack(side="left", padx=8)

            strategy_lbl = ctk.CTkLabel(row, text="Early Traversal", width=120, font=ctk.CTkFont(size=10), text_color=COLOR_TEXT_DIM)
            strategy_lbl.pack(side="left", padx=8)

            size_str = f"{size_bytes} B" if size_bytes < 1024 else f"{size_bytes // 1024} KB"
            size_lbl = ctk.CTkLabel(row, text=size_str, width=70, font=ctk.CTkFont(size=11), text_color=COLOR_TEXT_MUTED)
            size_lbl.pack(side="right", padx=12)

    # =========================================================================
    # VIEW 3: THREAT FEED & LIVE CONSOLE
    # =========================================================================
    def _create_threat_feed_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # Header
        header_frame = ctk.CTkFrame(frame, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 6))

        title = ctk.CTkLabel(
            header_frame,
            text="Live Security Events & Defense Feed",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=COLOR_TEXT_MAIN,
        )
        title.pack(side="left")

        btn_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        btn_box.pack(side="right")

        self.feed_autoscroll = ctk.CTkSwitch(btn_box, text="Auto-Scroll", font=ctk.CTkFont(size=12))
        self.feed_autoscroll.select()
        self.feed_autoscroll.pack(side="left", padx=10)

        btn_clear = ctk.CTkButton(
            btn_box,
            text="Clear Feed",
            fg_color=COLOR_CARD_SUBTLE,
            hover_color=COLOR_CARD_HOVER,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
            height=30,
            corner_radius=8,
            command=self._clear_threat_feed,
        )
        btn_clear.pack(side="left", padx=4)

        # Subtitle
        sub = ctk.CTkLabel(
            frame,
            text="Real-time telemetry showing filesystem traversal interception, process attribution, containment freeze, and termination.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=COLOR_TEXT_MUTED,
        )
        sub.grid(row=1, column=0, sticky="w", pady=(0, 10))

        # Terminal Container Card
        term_card = ctk.CTkFrame(
            frame,
            fg_color=COLOR_TERMINAL_BG,
            corner_radius=10,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
        )
        term_card.grid(row=2, column=0, sticky="nsew")
        term_card.grid_rowconfigure(1, weight=1)
        term_card.grid_columnconfigure(0, weight=1)

        # Terminal Header Bar
        term_header = ctk.CTkFrame(term_card, fg_color=COLOR_CARD_SUBTLE, height=32, corner_radius=0)
        term_header.grid(row=0, column=0, sticky="ew")

        ctk.CTkLabel(
            term_header,
            text="● ● ●  EDR EVENT TELEMETRY STREAM — REAL-TIME MONITORING",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=COLOR_ACCENT,
        ).pack(side="left", padx=14, pady=6)

        # Console Textbox
        self.feed_textbox = ctk.CTkTextbox(
            term_card,
            fg_color=COLOR_TERMINAL_BG,
            text_color=COLOR_TEXT_MAIN,
            font=ctk.CTkFont(family="Consolas", size=11),
            wrap="word",
            corner_radius=0,
        )
        self.feed_textbox.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)

        # Configure color tags on underlying Tk Text widget
        self.feed_textbox._textbox.tag_config("critical", foreground="#f43f5e")
        self.feed_textbox._textbox.tag_config("warning", foreground="#fbbf24")
        self.feed_textbox._textbox.tag_config("containment", foreground="#34d399")
        self.feed_textbox._textbox.tag_config("info", foreground="#38bdf8")

        # Initial messages
        self.feed_textbox.insert("end", f"[{time.strftime('%H:%M:%S')}] [INFO] Canary Shield Console Initialized.\n", "info")
        self.feed_textbox.insert("end", f"[{time.strftime('%H:%M:%S')}] [INFO] Allowlist active: {len(get_active_allowlist())} processes protected.\n", "info")

        return frame

    def _clear_threat_feed(self):
        self.feed_textbox.delete("1.0", "end")

    # =========================================================================
    # VIEW 4: FORENSICS & INCIDENTS
    # =========================================================================
    def _create_incidents_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # Header
        header_frame = ctk.CTkFrame(frame, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 6))

        title = ctk.CTkLabel(
            header_frame,
            text="Forensic Incident Reports & Malware Quarantine",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=COLOR_TEXT_MAIN,
        )
        title.pack(side="left")

        btn_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        btn_box.pack(side="right")

        btn_refresh = ctk.CTkButton(
            btn_box,
            text="Refresh Incidents",
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_ACCENT_HOVER,
            height=32,
            corner_radius=8,
            command=self._refresh_incidents_list,
        )
        btn_refresh.pack(side="left", padx=4)

        btn_quarantine = ctk.CTkButton(
            btn_box,
            text="Open Quarantine Vault",
            fg_color=COLOR_CARD_SUBTLE,
            hover_color=COLOR_CARD_HOVER,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
            height=32,
            corner_radius=8,
            command=lambda: os.startfile(QUARANTINE_DIR),
        )
        btn_quarantine.pack(side="left", padx=4)

        desc = ctk.CTkLabel(
            frame,
            text="Automated forensic investigation records generated upon containment. Each incident contains SHA-256 binary hashing, "
                 "process tree ancestry, containment latency telemetry, and standalone visual HTML reports.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=COLOR_TEXT_MUTED,
            justify="left",
            wraplength=880,
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 12))

        # Scrollable Incident Cards List
        self.incidents_scroll = ctk.CTkScrollableFrame(frame, fg_color="transparent")
        self.incidents_scroll.grid(row=2, column=0, sticky="nsew")
        self.incidents_scroll.grid_columnconfigure(0, weight=1)

        return frame

    def _refresh_incidents_list(self):
        """Populate the Forensics view with recorded incidents."""
        for widget in self.incidents_scroll.winfo_children():
            widget.destroy()

        incidents = list_incidents()
        if not incidents:
            empty_lbl = ctk.CTkLabel(
                self.incidents_scroll,
                text="No incidents recorded yet.\nRun an attack simulation to generate live telemetry and cryptographic quarantine reports.",
                font=ctk.CTkFont(family="Segoe UI", size=13),
                text_color=COLOR_TEXT_MUTED,
            )
            empty_lbl.pack(pady=40)
            return

        for inc in incidents:
            inc_id = inc.get("incident_id", "UNKNOWN")
            proc_name = inc.get("proc_name", "unknown")
            pid = inc.get("pid", "N/A")
            latency = inc.get("latency_ms", 0.0)
            method = inc.get("method", "N/A")
            confidence = inc.get("confidence", "HIGH")
            target = inc.get("target_path", "N/A")
            quarantine = inc.get("quarantine", {})
            sha256 = quarantine.get("sha256", "N/A")

            card = ctk.CTkFrame(
                self.incidents_scroll,
                fg_color=COLOR_CARD,
                corner_radius=10,
                border_width=1,
                border_color=COLOR_CARD_BORDER,
            )
            card.pack(fill="x", pady=6)

            card_header = ctk.CTkFrame(card, fg_color="transparent")
            card_header.pack(fill="x", padx=16, pady=(12, 4))

            badge_color = COLOR_SUCCESS if confidence == "HIGH" else COLOR_WARNING
            inc_badge = ctk.CTkLabel(
                card_header,
                text=f"● {inc_id}",
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                text_color=COLOR_ACCENT,
            )
            inc_badge.pack(side="left")

            conf_badge = ctk.CTkLabel(
                card_header,
                text=f"{confidence} CONFIDENCE",
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color=badge_color,
                fg_color=COLOR_CARD_SUBTLE,
                corner_radius=6,
                padx=8,
                pady=2,
            )
            conf_badge.pack(side="right")

            # Incident Details Row
            details_frame = ctk.CTkFrame(card, fg_color="transparent")
            details_frame.pack(fill="x", padx=16, pady=4)

            p1 = ctk.CTkLabel(
                details_frame,
                text=f"Offending Process: {proc_name} (PID: {pid})   |   Latency: {latency:.2f} ms   |   Method: {method}",
                font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                text_color=COLOR_TEXT_MAIN,
            )
            p1.pack(anchor="w")

            p2 = ctk.CTkLabel(
                details_frame,
                text=f"Target Canary: {os.path.basename(target)}\nSHA-256 Quarantine Hash: {sha256}",
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=COLOR_TEXT_MUTED,
                justify="left",
            )
            p2.pack(anchor="w", pady=(4, 8))

            # Action Buttons Row
            actions_row = ctk.CTkFrame(card, fg_color="transparent")
            actions_row.pack(fill="x", padx=16, pady=(0, 12))

            html_path = os.path.join(INCIDENTS_DIR, f"{inc_id}.html")
            if os.path.exists(html_path):
                btn_html = ctk.CTkButton(
                    actions_row,
                    text="🌐 Open Visual HTML Report",
                    font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                    fg_color=COLOR_ACCENT,
                    hover_color=COLOR_ACCENT_HOVER,
                    height=28,
                    corner_radius=6,
                    command=lambda p=html_path: webbrowser.open(f"file:///{p}"),
                )
                btn_html.pack(side="left", padx=(0, 8))

            json_path = os.path.join(INCIDENTS_DIR, f"{inc_id}.json")
            if os.path.exists(json_path):
                btn_json = ctk.CTkButton(
                    actions_row,
                    text="📄 View Telemetry JSON",
                    fg_color=COLOR_CARD_SUBTLE,
                    hover_color=COLOR_CARD_HOVER,
                    border_width=1,
                    border_color=COLOR_CARD_BORDER,
                    height=28,
                    corner_radius=6,
                    command=lambda p=json_path: webbrowser.open(f"file:///{p}"),
                )
                btn_json.pack(side="left")

    # =========================================================================
    # VIEW 5: ATTACK SIMULATOR (LIVE DEMONSTRATION HARNESS)
    # =========================================================================
    def _create_simulator_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        frame.grid_rowconfigure(3, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # Header
        title = ctk.CTkLabel(
            frame,
            text="Benign Ransomware Attack Simulator",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=COLOR_TEXT_MAIN,
        )
        title.grid(row=0, column=0, sticky="w", pady=(0, 4))

        sub = ctk.CTkLabel(
            frame,
            text="Demonstration test harness that safely mimics ransomware traversal (read -> overwrite -> rename) inside test_sandbox.\n"
                 "Hard Rule 1 strictly enforces isolation from user personal files. Use this for live presentations and proof of interception.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=COLOR_TEXT_MUTED,
            justify="left",
        )
        sub.grid(row=1, column=0, sticky="w", pady=(0, 12))

        # Simulation Configuration Bar
        ctrl_card = ctk.CTkFrame(
            frame,
            fg_color=COLOR_CARD,
            corner_radius=10,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
        )
        ctrl_card.grid(row=2, column=0, sticky="ew", pady=(0, 14))

        ctrl_inner = ctk.CTkFrame(ctrl_card, fg_color="transparent")
        ctrl_inner.pack(fill="x", padx=16, pady=12)

        lbl_delay = ctk.CTkLabel(ctrl_inner, text="Traversal Delay:", font=ctk.CTkFont(size=12))
        lbl_delay.pack(side="left", padx=(0, 8))

        self.sim_delay_entry = ctk.CTkEntry(ctrl_inner, width=70, font=ctk.CTkFont(size=12))
        self.sim_delay_entry.insert(0, "0.08")
        self.sim_delay_entry.pack(side="left", padx=(0, 20))

        lbl_handle = ctk.CTkLabel(ctrl_inner, text="Hold Handle (s):", font=ctk.CTkFont(size=12))
        lbl_handle.pack(side="left", padx=(0, 8))

        self.sim_handle_entry = ctk.CTkEntry(ctrl_inner, width=70, font=ctk.CTkFont(size=12))
        self.sim_handle_entry.insert(0, "0.4")
        self.sim_handle_entry.pack(side="left", padx=(0, 20))

        self.sim_run_btn = ctk.CTkButton(
            ctrl_inner,
            text="🚀 Launch Attack Simulation",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=COLOR_DANGER,
            hover_color=COLOR_DANGER_HOVER,
            height=36,
            corner_radius=8,
            command=self.run_attack_simulation_action,
        )
        self.sim_run_btn.pack(side="right")

        # Simulator Terminal Card
        term_card = ctk.CTkFrame(
            frame,
            fg_color=COLOR_TERMINAL_BG,
            corner_radius=10,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
        )
        term_card.grid(row=3, column=0, sticky="nsew")
        term_card.grid_rowconfigure(1, weight=1)
        term_card.grid_columnconfigure(0, weight=1)

        # Simulator Terminal Header
        term_header = ctk.CTkFrame(term_card, fg_color=COLOR_CARD_SUBTLE, height=32, corner_radius=0)
        term_header.grid(row=0, column=0, sticky="ew")

        ctk.CTkLabel(
            term_header,
            text="● ● ●  SIMULATE_ATTACK.PY — TEST HARNESS SUBPROCESS CONSOLE",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=COLOR_ACCENT,
        ).pack(side="left", padx=14, pady=6)

        # Simulator Output Box
        self.sim_console = ctk.CTkTextbox(
            term_card,
            fg_color=COLOR_TERMINAL_BG,
            text_color=COLOR_TEXT_MAIN,
            font=ctk.CTkFont(family="Consolas", size=11),
            corner_radius=0,
        )
        self.sim_console.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)
        self.sim_console.insert("end", "[Simulator Ready] Click 'Launch Attack Simulation' to test live ransomware interception.\n")

        return frame

    def run_attack_simulation_action(self):
        """Execute the attack simulator asynchronously and stream output to GUI."""
        if not self.is_armed:
            self.arm_shield()

        self.sim_run_btn.configure(state="disabled", text="Attacking Sandbox...")
        self.sim_console.delete("1.0", "end")
        self.sim_console.insert("end", "=== COMMENCING BENIGN ATTACK SIMULATION ===\n\n")

        delay = self.sim_delay_entry.get().strip() or "0.08"
        hold_handle = self.sim_handle_entry.get().strip() or "0.4"

        def _run():
            if getattr(sys, "frozen", False):
                cmd = [
                    sys.executable,
                    "--run-simulator",
                    "--delay", delay,
                    "--hold-handle", hold_handle,
                ]
            else:
                cmd = [
                    sys.executable,
                    os.path.join(BASE_DIR, "simulate_attack.py"),
                    "--delay", delay,
                    "--hold-handle", hold_handle,
                ]
            env = os.environ.copy()
            env["CANARY_TEST_MODE"] = "1"
            env["PYTHONUNBUFFERED"] = "1"

            try:
                proc = subprocess.Popen(
                    cmd,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                self.sim_proc = proc
                for line in proc.stdout:
                    try:
                        self.after(0, lambda l=line: self._append_sim_output(l))
                    except Exception:
                        break

                proc.wait()
                exit_code = proc.returncode
                try:
                    self.after(0, lambda: self._on_sim_finished(exit_code))
                except Exception:
                    pass
            except Exception as exc:
                try:
                    self.after(0, lambda: self._append_sim_output(f"\n[Simulator Error] {exc}\n"))
                except Exception:
                    pass

        threading.Thread(target=_run, daemon=True).start()

    def _append_sim_output(self, line: str):
        self.sim_console.insert("end", line)
        self.sim_console.see("end")

    def _on_sim_finished(self, code: int):
        self.sim_proc = None
        self.sim_run_btn.configure(state="normal", text="🚀 Launch Attack Simulation")
        incidents = list_incidents()
        self.threats_blocked_count = len(incidents)
        self.metric_threats["value_label"].configure(text=f"{self.threats_blocked_count} Logged")

        if code != 0:
            self.sim_console.insert("end", f"\n>>> SUCCESS: Attacker Process Intercepted & Terminated! (Exit code: {code}) <<<\n")
            self.dash_threat_detail.configure(
                text="Threat Contained! Ransomware traversal neutralized.\nSimulator process stopped before genuine user files were touched.",
                text_color=COLOR_SUCCESS,
            )
        else:
            self.sim_console.insert("end", "\n[Simulator] Process finished normally.\n")

        if self.current_view_name == "incidents":
            self._refresh_incidents_list()
        elif self.current_view_name == "decoys":
            self._refresh_decoys_table()

    # =========================================================================
    # VIEW 6: SETTINGS & CONFIGURATION
    # =========================================================================
    def _create_settings_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            frame,
            text="Canary Shield Enterprise Configuration",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=COLOR_TEXT_MAIN,
        )
        title.grid(row=0, column=0, sticky="w", pady=(0, 4))

        sub = ctk.CTkLabel(
            frame,
            text="Adjust real-time deception engine parameters, defense heuristics, and directory coverage.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=COLOR_TEXT_MUTED,
        )
        sub.grid(row=1, column=0, sticky="w", pady=(0, 14))

        settings_card = ctk.CTkFrame(
            frame,
            fg_color=COLOR_CARD,
            corner_radius=10,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
        )
        settings_card.grid(row=2, column=0, sticky="ew")

        # Switches
        cfg = load_config()

        self.sw_test_mode = ctk.CTkSwitch(
            settings_card,
            text="Test Sandbox Mode (CANARY_TEST_MODE) — Enforce test_sandbox isolation",
            font=ctk.CTkFont(size=13),
            command=self._on_test_mode_toggle,
        )
        if is_test_mode():
            self.sw_test_mode.select()
        self.sw_test_mode.pack(anchor="w", padx=20, pady=(16, 10))

        self.sw_autorestore = ctk.CTkSwitch(
            settings_card,
            text="Self-Healing Tripwires — Automatically re-seed and un-lock tripped canaries",
            font=ctk.CTkFont(size=13),
        )
        if cfg.get("auto_restore_canaries", True):
            self.sw_autorestore.select()
        self.sw_autorestore.pack(anchor="w", padx=20, pady=10)

        self.sw_freeze = ctk.CTkSwitch(
            settings_card,
            text="Thread Freeze Prior to Termination — Suspend attacker threads prior to termination",
            font=ctk.CTkFont(size=13),
        )
        if cfg.get("instant_thread_freeze", True):
            self.sw_freeze.select()
        self.sw_freeze.pack(anchor="w", padx=20, pady=10)

        self.sw_tree = ctk.CTkSwitch(
            settings_card,
            text="Process Tree Termination — Terminate parent and all descendant worker processes",
            font=ctk.CTkFont(size=13),
        )
        if cfg.get("terminate_process_tree", True):
            self.sw_tree.select()
        self.sw_tree.pack(anchor="w", padx=20, pady=10)

        self.sw_quarantine = ctk.CTkSwitch(
            settings_card,
            text="Cryptographic Malware Quarantine — Vault binaries and compute SHA-256 hashes",
            font=ctk.CTkFont(size=13),
        )
        if cfg.get("quarantine_malware", True):
            self.sw_quarantine.select()
        self.sw_quarantine.pack(anchor="w", padx=20, pady=10)

        self.sw_vss = ctk.CTkSwitch(
            settings_card,
            text="Volume Shadow Copy (VSS) Guard [SYSTEM-WIDE] — Intercept backup deletion commands (scans entire machine; requires Admin)",
            font=ctk.CTkFont(size=13),
        )
        if cfg.get("vss_protection_enabled", False):
            self.sw_vss.select()
        else:
            self.sw_vss.deselect()
        self.sw_vss.pack(anchor="w", padx=20, pady=10)

        self.sw_alerts = ctk.CTkSwitch(
            settings_card,
            text="Windows Action Center Toast Notifications — Dispatch native desktop alerts",
            font=ctk.CTkFont(size=13),
        )
        if cfg.get("desktop_alerts", True):
            self.sw_alerts.select()
        self.sw_alerts.pack(anchor="w", padx=20, pady=(10, 20))

        # Save Button
        btn_save = ctk.CTkButton(
            frame,
            text="Save Configuration",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_ACCENT_HOVER,
            height=36,
            corner_radius=8,
            command=self._save_settings_action,
        )
        btn_save.grid(row=3, column=0, sticky="e", pady=16)

        return frame

    def _on_test_mode_toggle(self):
        """Validate safety when switching between Test Sandbox and Production mode."""
        if self.sw_test_mode.get() == 0:  # User un-checked Test Mode (switching to Production)
            raw_dirs = load_config().get("production_watch_directories", ["~/Documents", "~/Desktop", "~/Downloads"])
            resolved_dirs = [os.path.normpath(os.path.expanduser(d)) for d in raw_dirs]
            dir_list = "\n".join([f"  • {d}" for d in resolved_dirs])
            confirm = messagebox.askyesno(
                "Production Mode Warning",
                f"WARNING: Switching to PRODUCTION MODE will monitor live user directories:\n\n{dir_list}\n\n"
                f"Decoy files will be deployed to your real user folders and suspicious modifications "
                f"will trigger immediate process containment.\n\n"
                f"Are you sure you want to enable Production Mode?",
                default="no",
            )
            if not confirm:
                self.sw_test_mode.select()

    def _save_settings_action(self):
        """Persist settings to canary_shield_config.json."""
        cfg = load_config()
        cfg["mode"] = "test" if self.sw_test_mode.get() == 1 else "production"
        cfg["auto_restore_canaries"] = bool(self.sw_autorestore.get())
        cfg["instant_thread_freeze"] = bool(self.sw_freeze.get())
        cfg["terminate_process_tree"] = bool(self.sw_tree.get())
        cfg["quarantine_malware"] = bool(self.sw_quarantine.get())
        cfg["vss_protection_enabled"] = bool(self.sw_vss.get())
        cfg["desktop_alerts"] = bool(self.sw_alerts.get())

        try:
            with open(CONFIG_FILE_PATH, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            self.log_queue.put(("INFO", "Configuration successfully saved to canary_shield_config.json"))
            self.sidebar_mode_badge.configure(
                text=f"● {'TEST SANDBOX' if cfg['mode'] == 'test' else 'PRODUCTION'}",
                text_color=COLOR_WARNING if cfg["mode"] == "test" else COLOR_ACCENT,
            )
        except Exception as exc:
            self.log_queue.put(("ERROR", f"Failed to save configuration: {exc}"))

    # =========================================================================
    # ENGINE CONTROLS (ARM / DISARM / DECOYS)
    # =========================================================================
    def toggle_shield(self):
        """Toggle Shield state between Armed and Disarmed."""
        if self.is_armed:
            self.disarm_shield()
        else:
            self.arm_shield()

    def arm_shield(self):
        """Deploy decoys and activate real-time monitoring and VSS guard."""
        if self.is_armed:
            return

        if not is_test_mode():
            watched = get_watched_directories()
            dir_list = "\n".join([f"  • {d}" for d in watched])
            confirm = messagebox.askyesno(
                "Confirm Production Arming",
                f"CAUTION: Canary Shield is about to ARM in PRODUCTION MODE.\n\n"
                f"Monitored directories:\n{dir_list}\n\n"
                f"Real canary honeytokens will be deployed to your system folders. "
                f"Do you want to proceed with arming in Production Mode?",
                default="no",
            )
            if not confirm:
                return

        def _worker():
            try:
                self.log_queue.put(("INFO", "Arming Canary Shield: Planting honeytokens across monitored paths..."))
                canaries = deploy_decoys()
                self.active_canaries = canaries

                self.observer, self.vss_guard = start_monitoring(canaries, block=False)
                self.is_armed = True

                self.after(0, self._on_shield_armed)
            except Exception as exc:
                self.log_queue.put(("CRITICAL", f"Failed to arm Canary Shield: {exc}"))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_shield_armed(self):
        self.dash_status_badge.configure(text="● ACTIVE SHIELD PROTECTING — ENDPOINTS ARMED", text_color=COLOR_SUCCESS)
        self.dash_arm_button.configure(text="DISARM SHIELD", fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER)
        self.sidebar_shield_badge.configure(text="● SHIELD ARMED", text_color=COLOR_SUCCESS)
        self.metric_decoys["value_label"].configure(text=f"{len(self.active_canaries)} Active")
        self.dash_threat_detail.configure(
            text="System Protected — Watching file traversals in real-time.\nAll tripwires active. No unauthorized tampering detected.",
            text_color=COLOR_TEXT_MAIN,
        )
        self.lbl_telemetry_engine.configure(
            text="• Filesystem Watchdog: Active (Native ReadDirectoryChangesW)",
            text_color=COLOR_SUCCESS,
        )
        self.log_queue.put(("INFO", f"Canary Shield successfully ARMED. {len(self.active_canaries)} tripwires active."))

    def disarm_shield(self):
        """Stop observer and VSS guard."""
        if not self.is_armed:
            return

        def _worker():
            try:
                if self.vss_guard:
                    self.vss_guard.stop()
                    self.vss_guard = None
                if self.observer:
                    self.observer.stop()
                    self.observer.join(timeout=3.0)
                    self.observer = None
                try:
                    from process_id import stop_process_cache
                    stop_process_cache()
                except Exception:
                    pass

                self.is_armed = False
                self.after(0, self._on_shield_disarmed)
            except Exception as exc:
                self.log_queue.put(("WARNING", f"Error while disarming: {exc}"))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_shield_disarmed(self):
        self.dash_status_badge.configure(text="○ SHIELD DISARMED — PROTECTION STANDBY", text_color=COLOR_TEXT_MUTED)
        self.dash_arm_button.configure(text="ARM SHIELD", fg_color=COLOR_SUCCESS, hover_color=COLOR_SUCCESS_HOVER)
        self.sidebar_shield_badge.configure(text="○ SHIELD DISARMED", text_color=COLOR_TEXT_MUTED)
        manifest_count = len(load_decoy_manifest())
        self.metric_decoys["value_label"].configure(text=f"{manifest_count} Present")
        self.dash_threat_detail.configure(
            text="Standby — shield is disarmed. Press ARM SHIELD to deploy active filesystem monitoring.",
            text_color=COLOR_TEXT_MUTED,
        )
        self.lbl_telemetry_engine.configure(
            text="• Filesystem Watchdog: Inactive (Armed upon start)",
            text_color=COLOR_TEXT_DIM,
        )
        self.log_queue.put(("INFO", "Canary Shield DISARMED."))

    def deploy_decoys_action(self):
        """Deploy honeytoken files."""
        def _worker():
            paths = deploy_decoys()
            self.active_canaries = paths
            count_text = f"{len(paths)} Active" if (self.is_armed and self.observer is not None) else f"{len(paths)} Present"
            self.after(0, lambda: self.metric_decoys["value_label"].configure(text=count_text))
            self.after(0, self._refresh_decoys_table)
            self.log_queue.put(("INFO", f"Deployed {len(paths)} canary honeytokens."))
        threading.Thread(target=_worker, daemon=True).start()

    def clean_decoys_action(self):
        """Safely remove honeytokens."""
        if self.is_armed:
            self.disarm_shield()

        def _worker():
            cleaned = cleanup_decoys()
            self.active_canaries = []
            self.after(0, lambda: self.metric_decoys["value_label"].configure(text="0 Present"))
            self.after(0, self._refresh_decoys_table)
            self.log_queue.put(("INFO", f"Safely purged {cleaned} decoy honeytokens from manifest."))
        threading.Thread(target=_worker, daemon=True).start()

    # =========================================================================
    # EVENT LOOP & BACKGROUND QUEUE POLLING
    # =========================================================================
    def _poll_log_queue(self):
        """Drain background log messages and render them in the Threat Feed."""
        try:
            while not self.log_queue.empty():
                level, msg = self.log_queue.get_nowait()
                self._append_feed_message(level, msg)
        except Exception:
            pass
        self.after(150, self._poll_log_queue)

    def _append_feed_message(self, level: str, msg: str):
        """Format and append a log entry into the feed with configured severity tag."""
        if not hasattr(self, "feed_textbox"):
            return

        tag = "info"
        prefix = f"[{time.strftime('%H:%M:%S')}] [{level}] "

        if "CONTAINMENT SUCCESS" in msg or "Process Terminated" in msg or "CONTAINMENT ACTIVE" in msg or "Threat Contained" in msg or "neutralized" in msg.lower():
            tag = "containment"
            self.threats_blocked_count = len(list_incidents())
            self.metric_threats["value_label"].configure(text=f"{self.threats_blocked_count} Logged")
        elif level == "CRITICAL" or "TRIPWIRE TRIGGERED" in msg or "ALERT" in msg:
            tag = "critical"
        elif level == "WARNING" or "WARN" in msg:
            tag = "warning"
        elif level == "INFO":
            tag = "info"

        self.feed_textbox.insert("end", f"{prefix}{msg}\n", tag)
        if self.feed_autoscroll.get():
            self.feed_textbox.see("end")

    def _refresh_system_status(self):
        """Read existing environment and sandbox on startup."""
        manifest_paths = load_decoy_manifest()
        present = [
            p for p in manifest_paths
            if os.path.isfile(p) or os.path.isfile(p + ".locked")
        ]
        count = len(present)
        if self.is_armed and self.observer is not None:
            self.metric_decoys["value_label"].configure(text=f"{count} Active")
        else:
            self.metric_decoys["value_label"].configure(text=f"{count} Present")

        incidents = list_incidents()
        self.threats_blocked_count = len(incidents)
        self.metric_threats["value_label"].configure(text=f"{len(incidents)} Logged")

    def _on_close(self):
        """Clean and safe shutdown when user closes window."""
        if self.is_armed:
            confirm = messagebox.askyesno(
                "Exit Confirmation",
                "Protection is active. Disarm and exit?",
                default="no",
            )
            if not confirm:
                return

        try:
            # 1. Terminate running simulator subprocess if any
            if hasattr(self, "sim_proc") and self.sim_proc is not None:
                try:
                    if self.sim_proc.poll() is None:
                        self.sim_proc.terminate()
                        try:
                            self.sim_proc.wait(timeout=1.0)
                        except Exception:
                            self.sim_proc.kill()
                except Exception:
                    pass
                self.sim_proc = None

            # 2. Stop VSS Guard
            if hasattr(self, "vss_guard") and self.vss_guard is not None:
                try:
                    self.vss_guard.stop()
                except Exception:
                    pass
                self.vss_guard = None

            # 3. Stop watchdog observer & incremental process cache
            if hasattr(self, "observer") and self.observer is not None:
                try:
                    self.observer.stop()
                    self.observer.join(timeout=3.0)
                except Exception:
                    pass
                self.observer = None

            try:
                from process_id import stop_process_cache
                stop_process_cache()
            except Exception:
                pass

            # 4. Stop self-healing thread if tracked
            if hasattr(self, "self_healing_thread") and self.self_healing_thread is not None:
                try:
                    if hasattr(self.self_healing_thread, "stop"):
                        self.self_healing_thread.stop()
                except Exception:
                    pass
                self.self_healing_thread = None

            # 5. Destroy slideshow window if open
            if hasattr(self, "presentation_window") and self.presentation_window is not None:
                try:
                    self.presentation_window.destroy()
                except Exception:
                    pass
                self.presentation_window = None

            self.is_armed = False
        finally:
            self.destroy()


def is_admin() -> bool:
    """Check if the current process has administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def request_admin_elevation() -> bool:
    """
    Relaunch current script or executable with elevated Administrator privileges via UAC prompt.
    Returns True if already running as Administrator.
    If elevation requested and user approved, exits the unelevated process.
    """
    if is_admin():
        return True

    if sys.platform != "win32":
        return True

    if getattr(sys, "frozen", False):
        executable = sys.executable
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    else:
        executable = sys.executable
        params = " ".join([f'"{arg}"' for arg in sys.argv])

    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            executable,
            params,
            os.getcwd(),
            1  # SW_SHOWNORMAL
        )
        if int(ret) > 32:
            sys.exit(0)
    except Exception as exc:
        logging.getLogger("canary_shield.app").warning("Elevation request failed: %s", exc)

    return False


def main():
    """Launch the Canary Shield Desktop Application or hidden subcommands."""
    if "--run-simulator" in sys.argv:
        sim_args = [a for a in sys.argv[1:] if a != "--run-simulator"]
        import simulate_attack
        simulate_attack.main(sim_args)
        sys.exit(0)

    request_admin_elevation()
    app = CanaryShieldApp()
    app.mainloop()


if __name__ == "__main__":
    main()
