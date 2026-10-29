import os
import sys
import tkinter as tk
import customtkinter as ctk
from typing import Optional, Dict, Any, List

# =========================================================================
# CONFIGURATION & CONSTANTS
# =========================================================================
PRESENTER_NAME = "Shreya"

def resource_path(relative_path: str) -> str:
    """Get absolute path to resource, works for dev and for PyInstaller bundle."""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(base_path, relative_path)

# Theme color palette matching Canary Shield UI
COLOR_BG = "#0b1120"
COLOR_HEADER = "#0f172a"
COLOR_CARD = "#1e293b"
COLOR_CARD_BORDER = "#334155"
COLOR_ACCENT = "#38bdf8"
COLOR_ACCENT_HOVER = "#0284c7"
COLOR_YELLOW = "#facc15"
COLOR_GREEN = "#10b981"
COLOR_RED = "#f87171"
COLOR_TEXT_MAIN = "#f8fafc"
COLOR_TEXT_MUTED = "#94a3b8"

# =========================================================================
# SLIDES DATA STRUCTURE (Edit slide text directly here)
# =========================================================================
SLIDES: List[Dict[str, Any]] = [
    {
        "id": 1,
        "type": "title",
        "title": "Canary Shield",
        "subtitle": "Deception-based ransomware defense for Windows",
        "footer_left": PRESENTER_NAME,
        "footer_right": "Capstone prototype",
    },
    {
        "id": 2,
        "type": "problem",
        "title": "The Problem",
        "bullets": [
            "Ransomware is a program that locks your files and demands money to give them back.",
            "Most antivirus tools stop it by recognizing viruses they have already seen.",
            "A brand-new ransomware has no known signature, so it can slip past and start locking files.",
            "Once it starts, a lot of damage can happen in seconds.",
        ],
        "highlight": "How do we catch ransomware we have never seen before?",
    },
    {
        "id": 3,
        "type": "solution",
        "title": "Proposed Solution: catch it by what it does, not what it looks like",
        "steps": [
            ("1 PLANT", "hidden decoy files with tempting names (like \"passwords\" or \"financial records\") that no normal user touches."),
            ("2 WATCH", "a file monitor raises an alert the moment a decoy is touched."),
            ("3 IDENTIFY", "find which running program did it."),
            ("4 CONTAIN", "freeze it, then stop it."),
            ("5 REPORT", "keep evidence: quarantined copy, SHA-256 fingerprint, incident report."),
        ],
        "safety_strip": "Runs in a sandbox. 140 core Windows processes are protected and can never be stopped.",
    },
    {
        "id": 4,
        "type": "objectives",
        "title": "Objectives (SMART)",
        "cards": [
            {
                "num": "1",
                "heading": "Contain fast",
                "goal": "stop a simulated ransomware process in under 1 second.",
                "measure": "time from tripwire to termination over 5 consecutive test runs.",
                "result": "median about 260 ms, worst run about 950 ms.",
                "deadline": "Deadline: prototype submission",
            },
            {
                "num": "2",
                "heading": "Protect user data",
                "goal": "lose no genuine user files.",
                "measure": "user files surviving in each of 5 test runs.",
                "result": "5 of 5 files survived in 5 of 5 runs.",
                "deadline": "Deadline: prototype submission",
            },
            {
                "num": "3",
                "heading": "Leave evidence",
                "goal": "a forensic report for every contained incident.",
                "measure": "reports (JSON and HTML with SHA-256) generated per incident.",
                "result": "one report per incident in every run.",
                "deadline": "Deadline: prototype submission",
            },
        ],
        "footnote": "Measured with the bundled benign simulator, in a sandbox, on one Windows machine, test mode.",
    },
    {
        "id": 5,
        "type": "architecture",
        "title": "System Architecture",
    },
    {
        "id": 6,
        "type": "milestones",
        "title": "Next Milestones",
        "milestones": [
            "1. Test against more realistic ransomware behaviour (fast open-encrypt-close, several processes) and report accuracy honestly.",
            "2. Use Windows kernel-level tracing (ETW) for more reliable attribution than the current heuristic.",
            "3. Run as a protected Windows service so malware cannot easily switch it off.",
            "4. Test for false alarms with backup and search-indexing tools.",
            "5. Stretch goal: a central dashboard that collects alerts from many machines.",
        ],
    },
]


class PresentationWindow(ctk.CTkToplevel):
    """Full-screen in-app presentation window with projector-readable slides."""

    def __init__(self, master=None):
        super().__init__(master)
        self.master_app = master
        self.title("Canary Shield — Presentation")
        self.configure(fg_color=COLOR_BG)

        self.current_index = 0
        self.is_fullscreen = False
        self._last_dims = (0, 0)
        self._resize_scheduled = False

        # Set window icon after 250ms (CTkToplevel overrides iconbitmap)
        self.after(250, self._set_icon)

        # Initial geometry: clamped to screen, start maximized / zoomed
        self._init_window_geometry()

        # Keyboard bindings
        self._bind_keys()

        # Window close handler
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Construct basic scaffolding
        self._build_ui()

        # Bring window to front
        self.focus_window()

        # Render initial slide
        self._render_current_slide()

        # Listen to resize events
        self.bind("<Configure>", self._on_window_configure)

    def _set_icon(self):
        """Set window icon from resource path."""
        try:
            ico_file = resource_path(os.path.join("assets", "canary_shield.ico"))
            if os.path.exists(ico_file):
                self.iconbitmap(ico_file)
        except Exception:
            pass

    def _init_window_geometry(self):
        """Set initial geometry clamped to screen bounds, start zoomed/maximized."""
        try:
            sw = self.winfo_screenwidth()
            sh = self.winfo_screenheight()
            w = max(1024, min(1600, sw - 80))
            h = max(600, min(900, sh - 80))
            self.geometry(f"{w}x{h}+40+20")
            self.minsize(1024, 600)
            self.state("zoomed")
        except Exception:
            self.geometry("1280x720+40+20")

    def _bind_keys(self):
        """Bind presentation control hotkeys."""
        self.bind("<Right>", lambda e: self.next_slide())
        self.bind("<space>", lambda e: self.next_slide())
        self.bind("<Next>", lambda e: self.next_slide())      # Page Down
        self.bind("<Left>", lambda e: self.prev_slide())
        self.bind("<Prior>", lambda e: self.prev_slide())     # Page Up
        self.bind("<Home>", lambda e: self.go_to_slide(0))
        self.bind("<End>", lambda e: self.go_to_slide(len(SLIDES) - 1))
        self.bind("<F11>", self.toggle_fullscreen)
        self.bind("<f>", self.toggle_fullscreen)
        self.bind("<F>", self.toggle_fullscreen)
        self.bind("<Escape>", self.handle_escape)

    def focus_window(self):
        """Bring window to front reliably on Windows."""
        try:
            self.deiconify()
            self.lift()
            self.attributes("-topmost", True)
            self.after(50, lambda: self.attributes("-topmost", False))
            self.focus_force()
        except Exception:
            pass

    def toggle_fullscreen(self, event=None):
        """Toggle fullscreen mode."""
        self.is_fullscreen = not self.is_fullscreen
        self.attributes("-fullscreen", self.is_fullscreen)
        self.after(50, self._render_current_slide)

    def handle_escape(self, event=None):
        """Escape leaves fullscreen, or closes window if not in fullscreen."""
        if self.is_fullscreen:
            self.is_fullscreen = False
            self.attributes("-fullscreen", False)
            self.after(50, self._render_current_slide)
        else:
            self._on_close()

    def _on_close(self):
        """Safely destroy presentation window and reset parent reference."""
        try:
            if self.master_app and hasattr(self.master_app, "presentation_window"):
                self.master_app.presentation_window = None
        except Exception:
            pass
        self.destroy()

    def _build_ui(self):
        """Create main layout frames."""
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_columnconfigure(0, weight=1)

        # Slide content area
        self.slide_container = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        self.slide_container.grid(row=0, column=0, sticky="nsew", padx=24, pady=(16, 8))

        # Bottom control bar
        self.nav_bar = ctk.CTkFrame(self, fg_color=COLOR_HEADER, height=54, corner_radius=0)
        self.nav_bar.grid(row=1, column=0, sticky="ew")
        self.nav_bar.grid_columnconfigure(1, weight=1)

        # Prev button
        self.btn_prev = ctk.CTkButton(
            self.nav_bar,
            text="◀ Prev",
            width=90,
            height=34,
            fg_color=COLOR_CARD,
            hover_color=COLOR_CARD_BORDER,
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            command=self.prev_slide,
        )
        self.btn_prev.pack(side="left", padx=20, pady=10)

        # Dots container
        self.dots_frame = ctk.CTkFrame(self.nav_bar, fg_color="transparent")
        self.dots_frame.pack(side="left", padx=10, pady=10)

        self.dot_indicators = []
        for i in range(len(SLIDES)):
            dot = ctk.CTkButton(
                self.dots_frame,
                text="",
                width=12,
                height=12,
                corner_radius=6,
                fg_color=COLOR_CARD_BORDER,
                hover_color=COLOR_ACCENT,
                command=lambda idx=i: self.go_to_slide(idx),
            )
            dot.pack(side="left", padx=4)
            self.dot_indicators.append(dot)

        # Slide counter
        self.counter_label = ctk.CTkLabel(
            self.nav_bar,
            text="1 / 6",
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            text_color=COLOR_TEXT_MUTED,
        )
        self.counter_label.pack(side="left", padx=15)

        # Next button
        self.btn_next = ctk.CTkButton(
            self.nav_bar,
            text="Next ▶",
            width=90,
            height=34,
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_ACCENT_HOVER,
            text_color="#0f172a",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            command=self.next_slide,
        )
        self.btn_next.pack(side="left", padx=10, pady=10)

        # Optional Live Demo button on last slide
        self.btn_demo = ctk.CTkButton(
            self.nav_bar,
            text="🚀 Live Demo",
            width=110,
            height=34,
            fg_color=COLOR_GREEN,
            hover_color="#059669",
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            command=self.launch_live_demo,
        )

        # Fullscreen hint on right
        self.hint_label = ctk.CTkLabel(
            self.nav_bar,
            text="F11: Fullscreen | Esc: Close",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=COLOR_TEXT_MUTED,
        )
        self.hint_label.pack(side="right", padx=20)

    def _on_window_configure(self, event):
        """Handle window resize without repeating timers or background threads."""
        if event.widget != self:
            return
        w, h = event.width, event.height
        if abs(w - self._last_dims[0]) > 25 or abs(h - self._last_dims[1]) > 25:
            self._last_dims = (w, h)
            self._render_current_slide()

    def go_to_slide(self, index: int):
        """Jump to specific slide index."""
        if 0 <= index < len(SLIDES):
            self.current_index = index
            self._render_current_slide()

    def next_slide(self):
        """Advance to next slide."""
        if self.current_index < len(SLIDES) - 1:
            self.current_index += 1
            self._render_current_slide()

    def prev_slide(self):
        """Go back to previous slide."""
        if self.current_index > 0:
            self.current_index -= 1
            self._render_current_slide()

    def launch_live_demo(self):
        """Close presentation and switch main app to Attack Simulator view."""
        self._on_close()
        try:
            if self.master_app and hasattr(self.master_app, "switch_view"):
                self.master_app.switch_view("simulator")
        except Exception:
            pass

    def _calc_font_sizes(self):
        """Calculate projector-readable font sizes scaled with height, never below minimums."""
        h = max(600, self.winfo_height())
        # Enforce strict minimums: title >= 40 pt, body >= 22 pt
        title_pt = max(40, int(h * 0.048))
        body_pt = max(22, int(h * 0.024))
        sub_pt = max(24, int(h * 0.028))
        small_pt = max(16, int(h * 0.018))
        return title_pt, body_pt, sub_pt, small_pt

    def _render_current_slide(self):
        """Clear and redraw active slide."""
        # Update counter & progress dots
        self.counter_label.configure(text=f"{self.current_index + 1} / {len(SLIDES)}")
        for i, dot in enumerate(self.dot_indicators):
            if i == self.current_index:
                dot.configure(fg_color=COLOR_ACCENT)
            else:
                dot.configure(fg_color=COLOR_CARD_BORDER)

        # Update Prev/Next button states
        self.btn_prev.configure(state="normal" if self.current_index > 0 else "disabled")
        if self.current_index == len(SLIDES) - 1:
            self.btn_next.configure(state="disabled")
            if not self.btn_demo.winfo_ismapped():
                self.btn_demo.pack(side="left", padx=10, pady=10)
        else:
            self.btn_next.configure(state="normal")
            if self.btn_demo.winfo_ismapped():
                self.btn_demo.pack_forget()

        # Clear container
        for widget in self.slide_container.winfo_children():
            widget.destroy()

        slide_data = SLIDES[self.current_index]
        slide_type = slide_data.get("type")

        w = max(1024, self.winfo_width())
        wrap_width = max(600, w - 120)
        title_pt, body_pt, sub_pt, small_pt = self._calc_font_sizes()

        if slide_type == "title":
            self._render_title_slide(slide_data, wrap_width, title_pt, body_pt, sub_pt)
        elif slide_type == "problem":
            self._render_problem_slide(slide_data, wrap_width, title_pt, body_pt, sub_pt)
        elif slide_type == "solution":
            self._render_solution_slide(slide_data, wrap_width, title_pt, body_pt, sub_pt)
        elif slide_type == "objectives":
            self._render_objectives_slide(slide_data, wrap_width, title_pt, body_pt, sub_pt, small_pt)
        elif slide_type == "architecture":
            self._render_architecture_slide(slide_data, title_pt)
        elif slide_type == "milestones":
            self._render_milestones_slide(slide_data, wrap_width, title_pt, body_pt, sub_pt)

    # ---------------------------------------------------------------------
    # SLIDE 1: TITLE
    # ---------------------------------------------------------------------
    def _render_title_slide(self, data, wrap_w, title_pt, body_pt, sub_pt):
        center_frame = ctk.CTkFrame(self.slide_container, fg_color="transparent")
        center_frame.pack(expand=True, fill="both")

        inner = ctk.CTkFrame(center_frame, fg_color=COLOR_CARD, corner_radius=16, border_width=1, border_color=COLOR_CARD_BORDER)
        inner.pack(expand=True, padx=40, pady=30, fill="both")

        # Shield icon banner
        lbl_icon = ctk.CTkLabel(
            inner,
            text="🛡️",
            font=ctk.CTkFont(size=int(title_pt * 1.4)),
        )
        lbl_icon.pack(pady=(40, 10))

        # Title: "Canary Shield"
        lbl_title = ctk.CTkLabel(
            inner,
            text=data["title"],
            font=ctk.CTkFont(family="Segoe UI", size=int(title_pt * 1.3), weight="bold"),
            text_color=COLOR_ACCENT,
        )
        lbl_title.pack(pady=(0, 10))

        # Subtitle: "Deception-based ransomware defense for Windows"
        lbl_sub = ctk.CTkLabel(
            inner,
            text=data["subtitle"],
            font=ctk.CTkFont(family="Segoe UI", size=sub_pt),
            text_color=COLOR_TEXT_MAIN,
            wraplength=wrap_w - 100,
        )
        lbl_sub.pack(pady=(0, 30))

        # Footer strip
        footer_frame = ctk.CTkFrame(inner, fg_color="transparent")
        footer_frame.pack(side="bottom", fill="x", padx=40, pady=25)

        lbl_footer_left = ctk.CTkLabel(
            footer_frame,
            text=f"Presenter: {data['footer_left']}",
            font=ctk.CTkFont(family="Segoe UI", size=body_pt, weight="bold"),
            text_color=COLOR_YELLOW,
        )
        lbl_footer_left.pack(side="left")

        lbl_footer_right = ctk.CTkLabel(
            footer_frame,
            text=data["footer_right"],
            font=ctk.CTkFont(family="Segoe UI", size=body_pt),
            text_color=COLOR_TEXT_MUTED,
        )
        lbl_footer_right.pack(side="right")

    # ---------------------------------------------------------------------
    # SLIDE 2: THE PROBLEM
    # ---------------------------------------------------------------------
    def _render_problem_slide(self, data, wrap_w, title_pt, body_pt, sub_pt):
        # Title
        lbl_title = ctk.CTkLabel(
            self.slide_container,
            text=data["title"],
            font=ctk.CTkFont(family="Segoe UI", size=title_pt, weight="bold"),
            text_color=COLOR_ACCENT,
            anchor="w",
        )
        lbl_title.pack(fill="x", pady=(10, 16))

        # Content card
        card = ctk.CTkFrame(self.slide_container, fg_color=COLOR_CARD, corner_radius=12, border_width=1, border_color=COLOR_CARD_BORDER)
        card.pack(fill="both", expand=True, padx=4, pady=4)

        bullets_frame = ctk.CTkFrame(card, fg_color="transparent")
        bullets_frame.pack(fill="both", expand=True, padx=30, pady=20)

        for text in data["bullets"]:
            row = ctk.CTkFrame(bullets_frame, fg_color="transparent")
            row.pack(fill="x", pady=8, anchor="w")

            dot = ctk.CTkLabel(
                row,
                text="⚠️",
                font=ctk.CTkFont(size=int(body_pt * 0.9)),
                width=30,
            )
            dot.pack(side="left", anchor="n", padx=(0, 12))

            msg = ctk.CTkLabel(
                row,
                text=text,
                font=ctk.CTkFont(family="Segoe UI", size=body_pt),
                text_color=COLOR_TEXT_MAIN,
                justify="left",
                wraplength=wrap_w - 120,
                anchor="w",
            )
            msg.pack(side="left", fill="x", expand=True)

        # Highlight callout box
        hl_frame = ctk.CTkFrame(card, fg_color="#0f172a", corner_radius=8, border_width=1, border_color=COLOR_YELLOW)
        hl_frame.pack(fill="x", padx=30, pady=(10, 20))

        lbl_hl = ctk.CTkLabel(
            hl_frame,
            text=f"👉  {data['highlight']}",
            font=ctk.CTkFont(family="Segoe UI", size=sub_pt, weight="bold"),
            text_color=COLOR_YELLOW,
            justify="center",
            wraplength=wrap_w - 140,
        )
        lbl_hl.pack(padx=20, pady=14)

    # ---------------------------------------------------------------------
    # SLIDE 3: PROPOSED SOLUTION
    # ---------------------------------------------------------------------
    def _render_solution_slide(self, data, wrap_w, title_pt, body_pt, sub_pt):
        # Title
        lbl_title = ctk.CTkLabel(
            self.slide_container,
            text=data["title"],
            font=ctk.CTkFont(family="Segoe UI", size=title_pt, weight="bold"),
            text_color=COLOR_ACCENT,
            anchor="w",
            wraplength=wrap_w,
            justify="left",
        )
        lbl_title.pack(fill="x", pady=(10, 12))

        # Main 5-step flow container
        card = ctk.CTkFrame(self.slide_container, fg_color=COLOR_CARD, corner_radius=12, border_width=1, border_color=COLOR_CARD_BORDER)
        card.pack(fill="both", expand=True, padx=4, pady=(0, 8))

        steps_frame = ctk.CTkFrame(card, fg_color="transparent")
        steps_frame.pack(fill="both", expand=True, padx=24, pady=12)

        step_colors = [COLOR_YELLOW, COLOR_ACCENT, "#38bdf8", COLOR_RED, COLOR_GREEN]

        for i, (tag, desc) in enumerate(data["steps"]):
            row = ctk.CTkFrame(steps_frame, fg_color="transparent")
            row.pack(fill="x", pady=4, anchor="w")

            tag_badge = ctk.CTkLabel(
                row,
                text=tag,
                font=ctk.CTkFont(family="Segoe UI", size=body_pt, weight="bold"),
                text_color=step_colors[i % len(step_colors)],
                width=140,
                anchor="w",
            )
            tag_badge.pack(side="left", padx=(0, 12), anchor="n")

            arrow_lbl = ctk.CTkLabel(
                row,
                text="—",
                font=ctk.CTkFont(family="Segoe UI", size=body_pt, weight="bold"),
                text_color=COLOR_TEXT_MUTED,
            )
            arrow_lbl.pack(side="left", padx=(0, 12), anchor="n")

            desc_lbl = ctk.CTkLabel(
                row,
                text=desc,
                font=ctk.CTkFont(family="Segoe UI", size=body_pt),
                text_color=COLOR_TEXT_MAIN,
                justify="left",
                wraplength=wrap_w - 240,
                anchor="w",
            )
            desc_lbl.pack(side="left", fill="x", expand=True)

        # Safety strip at bottom
        safety_card = ctk.CTkFrame(self.slide_container, fg_color="#0f172a", corner_radius=8, border_width=1, border_color=COLOR_GREEN)
        safety_card.pack(fill="x", padx=4, pady=(4, 0))

        lbl_safety = ctk.CTkLabel(
            safety_card,
            text=f"🛡️  {data['safety_strip']}",
            font=ctk.CTkFont(family="Segoe UI", size=int(body_pt * 0.95), weight="bold"),
            text_color=COLOR_GREEN,
            justify="center",
            wraplength=wrap_w - 80,
        )
        lbl_safety.pack(padx=20, pady=10)

    # ---------------------------------------------------------------------
    # SLIDE 4: OBJECTIVES (SMART)
    # ---------------------------------------------------------------------
    def _render_objectives_slide(self, data, wrap_w, title_pt, body_pt, sub_pt, small_pt):
        # Title
        lbl_title = ctk.CTkLabel(
            self.slide_container,
            text=data["title"],
            font=ctk.CTkFont(family="Segoe UI", size=title_pt, weight="bold"),
            text_color=COLOR_ACCENT,
            anchor="w",
        )
        lbl_title.pack(fill="x", pady=(10, 12))

        # Three cards row
        cards_row = ctk.CTkFrame(self.slide_container, fg_color="transparent")
        cards_row.pack(fill="both", expand=True, padx=4, pady=4)
        cards_row.grid_columnconfigure((0, 1, 2), weight=1)
        cards_row.grid_rowconfigure(0, weight=1)

        card_accent_colors = [COLOR_ACCENT, COLOR_GREEN, COLOR_YELLOW]

        card_width_approx = max(260, int((wrap_w - 60) / 3))

        for col, card_data in enumerate(data["cards"]):
            c_frame = ctk.CTkFrame(
                cards_row,
                fg_color=COLOR_CARD,
                corner_radius=12,
                border_width=1,
                border_color=COLOR_CARD_BORDER,
            )
            c_frame.grid(row=0, column=col, padx=8, pady=4, sticky="nsew")

            accent_color = card_accent_colors[col % len(card_accent_colors)]

            # Header
            lbl_num = ctk.CTkLabel(
                c_frame,
                text=f"{card_data['num']}. {card_data['heading']}",
                font=ctk.CTkFont(family="Segoe UI", size=sub_pt, weight="bold"),
                text_color=accent_color,
                anchor="w",
                justify="left",
                wraplength=card_width_approx - 30,
            )
            lbl_num.pack(padx=16, pady=(16, 8), fill="x")

            # Goal
            lbl_goal = ctk.CTkLabel(
                c_frame,
                text=f"Goal: {card_data['goal']}",
                font=ctk.CTkFont(family="Segoe UI", size=body_pt),
                text_color=COLOR_TEXT_MAIN,
                anchor="w",
                justify="left",
                wraplength=card_width_approx - 30,
            )
            lbl_goal.pack(padx=16, pady=4, fill="x")

            # Measure
            lbl_measure = ctk.CTkLabel(
                c_frame,
                text=f"Measure: {card_data['measure']}",
                font=ctk.CTkFont(family="Segoe UI", size=body_pt),
                text_color=COLOR_TEXT_MUTED,
                anchor="w",
                justify="left",
                wraplength=card_width_approx - 30,
            )
            lbl_measure.pack(padx=16, pady=4, fill="x")

            # Result
            lbl_result = ctk.CTkLabel(
                c_frame,
                text=f"Result: {card_data['result']}",
                font=ctk.CTkFont(family="Segoe UI", size=body_pt, weight="bold"),
                text_color=accent_color,
                anchor="w",
                justify="left",
                wraplength=card_width_approx - 30,
            )
            lbl_result.pack(padx=16, pady=6, fill="x")

            # Deadline footer
            lbl_deadline = ctk.CTkLabel(
                c_frame,
                text=card_data["deadline"],
                font=ctk.CTkFont(family="Segoe UI", size=small_pt),
                text_color=COLOR_TEXT_MUTED,
                anchor="w",
            )
            lbl_deadline.pack(side="bottom", padx=16, pady=12, fill="x")

        # Small footnote
        lbl_footnote = ctk.CTkLabel(
            self.slide_container,
            text=f"*{data['footnote']}",
            font=ctk.CTkFont(family="Segoe UI", size=small_pt, slant="italic"),
            text_color=COLOR_TEXT_MUTED,
            anchor="w",
            wraplength=wrap_w,
        )
        lbl_footnote.pack(fill="x", padx=8, pady=(6, 0))

    # ---------------------------------------------------------------------
    # SLIDE 5: SYSTEM ARCHITECTURE (Canvas Diagram)
    # ---------------------------------------------------------------------
    def _render_architecture_slide(self, data, title_pt):
        # Title
        lbl_title = ctk.CTkLabel(
            self.slide_container,
            text=data["title"],
            font=ctk.CTkFont(family="Segoe UI", size=title_pt, weight="bold"),
            text_color=COLOR_ACCENT,
            anchor="w",
        )
        lbl_title.pack(fill="x", pady=(6, 6))

        # Canvas container
        canvas_frame = ctk.CTkFrame(self.slide_container, fg_color=COLOR_CARD, corner_radius=12, border_width=1, border_color=COLOR_CARD_BORDER)
        canvas_frame.pack(fill="both", expand=True, padx=4, pady=4)

        canvas = tk.Canvas(canvas_frame, bg=COLOR_HEADER, highlightthickness=0)
        canvas.pack(fill="both", expand=True, padx=8, pady=8)

        def _draw(event=None):
            try:
                if not canvas.winfo_exists():
                    return
                w = canvas.winfo_width()
                h = canvas.winfo_height()
                if w <= 10 or h <= 10:
                    return
                self._draw_architecture_diagram(canvas, w, h)
            except Exception:
                pass

        canvas.bind("<Configure>", _draw)

    def _draw_architecture_diagram(self, canvas: tk.Canvas, w: int, h: int):
        """Draw complete architecture diagram redrawing on resize, readable at projector size."""
        canvas.delete("all")

        # Dynamic font sizes for diagram
        f_title = ("Segoe UI", max(12, int(h * 0.024)), "bold")
        f_sub = ("Segoe UI", max(10, int(h * 0.018)), "normal")
        f_legend = ("Segoe UI", max(10, int(h * 0.018)), "normal")
        f_loop = ("Segoe UI", max(11, int(h * 0.020)), "bold")

        # -------------------------------------------------------------
        # Helper: Draw stylized rounded/bordered box with wrapped text
        # -------------------------------------------------------------
        def draw_box(x1, y1, x2, y2, fill_color, border_color, title_text, sub_text="", dashed=False):
            dash_param = (5, 3) if dashed else ()
            canvas.create_rectangle(
                x1, y1, x2, y2,
                fill=fill_color,
                outline=border_color,
                width=2,
                dash=dash_param,
            )
            mid_x = (x1 + x2) / 2
            max_text_w = max(40, int((x2 - x1) - 10))
            if sub_text:
                mid_y = (y1 + y2) / 2 - 12
                canvas.create_text(mid_x, mid_y, text=title_text, fill=COLOR_TEXT_MAIN, font=f_title, justify="center", width=max_text_w)
                canvas.create_text(mid_x, mid_y + 24, text=sub_text, fill=COLOR_TEXT_MUTED, font=f_sub, justify="center", width=max_text_w)
            else:
                mid_y = (y1 + y2) / 2
                canvas.create_text(mid_x, mid_y, text=title_text, fill=COLOR_TEXT_MAIN, font=f_title, justify="center", width=max_text_w)

        # -------------------------------------------------------------
        # 1. Top bar: Desktop Console (app.py)
        # -------------------------------------------------------------
        top_y1 = h * 0.03
        top_y2 = h * 0.13
        top_x1 = w * 0.22
        top_x2 = w * 0.78
        draw_box(top_x1, top_y1, top_x2, top_y2, COLOR_CARD, COLOR_ACCENT, "Desktop Console (app.py)", "CustomTkinter Dashboard & Telemetry Feeds")

        # -------------------------------------------------------------
        # Supporting boxes above flow:
        # Cache thread (above Box 3) & Config (above Box 4)
        # -------------------------------------------------------------
        mid_top_y1 = h * 0.17
        mid_top_y2 = h * 0.27

        # Process cache thread (feeds Process Identifier)
        cache_x1 = w * 0.42
        cache_x2 = w * 0.58
        draw_box(cache_x1, mid_top_y1, cache_x2, mid_top_y2, "#0b1727", COLOR_YELLOW, "Process cache thread", "(polls about every 100 ms)")

        # config.py box (feeds Identifier & Containment)
        cfg_x1 = w * 0.62
        cfg_x2 = w * 0.78
        draw_box(cfg_x1, mid_top_y1, cfg_x2, mid_top_y2, "#0b1727", COLOR_ACCENT, "config.py: settings", "140-process allowlist, test mode")

        # -------------------------------------------------------------
        # 2. Main Flow: 5 boxes left-to-right
        # -------------------------------------------------------------
        flow_y1 = h * 0.33
        flow_y2 = h * 0.50

        box_w = w * 0.17
        gap = (w - (5 * box_w) - (w * 0.06)) / 4
        start_x = w * 0.03

        # 5 box definitions
        b1_x1 = start_x
        b1_x2 = b1_x1 + box_w

        b2_x1 = b1_x2 + gap
        b2_x2 = b2_x1 + box_w

        b3_x1 = b2_x2 + gap
        b3_x2 = b3_x1 + box_w

        b4_x1 = b3_x2 + gap
        b4_x2 = b4_x1 + box_w

        b5_x1 = b4_x2 + gap
        b5_x2 = b5_x1 + box_w

        # Draw 5 engine boxes with wrapped titles & subtexts
        draw_box(b1_x1, flow_y1, b1_x2, flow_y2, COLOR_CARD, COLOR_YELLOW, "Decoy Planter", "(decoy.py)")
        draw_box(b2_x1, flow_y1, b2_x2, flow_y2, COLOR_CARD, COLOR_ACCENT, "File Monitor", "(monitor.py, watchdog)")
        draw_box(b3_x1, flow_y1, b3_x2, flow_y2, COLOR_CARD, COLOR_ACCENT, "Process Identifier", "(process_id.py, psutil)")
        draw_box(b4_x1, flow_y1, b4_x2, flow_y2, COLOR_CARD, COLOR_RED, "Containment (contain.py)", "freeze, then terminate")
        draw_box(b5_x1, flow_y1, b5_x2, flow_y2, COLOR_CARD, COLOR_GREEN, "Forensics", "(incident_manager.py)\nquarantine, SHA-256, reports")

        # -------------------------------------------------------------
        # Arrows in main flow (Box 1 -> 2 -> 3 -> 4 -> 5)
        # -------------------------------------------------------------
        flow_mid_y = (flow_y1 + flow_y2) / 2
        for (ax1, ax2) in [(b1_x2, b2_x1), (b2_x2, b3_x1), (b3_x2, b4_x1), (b4_x2, b5_x1)]:
            canvas.create_line(ax1, flow_mid_y, ax2, flow_mid_y, fill=COLOR_ACCENT, width=2, arrow=tk.LAST)

        # Arrow: Top console down to engine
        canvas.create_line((top_x1 + top_x2) / 2, top_y2, (top_x1 + top_x2) / 2, mid_top_y1 - 4, fill=COLOR_TEXT_MUTED, width=2, arrow=tk.LAST)
        canvas.create_line(top_x1 + 30, top_y2, b2_x1 + (box_w / 2), flow_y1, fill=COLOR_TEXT_MUTED, width=2, arrow=tk.LAST)

        # Arrow: Process cache -> Process Identifier
        canvas.create_line((cache_x1 + cache_x2) / 2, mid_top_y2, (b3_x1 + b3_x2) / 2, flow_y1, fill=COLOR_YELLOW, width=2, arrow=tk.LAST)

        # Arrow: config.py -> Identifier & Containment
        cfg_mid_x = (cfg_x1 + cfg_x2) / 2
        canvas.create_line(cfg_mid_x, mid_top_y2, (b4_x1 + b4_x2) / 2, flow_y1, fill=COLOR_ACCENT, width=2, arrow=tk.LAST)
        canvas.create_line(cfg_x1, (mid_top_y1 + mid_top_y2) / 2, cache_x2, (mid_top_y1 + mid_top_y2) / 2, fill=COLOR_ACCENT, width=1, dash=(3, 3), arrow=tk.LAST)

        # -------------------------------------------------------------
        # 3. Self-healing loop: Containment back to Planter
        # -------------------------------------------------------------
        loop_y = flow_y2 + (h * 0.05)
        canvas.create_line(
            (b4_x1 + b4_x2) / 2, flow_y2,
            (b4_x1 + b4_x2) / 2, loop_y,
            (b1_x1 + b1_x2) / 2, loop_y,
            (b1_x1 + b1_x2) / 2, flow_y2,
            fill=COLOR_GREEN, width=2, arrow=tk.LAST
        )
        canvas.create_text(
            (b2_x1 + b3_x2) / 2, loop_y + 12,
            text="self-healing: restore decoy",
            fill=COLOR_GREEN, font=f_loop, justify="center"
        )

        # -------------------------------------------------------------
        # 4. Dashed rectangle at bottom: Protected sandbox folder
        # -------------------------------------------------------------
        sand_x1 = w * 0.03
        sand_x2 = w * 0.52
        sand_y1 = h * 0.64
        sand_y2 = h * 0.92

        draw_box(
            sand_x1, sand_y1, sand_x2, sand_y2,
            "#07111e", COLOR_YELLOW,
            "Protected sandbox folder: decoys and user files",
            "Monitored directory holding tripwires and test assets",
            dashed=True
        )

        # Arrows between Sandbox, Planter, and Monitor
        b1_mid_x = (b1_x1 + b1_x2) / 2
        canvas.create_line(b1_mid_x, loop_y + 20, b1_mid_x, sand_y1, fill=COLOR_YELLOW, width=2, arrow=tk.LAST)
        canvas.create_text(b1_mid_x + 8, (loop_y + 20 + sand_y1) / 2, text="seeds decoys", fill=COLOR_YELLOW, font=f_sub, anchor="w")

        b2_mid_x = (b2_x1 + b2_x2) / 2
        canvas.create_line(b2_mid_x, sand_y1, b2_mid_x, loop_y + 20, fill=COLOR_ACCENT, width=2, arrow=tk.LAST)
        canvas.create_text(b2_mid_x + 8, (loop_y + 20 + sand_y1) / 2, text="watches I/O", fill=COLOR_ACCENT, font=f_sub, anchor="w")

        # -------------------------------------------------------------
        # 5. Short Legend explaining solid vs dashed
        # -------------------------------------------------------------
        leg_x1 = w * 0.56
        leg_x2 = w * 0.97
        leg_y1 = h * 0.64
        leg_y2 = h * 0.92

        draw_box(leg_x1, leg_y1, leg_x2, leg_y2, COLOR_CARD, COLOR_CARD_BORDER, "Legend")

        line1_y = leg_y1 + ((leg_y2 - leg_y1) * 0.40)
        line2_y = leg_y1 + ((leg_y2 - leg_y1) * 0.70)
        leg_text_w = max(60, int((leg_x2 - leg_x1) - 75))

        canvas.create_line(leg_x1 + 15, line1_y, leg_x1 + 55, line1_y, fill=COLOR_ACCENT, width=2, arrow=tk.LAST)
        canvas.create_text(leg_x1 + 65, line1_y, text="Solid line: Control flow & telemetry pipeline", fill=COLOR_TEXT_MAIN, font=f_legend, anchor="w", width=leg_text_w)

        canvas.create_line(leg_x1 + 15, line2_y, leg_x1 + 55, line2_y, fill=COLOR_YELLOW, width=2, dash=(5, 3))
        canvas.create_text(leg_x1 + 65, line2_y, text="Dashed line: Protected sandbox isolation boundary", fill=COLOR_TEXT_MAIN, font=f_legend, anchor="w", width=leg_text_w)
        canvas.create_line(b1_mid_x, loop_y + 20, b1_mid_x, sand_y1, fill=COLOR_YELLOW, width=2, arrow=tk.LAST)
        canvas.create_text(b1_mid_x + 8, (loop_y + 20 + sand_y1) / 2, text="seeds decoys", fill=COLOR_YELLOW, font=f_sub, anchor="w")

        b2_mid_x = (b2_x1 + b2_x2) / 2
        canvas.create_line(b2_mid_x, sand_y1, b2_mid_x, loop_y + 20, fill=COLOR_ACCENT, width=2, arrow=tk.LAST)
        canvas.create_text(b2_mid_x + 8, (loop_y + 20 + sand_y1) / 2, text="watches I/O", fill=COLOR_ACCENT, font=f_sub, anchor="w")

        # -------------------------------------------------------------
        # 5. Short Legend explaining solid vs dashed
        # -------------------------------------------------------------
        leg_x1 = w * 0.58
        leg_x2 = w * 0.97
        leg_y1 = h * 0.66
        leg_y2 = h * 0.92

        draw_box(leg_x1, leg_y1, leg_x2, leg_y2, COLOR_CARD, COLOR_CARD_BORDER, "Legend")

        # Legend items
        mid_leg_x = (leg_x1 + leg_x2) / 2
        line1_y = leg_y1 + ((leg_y2 - leg_y1) * 0.42)
        line2_y = leg_y1 + ((leg_y2 - leg_y1) * 0.72)

        # Solid sample
        canvas.create_line(leg_x1 + 25, line1_y, leg_x1 + 75, line1_y, fill=COLOR_ACCENT, width=2, arrow=tk.LAST)
        canvas.create_text(leg_x1 + 85, line1_y, text="Solid line: Control flow & telemetry pipeline", fill=COLOR_TEXT_MAIN, font=f_legend, anchor="w")

        # Dashed sample
        canvas.create_line(leg_x1 + 25, line2_y, leg_x1 + 75, line2_y, fill=COLOR_YELLOW, width=2, dash=(5, 3))
        canvas.create_text(leg_x1 + 85, line2_y, text="Dashed line: Protected sandbox isolation boundary", fill=COLOR_TEXT_MAIN, font=f_legend, anchor="w")

    # ---------------------------------------------------------------------
    # SLIDE 6: NEXT MILESTONES
    # ---------------------------------------------------------------------
    def _render_milestones_slide(self, data, wrap_w, title_pt, body_pt, sub_pt):
        # Title
        lbl_title = ctk.CTkLabel(
            self.slide_container,
            text=data["title"],
            font=ctk.CTkFont(family="Segoe UI", size=title_pt, weight="bold"),
            text_color=COLOR_ACCENT,
            anchor="w",
        )
        lbl_title.pack(fill="x", pady=(10, 16))

        # Milestones card
        card = ctk.CTkFrame(self.slide_container, fg_color=COLOR_CARD, corner_radius=12, border_width=1, border_color=COLOR_CARD_BORDER)
        card.pack(fill="both", expand=True, padx=4, pady=4)

        list_frame = ctk.CTkFrame(card, fg_color="transparent")
        list_frame.pack(fill="both", expand=True, padx=30, pady=20)

        icons = ["🎯", "⚡", "🛡️", "🔍", "🌐"]

        for idx, text in enumerate(data["milestones"]):
            row = ctk.CTkFrame(list_frame, fg_color="transparent")
            row.pack(fill="x", pady=8, anchor="w")

            icon_lbl = ctk.CTkLabel(
                row,
                text=icons[idx % len(icons)],
                font=ctk.CTkFont(size=int(body_pt * 0.9)),
                width=30,
            )
            icon_lbl.pack(side="left", anchor="n", padx=(0, 12))

            msg_lbl = ctk.CTkLabel(
                row,
                text=text,
                font=ctk.CTkFont(family="Segoe UI", size=body_pt),
                text_color=COLOR_TEXT_MAIN,
                justify="left",
                wraplength=wrap_w - 120,
                anchor="w",
            )
            msg_lbl.pack(side="left", fill="x", expand=True)
