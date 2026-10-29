"""
Canary Shield — In-App Presentation Slideshow View.
Light, soft watercolor minimalist theme inspired by pastel lavender palettes.
"""

import os
import sys
import time
import random
import tkinter as tk
import tkinter.font as tkfont
import customtkinter as ctk
from PIL import Image, ImageDraw, ImageFilter, ImageTk
from typing import Optional, Dict, Any, List, Tuple

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

# Palette (Strictly restricted to requested watercolor minimalist lavender theme)
COLOR_BG = "#FBF4FF"          # pale pink-lavender
COLOR_CARD = "#FFFFFF"        # pure white card surface
COLOR_BLOB_SOFT = "#E6D8F5"   # soft lilac blob
COLOR_BLOB_MID = "#CDB6EA"    # mid lilac
COLOR_PLUM = "#6B3FA0"        # deep plum accent
COLOR_TEXT_DARK = "#241B2F"   # dark text (contrast ratio > 15:1)
COLOR_TEXT_MUTED = "#6B5F7A"  # muted text (contrast ratio > 5.5:1)
COLOR_HAIRLINE = "#3A2D4A"    # hairline and progress dots
COLOR_CORAL = "#E5566D"       # soft coral (ONLY for containment & 1s goal line)
COLOR_CANARY = "#F2B705"      # canary yellow (logo & tiny dot accents)

# =========================================================================
# SLIDES DATA STRUCTURE (Exact wording and numbers preserved)
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
                "hero": "260 ms",
                "deadline": "Deadline: prototype submission",
            },
            {
                "num": "2",
                "heading": "Protect user data",
                "goal": "lose no genuine user files.",
                "measure": "user files surviving in each of 5 test runs.",
                "result": "5 of 5 files survived in 5 of 5 runs.",
                "hero": "5 of 5",
                "deadline": "Deadline: prototype submission",
            },
            {
                "num": "3",
                "heading": "Leave evidence",
                "goal": "a forensic report for every contained incident.",
                "measure": "reports (JSON and HTML with SHA-256) generated per incident.",
                "result": "one report per incident in every run.",
                "hero": "1 per inc.",
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

def hex_to_rgb(h: str) -> Tuple[int, int, int]:
    """Convert hex color string to integer RGB tuple."""
    h = h.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

def make_watercolor(w: int, h: int, base_color: str = COLOR_BLOB_SOFT, seed: int = 42) -> Image.Image:
    """
    Generate soft watercolor blob texture using Pillow.
    Overlapping ellipses with varied alpha, GaussianBlur, and subtle pigment edge,
    rendered at half resolution then upscaled with LANCZOS.
    """
    rng = random.Random(seed)
    hw = max(60, int(w / 2))
    hh = max(60, int(h / 2))

    layer = Image.new("RGBA", (hw, hh), (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)

    base_rgb = hex_to_rgb(base_color)
    dark_edge_rgb = (max(0, base_rgb[0] - 25), max(0, base_rgb[1] - 25), max(0, base_rgb[2] - 25))

    cx, cy = hw / 2, hh / 2
    rx_base, ry_base = hw * 0.42, hh * 0.42

    # 8-10 overlapping soft watercolor washes
    for _ in range(8):
        ox = rng.uniform(-0.16, 0.16) * hw
        oy = rng.uniform(-0.16, 0.16) * hh
        rx = rx_base * rng.uniform(0.70, 1.25)
        ry = ry_base * rng.uniform(0.70, 1.25)
        alpha = int(rng.uniform(30, 65))
        draw.ellipse([cx + ox - rx, cy + oy - ry, cx + ox + rx, cy + oy + ry], fill=(*base_rgb, alpha))

    blur_rad = max(2, int(min(hw, hh) * 0.035))
    layer = layer.filter(ImageFilter.GaussianBlur(blur_rad))

    # Pigment edge layer for authentic watercolor look
    edge_layer = Image.new("RGBA", (hw, hh), (0, 0, 0, 0))
    edraw = ImageDraw.Draw(edge_layer)
    for _ in range(4):
        ox = rng.uniform(-0.18, 0.18) * hw
        oy = rng.uniform(-0.18, 0.18) * hh
        rx = rx_base * rng.uniform(0.85, 1.15)
        ry = ry_base * rng.uniform(0.85, 1.15)
        edraw.ellipse([cx + ox - rx, cy + oy - ry, cx + ox + rx, cy + oy + ry], outline=(*dark_edge_rgb, 45), width=max(1, int(min(hw, hh) * 0.025)))

    edge_layer = edge_layer.filter(ImageFilter.GaussianBlur(blur_rad))
    layer = Image.alpha_composite(layer, edge_layer)

    # Composite onto solid background
    bg_rgb = hex_to_rgb(COLOR_BG)
    final_canvas = Image.new("RGB", (hw, hh), bg_rgb)
    final_canvas.paste(layer, (0, 0), layer)

    # Upscale to full resolution
    return final_canvas.resize((w, h), Image.Resampling.LANCZOS)


class PresentationWindow(ctk.CTkToplevel):
    """Full-screen in-app presentation window with light watercolor theme."""

    def __init__(self, master=None):
        super().__init__(master)
        self.master_app = master
        self.title("Canary Shield — Presentation")
        self.configure(fg_color=COLOR_BG)

        self.current_index = 0
        self.is_fullscreen = False
        self._image_cache: Dict[str, Any] = {}
        self._resize_after_id: Optional[str] = None
        self._last_rendered_dims: Tuple[int, int] = (0, 0)
        self.last_render_time_ms: float = 0.0

        # Discover system typography
        self._setup_fonts()

        # Load application logo if available
        self._load_logo()

        # Window icon
        self.after(250, self._set_icon)

        # Clamped initial window geometry (fits within usable screen)
        self._init_window_geometry()

        # Setup keyboard shortcuts
        self._bind_keys()

        # Window protocol
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Build UI layout (Canvas slide area + fixed-height footer)
        self._build_ui()

        # Bring window to front
        self.focus_window()

        # Initial render
        self.after(50, self._render_current_slide)

        # Debounced resize listener
        self.bind("<Configure>", self._on_window_configure)

    def _setup_fonts(self):
        """Pick available fonts: Serif titles, clean sans body, and monospaced labels."""
        try:
            available = set(tkfont.families())
        except Exception:
            available = set()

        # Pick serif for titles
        serif_prefs = ["Bodoni MT", "Didot", "Palatino Linotype", "Georgia"]
        self.font_serif = next((f for f in serif_prefs if f in available), "Georgia")

        # Pick sans for body
        body_prefs = ["Segoe UI", "Poppins", "Arial"]
        self.font_body = next((f for f in body_prefs if f in available), "Segoe UI")

        self.font_mono = "Consolas" if "Consolas" in available else "Courier New"

    def _load_logo(self):
        """Load logo image for Slide 1."""
        self.logo_pil = None
        png_path = resource_path(os.path.join("assets", "canary_shield.png"))
        if os.path.exists(png_path):
            try:
                self.logo_pil = Image.open(png_path).convert("RGBA")
            except Exception:
                pass

    def _set_icon(self):
        """Set window icon from resource path."""
        try:
            ico_file = resource_path(os.path.join("assets", "canary_shield.ico"))
            if os.path.exists(ico_file):
                self.iconbitmap(ico_file)
        except Exception:
            pass

    def _init_window_geometry(self):
        """Set geometry clamped to usable screen height (minus taskbar)."""
        try:
            sw = self.winfo_screenwidth()
            sh = self.winfo_screenheight()
            usable_w = max(1024, min(1400, sw - 60))
            usable_h = max(600, min(860, sh - 60))
            self.geometry(f"{usable_w}x{usable_h}+30+15")
            self.minsize(1024, 600)
            self.state("zoomed")
        except Exception:
            self.geometry("1280x720+30+15")

    def _bind_keys(self):
        """Bind keyboard presentation controls."""
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
        """Bring window to front on Windows."""
        try:
            self.deiconify()
            self.lift()
            self.attributes("-topmost", True)
            self.after(60, lambda: self.attributes("-topmost", False))
            self.focus_force()
        except Exception:
            pass

    def toggle_fullscreen(self, event=None):
        """Toggle fullscreen state."""
        self.is_fullscreen = not self.is_fullscreen
        self.attributes("-fullscreen", self.is_fullscreen)
        self.after(50, self._render_current_slide)

    def handle_escape(self, event=None):
        """Escape exits fullscreen, or closes window if already windowed."""
        if self.is_fullscreen:
            self.is_fullscreen = False
            self.attributes("-fullscreen", False)
            self.after(50, self._render_current_slide)
        else:
            self._on_close()

    def _on_close(self):
        """Safely destroy presentation window and release cached images."""
        try:
            if self._resize_after_id:
                self.after_cancel(self._resize_after_id)
                self._resize_after_id = None
        except Exception:
            pass

        self._image_cache.clear()

        try:
            if self.master_app and hasattr(self.master_app, "presentation_window"):
                self.master_app.presentation_window = None
        except Exception:
            pass
        self.destroy()

    def _build_ui(self):
        """Build main layout with grid: row 0 weight 1 (slide canvas), row 1 fixed height (footer)."""
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_columnconfigure(0, weight=1)

        # 1. Slide Canvas (fills row 0 completely)
        self.canvas = tk.Canvas(
            self,
            bg=COLOR_BG,
            highlightthickness=0,
            bd=0,
        )
        self.canvas.grid(row=0, column=0, sticky="nsew")

        # 2. Fixed-height Footer Frame (row 1, guaranteed visible)
        self.footer_frame = ctk.CTkFrame(
            self,
            fg_color=COLOR_BG,
            height=54,
            corner_radius=0,
            border_width=1,
            border_color=COLOR_BLOB_SOFT,
        )
        self.footer_frame.grid(row=1, column=0, sticky="ew")
        self.footer_frame.grid_propagate(False)

        # Left: 6-dot progress indicator (current filled plum, others hollow)
        self.dots_container = ctk.CTkFrame(self.footer_frame, fg_color="transparent")
        self.dots_container.pack(side="left", padx=(28, 16), pady=12)

        self.dot_buttons = []
        for i in range(len(SLIDES)):
            dot = ctk.CTkButton(
                self.dots_container,
                text="",
                width=10,
                height=10,
                corner_radius=5,
                fg_color="transparent",
                border_width=2,
                border_color=COLOR_HAIRLINE,
                hover_color=COLOR_BLOB_MID,
                command=lambda idx=i: self.go_to_slide(idx),
            )
            dot.pack(side="left", padx=4)
            self.dot_buttons.append(dot)

        # Slide counter label: "n / 6"
        self.counter_lbl = ctk.CTkLabel(
            self.footer_frame,
            text="1 / 6",
            font=ctk.CTkFont(family=self.font_serif, size=15, weight="bold"),
            text_color=COLOR_TEXT_DARK,
        )
        self.counter_lbl.pack(side="left", padx=(10, 20))

        # Center: Prev & Next buttons styled as soft lavender and plum pills
        controls_box = ctk.CTkFrame(self.footer_frame, fg_color="transparent")
        controls_box.pack(side="left", padx=10)

        self.btn_prev = ctk.CTkButton(
            controls_box,
            text="◀ Prev",
            width=88,
            height=34,
            corner_radius=17,
            fg_color=COLOR_CARD,
            hover_color=COLOR_BLOB_SOFT,
            border_width=1,
            border_color=COLOR_BLOB_MID,
            text_color=COLOR_TEXT_DARK,
            font=ctk.CTkFont(family=self.font_body, size=13, weight="bold"),
            command=self.prev_slide,
        )
        self.btn_prev.pack(side="left", padx=5)

        self.btn_next = ctk.CTkButton(
            controls_box,
            text="Next ▶",
            width=88,
            height=34,
            corner_radius=17,
            fg_color=COLOR_PLUM,
            hover_color="#532d80",
            text_color="#FFFFFF",
            font=ctk.CTkFont(family=self.font_body, size=13, weight="bold"),
            command=self.next_slide,
        )
        self.btn_next.pack(side="left", padx=5)

        # Live Demo button on last slide
        self.btn_demo = ctk.CTkButton(
            controls_box,
            text="🚀 Live Demo",
            width=124,
            height=34,
            corner_radius=17,
            fg_color=COLOR_PLUM,
            hover_color="#532d80",
            text_color="#FFFFFF",
            font=ctk.CTkFont(family=self.font_body, size=13, weight="bold"),
            command=self.launch_live_demo,
        )

        # Right: Keyboard shortcut hint
        hint_lbl = ctk.CTkLabel(
            self.footer_frame,
            text="F11: Fullscreen  |  Esc: Close",
            font=ctk.CTkFont(family=self.font_body, size=11),
            text_color=COLOR_TEXT_MUTED,
        )
        hint_lbl.pack(side="right", padx=28)

    def _on_window_configure(self, event):
        """Debounced window resize handler (one-shot after call)."""
        if event.widget != self:
            return
        if self._resize_after_id:
            self.after_cancel(self._resize_after_id)
        self._resize_after_id = self.after(60, self._handle_debounced_resize)

    def _handle_debounced_resize(self):
        """Execute resize render once geometry settles."""
        self._resize_after_id = None
        self._render_current_slide()

    def go_to_slide(self, index: int):
        """Jump to slide by index."""
        if 0 <= index < len(SLIDES):
            self.current_index = index
            self._render_current_slide()

    def next_slide(self):
        """Next slide."""
        if self.current_index < len(SLIDES) - 1:
            self.current_index += 1
            self._render_current_slide()

    def prev_slide(self):
        """Previous slide."""
        if self.current_index > 0:
            self.current_index -= 1
            self._render_current_slide()

    def launch_live_demo(self):
        """Close slideshow and switch to Attack Simulator."""
        self._on_close()
        try:
            if self.master_app and hasattr(self.master_app, "switch_view"):
                self.master_app.switch_view("simulator")
        except Exception:
            pass

    # =========================================================================
    # CANVAS PRIMITIVE HELPERS
    # =========================================================================
    def _draw_pill(self, x1: float, y1: float, x2: float, y2: float, fill: str, outline: str = "", width: int = 1):
        """Draw rounded pill shape on canvas."""
        h = max(2.0, y2 - y1)
        r = h / 2.0
        if (x2 - x1) <= h:
            return self.canvas.create_oval(x1, y1, x2, y2, fill=fill, outline=outline, width=width)
        o1 = self.canvas.create_oval(x1, y1, x1 + h, y2, fill=fill, outline=outline, width=width)
        o2 = self.canvas.create_oval(x2 - h, y1, x2, y2, fill=fill, outline=outline, width=width)
        r1 = self.canvas.create_rectangle(x1 + r, y1, x2 - r, y2, fill=fill, outline=outline, width=width)
        if fill:
            self.canvas.create_rectangle(x1 + r, y1 + width, x2 - r, y2 - width, fill=fill, outline=fill)
        return r1

    def _draw_card(self, x1: float, y1: float, x2: float, y2: float, radius: float = 14, fill: str = COLOR_CARD, outline: str = COLOR_BLOB_MID, width: int = 1):
        """Draw smooth rounded card on canvas."""
        r = max(2.0, min(radius, (x2 - x1) / 2.0, (y2 - y1) / 2.0))
        pts = [
            x1 + r, y1,
            x2 - r, y1,
            x2, y1,
            x2, y1 + r,
            x2, y2 - r,
            x2, y2,
            x2 - r, y2,
            x1 + r, y2,
            x1, y2,
            x1, y2 - r,
            x1, y1 + r,
            x1, y1,
        ]
        return self.canvas.create_polygon(pts, smooth=True, fill=fill, outline=outline, width=width)

    def _draw_dot_grid(self, x_start: float, y_start: float, cols: int = 5, rows: int = 4, spacing: float = 16, dot_color: str = COLOR_HAIRLINE):
        """Draw small decorative dot-grid motif."""
        for c in range(cols):
            for r in range(rows):
                cx = x_start + (c * spacing)
                cy = y_start + (r * spacing)
                self.canvas.create_oval(cx - 1.5, cy - 1.5, cx + 1.5, cy + 1.5, fill=dot_color, outline="")

    def _draw_arrow_doodle(self, x: float, y: float, size: float = 24, color: str = COLOR_PLUM):
        """Draw hand-drawn curved arrow doodle motif next to headers."""
        self.canvas.create_arc(
            x, y, x + (size * 1.4), y + (size * 0.9),
            start=45, extent=170, style="arc", outline=color, width=2
        )
        tip_x = x + (size * 1.35)
        tip_y = y + (size * 0.45)
        self.canvas.create_line(tip_x, tip_y, tip_x - 7, tip_y - 2, fill=color, width=2)
        self.canvas.create_line(tip_x, tip_y, tip_x - 4, tip_y + 7, fill=color, width=2)

    def _draw_paper_plane_path(self, x1: float, y1: float, x2: float, y2: float):
        """Draw dashed looping flight path with a tiny paper plane."""
        dx = x2 - x1
        ctrl_x1 = x1 + dx * 0.35
        ctrl_y1 = max(10, y1 - 25)
        ctrl_x2 = x1 + dx * 0.65
        ctrl_y2 = max(10, y2 - 20)
        pts = [x1, y1, ctrl_x1, ctrl_y1, ctrl_x1 + 20, ctrl_y1 + 25, ctrl_x2 - 20, ctrl_y2 - 25, ctrl_x2, ctrl_y2, x2, y2]
        self.canvas.create_line(pts, smooth=True, fill=COLOR_BLOB_MID, width=2, dash=(6, 4))

        plane_pts = [
            x2, y2,
            x2 - 16, y2 - 8,
            x2 - 11, y2,
            x2 - 16, y2 + 8,
        ]
        self.canvas.create_polygon(plane_pts, fill=COLOR_PLUM, outline=COLOR_TEXT_DARK, width=1)
        self.canvas.create_line(x2, y2, x2 - 11, y2, fill=COLOR_BG, width=1)

    # =========================================================================
    # SLIDE RENDERING PIPELINE
    # =========================================================================
    def _render_current_slide(self):
        """Paint active slide with watercolor background and canvas primitives."""
        t0 = time.perf_counter()

        cw = max(900, self.canvas.winfo_width())
        ch = max(500, self.canvas.winfo_height())

        # Update footer progress dots and slide counter
        self.counter_lbl.configure(text=f"{self.current_index + 1} / {len(SLIDES)}")
        for i, dot in enumerate(self.dot_buttons):
            if i == self.current_index:
                dot.configure(fg_color=COLOR_PLUM, border_color=COLOR_PLUM)
            else:
                dot.configure(fg_color="transparent", border_color=COLOR_HAIRLINE)

        # Update button states
        self.btn_prev.configure(state="normal" if self.current_index > 0 else "disabled")
        if self.current_index == len(SLIDES) - 1:
            self.btn_next.pack_forget()
            if not self.btn_demo.winfo_ismapped():
                self.btn_demo.pack(side="left", padx=5)
        else:
            if self.btn_demo.winfo_ismapped():
                self.btn_demo.pack_forget()
            if not self.btn_next.winfo_ismapped():
                self.btn_next.pack(side="left", padx=5)
            self.btn_next.configure(state="normal")

        # Clear canvas
        self.canvas.delete("all")

        # 1. Background Watercolor Texture
        cache_key = f"bg_{self.current_index}_{cw}_{ch}"
        if cache_key not in self._image_cache:
            blob_seed = 100 + (self.current_index * 37)
            pil_bg = make_watercolor(cw, ch, base_color=COLOR_BLOB_SOFT, seed=blob_seed)
            self._image_cache[cache_key] = ImageTk.PhotoImage(pil_bg)

        self.canvas.create_image(0, 0, image=self._image_cache[cache_key], anchor="nw")

        # 2. Top-Right Decorative Dot-Grid
        self._draw_dot_grid(cw - 110, 24, cols=5, rows=4, spacing=14)

        # Responsive font scaling (guaranteed >= minimums)
        title_pt = max(44, int(ch * 0.052))
        body_pt = max(24, int(ch * 0.028))
        hero_pt = max(80, min(120, int(ch * 0.11)))

        slide_data = SLIDES[self.current_index]
        slide_type = slide_data.get("type")

        # Render specific slide content
        if slide_type == "title":
            self._render_title(slide_data, cw, ch, title_pt, body_pt)
        elif slide_type == "problem":
            self._render_problem(slide_data, cw, ch, title_pt, body_pt)
        elif slide_type == "solution":
            self._render_solution(slide_data, cw, ch, title_pt, body_pt)
        elif slide_type == "objectives":
            self._render_objectives(slide_data, cw, ch, title_pt, body_pt, hero_pt)
        elif slide_type == "architecture":
            self._render_architecture(slide_data, cw, ch, title_pt)
        elif slide_type == "milestones":
            self._render_milestones(slide_data, cw, ch, title_pt, body_pt)

        self.last_render_time_ms = (time.perf_counter() - t0) * 1000.0

    # ---------------------------------------------------------------------
    # SLIDE 1: TITLE SLIDE
    # ---------------------------------------------------------------------
    def _render_title(self, data: Dict[str, Any], w: int, h: int, title_pt: int, body_pt: int):
        cx, cy = w / 2, h / 2

        # Flight path with paper plane motif
        self._draw_paper_plane_path(w * 0.10, h * 0.84, w * 0.90, h * 0.18)

        # Logo above title
        logo_y = cy - (title_pt * 1.5)
        if self.logo_pil is not None:
            logo_key = f"logo_{w}_{h}"
            if logo_key not in self._image_cache:
                resized = self.logo_pil.resize((48, 48), Image.Resampling.LANCZOS)
                self._image_cache[logo_key] = ImageTk.PhotoImage(resized)
            self.canvas.create_image(cx, logo_y, image=self._image_cache[logo_key])
        else:
            self.canvas.create_oval(cx - 20, logo_y - 20, cx + 20, logo_y + 20, fill=COLOR_CANARY, outline=COLOR_PLUM, width=2)
            self.canvas.create_text(cx, logo_y, text="🛡️", font=(self.font_body, 16))

        # Main Title (Capital letters, serif, letter-spaced)
        title_text = "C A N A R Y   S H I E L D"
        self.canvas.create_text(
            cx, cy - 20,
            text=title_text,
            font=(self.font_serif, int(title_pt * 1.25), "bold"),
            fill=COLOR_TEXT_DARK,
            justify="center",
        )

        # Subtitle under title
        self.canvas.create_text(
            cx, cy + 46,
            text=data["subtitle"],
            font=(self.font_body, body_pt),
            fill=COLOR_TEXT_MUTED,
            justify="center",
        )

        # Author strip in a subtle pill shape
        pill_w = 440
        pill_h = 38
        self._draw_pill(cx - (pill_w / 2), cy + 105, cx + (pill_w / 2), cy + 105 + pill_h, fill=COLOR_CARD, outline=COLOR_BLOB_MID, width=1)
        self.canvas.create_text(
            cx, cy + 105 + (pill_h / 2),
            text=f"by {data['footer_left']}   |   {data['footer_right']}",
            font=(self.font_body, max(15, int(body_pt * 0.65)), "bold"),
            fill=COLOR_PLUM,
        )

    # ---------------------------------------------------------------------
    # SLIDE 2: THE PROBLEM
    # ---------------------------------------------------------------------
    def _render_problem(self, data: Dict[str, Any], w: int, h: int, title_pt: int, body_pt: int):
        # Header strictly at top
        title_y = 20
        self.canvas.create_text(
            54, title_y,
            text=data["title"].upper(),
            font=(self.font_serif, title_pt, "bold"),
            fill=COLOR_TEXT_DARK,
            anchor="nw",
        )
        self._draw_arrow_doodle(340, title_y + 10)

        # Bottom Pill strictly above footer
        pill_h = 44
        pill_y1 = h - 56
        pill_y2 = pill_y1 + pill_h
        self._draw_pill(54, pill_y1, w - 54, pill_y2, fill=COLOR_PLUM, outline="")
        self.canvas.create_text(
            w / 2, (pill_y1 + pill_y2) / 2,
            text=f"👉   {data['highlight']}",
            font=(self.font_serif, max(18, int(body_pt * 0.85)), "bold"),
            fill="#FFFFFF",
        )

        # 2x2 Grid of Rounded White Cards (strictly between title and bottom pill)
        grid_top = 80
        grid_bottom = pill_y1 - 16
        grid_left = 54
        grid_right = w - 54
        card_gap = 14

        col_w = (grid_right - grid_left - card_gap) / 2.0
        row_h = (grid_bottom - grid_top - card_gap) / 2.0

        badges = ["01", "02", "03", "04"]
        bullets = data["bullets"]
        b_font_pt = max(20, int(body_pt * 0.85))

        for idx in range(4):
            c = idx % 2
            r = idx // 2
            x1 = grid_left + c * (col_w + card_gap)
            y1 = grid_top + r * (row_h + card_gap)
            x2 = x1 + col_w
            y2 = y1 + row_h

            # White Card
            self._draw_card(x1, y1, x2, y2, radius=14, fill=COLOR_CARD, outline=COLOR_BLOB_MID, width=1)

            # Plum number badge in top-left of card
            badge_r = 13
            bx, by = x1 + 24, y1 + 22
            self.canvas.create_oval(bx - badge_r, by - badge_r, bx + badge_r, by + badge_r, fill=COLOR_PLUM, outline="")
            self.canvas.create_text(bx, by, text=badges[idx], font=(self.font_serif, 10, "bold"), fill="#FFFFFF")

            # Bullet text anchored northwest to guarantee it never extends outside card
            self.canvas.create_text(
                x1 + 48, y1 + 14,
                text=bullets[idx],
                font=(self.font_body, b_font_pt),
                fill=COLOR_TEXT_DARK,
                anchor="nw",
                width=col_w - 64,
            )

    # ---------------------------------------------------------------------
    # SLIDE 3: PROPOSED SOLUTION
    # ---------------------------------------------------------------------
    def _render_solution(self, data: Dict[str, Any], w: int, h: int, title_pt: int, body_pt: int):
        title_y = 16
        self.canvas.create_text(
            50, title_y,
            text="PROPOSED SOLUTION",
            font=(self.font_serif, title_pt, "bold"),
            fill=COLOR_TEXT_DARK,
            anchor="nw",
        )
        self._draw_arrow_doodle(390, title_y + 10)

        # Bottom Safety strip in plum pill
        pill_h = 40
        pill_y1 = h - 48
        pill_y2 = pill_y1 + pill_h
        left_m = 44
        right_m = w - 44
        self._draw_pill(left_m, pill_y1, right_m, pill_y2, fill=COLOR_PLUM, outline="")
        self.canvas.create_text(
            w / 2, (pill_y1 + pill_y2) / 2,
            text=f"🛡️   {data['safety_strip']}",
            font=(self.font_body, max(16, int(body_pt * 0.70)), "bold"),
            fill="#FFFFFF",
        )

        # Five rounded cards in a row (using >= 60% of slide height)
        card_y1 = 92
        card_y2 = pill_y1 - 12
        card_h = card_y2 - card_y1
        gap = 10
        card_w = (right_m - left_m - (4 * gap)) / 5.0

        verbs = ["PLANT", "WATCH", "IDENTIFY", "CONTAIN", "REPORT"]
        steps = data["steps"]
        desc_font_pt = max(16, int(body_pt * 0.70))

        for i in range(5):
            cx1 = left_m + i * (card_w + gap)
            cx2 = cx1 + card_w

            is_contain = (i == 3)
            out_col = COLOR_CORAL if is_contain else COLOR_PLUM

            self._draw_card(cx1, card_y1, cx2, card_y2, radius=12, fill=COLOR_CARD, outline=out_col, width=2)
            mid_x = (cx1 + cx2) / 2.0

            # Numbered circle
            num_y = card_y1 + 18
            num_r = 12
            c_fill = COLOR_CORAL if is_contain else COLOR_PLUM
            self.canvas.create_oval(mid_x - num_r, num_y - num_r, mid_x + num_r, num_y + num_r, fill=c_fill, outline="")
            self.canvas.create_text(mid_x, num_y, text=str(i + 1), font=(self.font_serif, 10, "bold"), fill="#FFFFFF")

            # Icon
            self._draw_step_icon(i, mid_x, card_y1 + 46, is_contain)

            # Bold verb at 30+ pt
            self.canvas.create_text(
                mid_x, card_y1 + 80,
                text=verbs[i],
                font=(self.font_serif, max(22, int(body_pt * 1.05)), "bold"),
                fill=out_col,
            )

            # Description (anchored north to never collide with bottom)
            self.canvas.create_text(
                mid_x, card_y1 + 106,
                text=steps[i][1],
                font=(self.font_body, desc_font_pt),
                fill=COLOR_TEXT_DARK,
                anchor="n",
                width=card_w - 18,
                justify="center",
            )

            # Connecting dashed curved arrow between cards
            if i < 4:
                arrow_y = card_y1 + 18
                self.canvas.create_line(cx2 + 1, arrow_y, cx2 + gap - 1, arrow_y, fill=COLOR_BLOB_MID, width=2, arrow=tk.LAST, dash=(4, 2))

    def _draw_step_icon(self, step_idx: int, cx: float, cy: float, is_contain: bool):
        """Draw minimalist Canvas icon for each step."""
        col = COLOR_CORAL if is_contain else COLOR_PLUM
        if step_idx == 0:  # Bait file
            self.canvas.create_rectangle(cx - 9, cy - 11, cx + 9, cy + 11, fill=COLOR_CARD, outline=col, width=2)
            self.canvas.create_line(cx - 5, cy - 4, cx + 5, cy - 4, fill=col, width=1.5)
            self.canvas.create_line(cx - 5, cy + 2, cx + 3, cy + 2, fill=col, width=1.5)
        elif step_idx == 1:  # Eye
            self.canvas.create_arc(cx - 12, cy - 10, cx + 12, cy + 10, start=45, extent=90, style="arc", outline=col, width=2)
            self.canvas.create_arc(cx - 12, cy - 10, cx + 12, cy + 10, start=225, extent=90, style="arc", outline=col, width=2)
            self.canvas.create_oval(cx - 3, cy - 3, cx + 3, cy + 3, fill=col, outline="")
        elif step_idx == 2:  # Magnifier
            self.canvas.create_oval(cx - 9, cy - 9, cx + 5, cy + 5, fill=COLOR_CARD, outline=col, width=2)
            self.canvas.create_line(cx + 4, cy + 4, cx + 11, cy + 11, fill=col, width=2.5)
        elif step_idx == 3:  # Pause bars
            self.canvas.create_rectangle(cx - 6, cy - 10, cx - 2, cy + 10, fill=col, outline="")
            self.canvas.create_rectangle(cx + 2, cy - 10, cx + 6, cy + 10, fill=col, outline="")
        elif step_idx == 4:  # Document
            self.canvas.create_rectangle(cx - 8, cy - 11, cx + 8, cy + 11, fill=COLOR_CARD, outline=col, width=2)
            self.canvas.create_line(cx - 4, cy - 4, cx + 4, cy - 4, fill=col, width=1.5)
            self.canvas.create_line(cx - 4, cy + 1, cx + 4, cy + 1, fill=col, width=1.5)

    # ---------------------------------------------------------------------
    # SLIDE 4: OBJECTIVES (SMART)
    # ---------------------------------------------------------------------
    def _render_objectives(self, data: Dict[str, Any], w: int, h: int, title_pt: int, body_pt: int, hero_pt: int):
        title_y = 16
        self.canvas.create_text(
            50, title_y,
            text=data["title"].upper(),
            font=(self.font_serif, title_pt, "bold"),
            fill=COLOR_TEXT_DARK,
            anchor="nw",
        )
        self._draw_arrow_doodle(350, title_y + 10)

        # Three cards row
        gap = 16
        left_m = 48
        right_m = w - 48
        card_w = (right_m - left_m - (2 * gap)) / 3.0
        card_y1 = 82
        card_y2 = 318

        cards_data = data["cards"]

        for i, item in enumerate(cards_data):
            cx1 = left_m + i * (card_w + gap)
            cx2 = cx1 + card_w

            self._draw_card(cx1, card_y1, cx2, card_y2, radius=14, fill=COLOR_CARD, outline=COLOR_BLOB_MID, width=1)

            # Top row: number badge & heading
            badge_y = card_y1 + 18
            num_r = 10
            self.canvas.create_oval(cx1 + 20 - num_r, badge_y - num_r, cx1 + 20 + num_r, badge_y + num_r, fill=COLOR_PLUM, outline="")
            self.canvas.create_text(cx1 + 20, badge_y, text=item["num"], font=(self.font_serif, 9, "bold"), fill="#FFFFFF")
            self.canvas.create_text(
                cx1 + 36, badge_y,
                text=item["heading"],
                font=(self.font_serif, 12, "bold"),
                fill=COLOR_PLUM,
                anchor="w",
            )

            # S-M-A-R-T letter pills at top right
            smart_letters = ["S", "M", "A", "R", "T"]
            for s_idx, ch_s in enumerate(smart_letters):
                sx = cx2 - 82 + (s_idx * 14)
                self.canvas.create_oval(sx - 5.5, badge_y - 5.5, sx + 5.5, badge_y + 5.5, fill=COLOR_BLOB_SOFT, outline="")
                self.canvas.create_text(sx, badge_y, text=ch_s, font=(self.font_serif, 7, "bold"), fill=COLOR_PLUM)

            # Hero Metric (e.g. "260 ms", "5 of 5", "1 per inc.")
            self.canvas.create_text(
                cx1 + 20, card_y1 + 42,
                text=item["hero"],
                font=(self.font_serif, 28, "bold"),
                fill=COLOR_PLUM,
                anchor="nw",
            )

            # Goal line
            self.canvas.create_text(
                cx1 + 20, card_y1 + 86,
                text=item["goal"],
                font=(self.font_body, 11, "bold"),
                fill=COLOR_TEXT_DARK,
                anchor="nw",
                width=card_w - 40,
            )

            # Measure line
            self.canvas.create_text(
                cx1 + 20, card_y1 + 130,
                text=item["measure"],
                font=(self.font_body, 10),
                fill=COLOR_TEXT_MUTED,
                anchor="nw",
                width=card_w - 40,
            )

            # Result chip pill
            pill_top = card_y1 + 180
            pill_bot = pill_top + 28
            self._draw_pill(cx1 + 16, pill_top, cx2 - 16, pill_bot, fill=COLOR_BLOB_SOFT, outline="")
            self.canvas.create_text(
                (cx1 + cx2) / 2, (pill_top + pill_bot) / 2,
                text=item["result"],
                font=(self.font_body, 10, "bold"),
                fill=COLOR_PLUM,
                justify="center",
            )

            # Deadline tag
            self.canvas.create_text(
                cx1 + 20, card_y2 - 14,
                text=item["deadline"].upper(),
                font=(self.font_mono, 9, "bold"),
                fill=COLOR_TEXT_MUTED,
                anchor="w",
            )

        # Horizontal Bar Chart below cards
        chart_y1 = card_y2 + 16
        chart_y2 = h - 30
        chart_left = left_m + 130
        chart_right = right_m - 30
        chart_w = chart_right - chart_left

        self._draw_card(left_m, chart_y1, right_m, chart_y2, radius=12, fill=COLOR_CARD, outline=COLOR_BLOB_MID, width=1)

        def ms_to_x(ms_val):
            return chart_left + (ms_val / 3000.0) * chart_w

        bar_h = 14
        by1 = chart_y1 + 26
        self.canvas.create_text(chart_left - 12, by1 + (bar_h / 2), text="BEFORE (cold)", font=(self.font_mono, 10, "bold"), fill=COLOR_TEXT_MUTED, anchor="e")
        self.canvas.create_rectangle(chart_left, by1, ms_to_x(2450), by1 + bar_h, fill=COLOR_BLOB_SOFT, outline="")
        self.canvas.create_rectangle(chart_left, by1, ms_to_x(930), by1 + bar_h, fill=COLOR_BLOB_MID, outline="")
        self.canvas.create_text(ms_to_x(2450) + 8, by1 + (bar_h / 2), text="930 ms median (2450 ms worst)", font=(self.font_body, 10), fill=COLOR_TEXT_DARK, anchor="w")

        by2 = by1 + bar_h + 14
        self.canvas.create_text(chart_left - 12, by2 + (bar_h / 2), text="AFTER (cache)", font=(self.font_mono, 10, "bold"), fill=COLOR_PLUM, anchor="e")
        self.canvas.create_rectangle(chart_left, by2, ms_to_x(950), by2 + bar_h, fill=COLOR_BLOB_MID, outline="")
        self.canvas.create_rectangle(chart_left, by2, ms_to_x(260), by2 + bar_h, fill=COLOR_PLUM, outline="")
        self.canvas.create_text(ms_to_x(950) + 8, by2 + (bar_h / 2), text="260 ms median (950 ms worst)", font=(self.font_body, 10, "bold"), fill=COLOR_PLUM, anchor="w")

        # 1s goal coral line
        goal_x = ms_to_x(1000)
        self.canvas.create_line(goal_x, chart_y1 + 8, goal_x, chart_y2 - 8, fill=COLOR_CORAL, width=2, dash=(4, 2))
        self.canvas.create_text(goal_x, chart_y1 + 10, text="1 s goal", font=(self.font_serif, 9, "bold"), fill=COLOR_CORAL, anchor="s")

        # Footnote
        self.canvas.create_text(
            left_m, h - 12,
            text=f"*{data['footnote']}",
            font=(self.font_body, 9, "italic"),
            fill=COLOR_TEXT_MUTED,
            anchor="w",
        )

    # ---------------------------------------------------------------------
    # SLIDE 5: SYSTEM ARCHITECTURE
    # ---------------------------------------------------------------------
    def _render_architecture(self, data: Dict[str, Any], w: int, h: int, title_pt: int):
        title_y = 16
        self.canvas.create_text(
            48, title_y,
            text=data["title"].upper(),
            font=(self.font_serif, title_pt, "bold"),
            fill=COLOR_TEXT_DARK,
            anchor="nw",
        )
        self._draw_arrow_doodle(370, title_y + 10)

        # Reserve right panel for Legend first so it NEVER overlaps
        legend_w = 210
        legend_x1 = w - legend_w - 40
        legend_x2 = w - 40
        legend_y1 = 82
        legend_y2 = h - 24

        self._draw_card(legend_x1, legend_y1, legend_x2, legend_y2, radius=12, fill=COLOR_CARD, outline=COLOR_PLUM, width=2)
        self.canvas.create_text(
            (legend_x1 + legend_x2) / 2, legend_y1 + 20,
            text="ARCHITECTURE ROLES",
            font=(self.font_serif, 12, "bold"),
            fill=COLOR_PLUM,
        )

        legend_items = [
            (COLOR_PLUM, "Pipeline flow (1-5)"),
            (COLOR_CORAL, "Containment / Kill"),
            (COLOR_BLOB_MID, "Process Cache"),
            (COLOR_HAIRLINE, "Dashed Sandbox"),
        ]
        for l_idx, (col_l, lbl_l) in enumerate(legend_items):
            ly = legend_y1 + 48 + (l_idx * 28)
            self.canvas.create_rectangle(legend_x1 + 14, ly - 5, legend_x1 + 26, ly + 5, fill=col_l, outline="")
            self.canvas.create_text(legend_x1 + 34, ly, text=lbl_l, font=(self.font_body, 11), fill=COLOR_TEXT_DARK, anchor="w")

        # Left Pipeline Area
        pipe_left = 40
        pipe_right = legend_x1 - 24
        pipe_w = pipe_right - pipe_left

        # Top Support Box: Cache & Config
        sup_y1 = 82
        sup_y2 = 136
        sup_w = (pipe_w - 16) / 2.0

        # Box A: Process Cache
        self._draw_card(pipe_left, sup_y1, pipe_left + sup_w, sup_y2, radius=8, fill=COLOR_CARD, outline=COLOR_PLUM, width=1)
        self.canvas.create_rectangle(pipe_left + 1, sup_y1 + 1, pipe_left + sup_w - 1, sup_y1 + 14, fill=COLOR_BLOB_SOFT, outline="")
        self.canvas.create_text(pipe_left + 12, sup_y1 + 20, text="Process Cache Thread", font=(self.font_serif, 12, "bold"), fill=COLOR_TEXT_DARK, anchor="w")
        self.canvas.create_text(pipe_left + 12, sup_y1 + 38, text="polls psutil.pids() ~100ms", font=(self.font_mono, 10), fill=COLOR_TEXT_MUTED, anchor="w")

        # Box B: Desktop Console
        bx_b = pipe_left + sup_w + 16
        self._draw_card(bx_b, sup_y1, pipe_right, sup_y2, radius=8, fill=COLOR_CARD, outline=COLOR_PLUM, width=1)
        self.canvas.create_rectangle(bx_b + 1, sup_y1 + 1, pipe_right - 1, sup_y1 + 14, fill=COLOR_BLOB_SOFT, outline="")
        self.canvas.create_text(bx_b + 12, sup_y1 + 20, text="Desktop Console (app.py)", font=(self.font_serif, 12, "bold"), fill=COLOR_TEXT_DARK, anchor="w")
        self.canvas.create_text(bx_b + 12, sup_y1 + 38, text="config.py: 140 safe procs", font=(self.font_mono, 10), fill=COLOR_TEXT_MUTED, anchor="w")

        # 5 Step Boxes
        flow_y1 = 152
        flow_y2 = 236
        box_gap = 10
        step_w = (pipe_w - (4 * box_gap)) / 5.0

        step_boxes = [
            ("1. PLANT", "Decoy Planter", "decoy.py", False),
            ("2. WATCH", "File Monitor", "monitor.py", False),
            ("3. IDENTIFY", "Process Identifier", "process_id.py", False),
            ("4. CONTAIN", "Containment", "contain.py", True),
            ("5. REPORT", "Forensics", "incident_manager.py", False),
        ]

        for s_idx, (tag, b_title, b_file, is_coral) in enumerate(step_boxes):
            bx1 = pipe_left + s_idx * (step_w + box_gap)
            bx2 = bx1 + step_w
            out_col = COLOR_CORAL if is_coral else COLOR_PLUM

            self._draw_card(bx1, flow_y1, bx2, flow_y2, radius=8, fill=COLOR_CARD, outline=out_col, width=2)
            self.canvas.create_rectangle(bx1 + 2, flow_y1 + 2, bx2 - 2, flow_y1 + 16, fill=COLOR_BLOB_SOFT, outline="")

            self.canvas.create_text((bx1 + bx2) / 2, flow_y1 + 9, text=tag, font=(self.font_body, 9, "bold"), fill=out_col)
            self.canvas.create_text((bx1 + bx2) / 2, flow_y1 + 38, text=b_title, font=(self.font_serif, 11, "bold"), fill=COLOR_TEXT_DARK, justify="center")
            self.canvas.create_text((bx1 + bx2) / 2, flow_y1 + 64, text=b_file, font=(self.font_mono, 10), fill=COLOR_TEXT_MUTED, justify="center")

            if s_idx < 4:
                ay = (flow_y1 + flow_y2) / 2
                self.canvas.create_line(bx2 + 1, ay, bx2 + box_gap - 1, ay, fill=COLOR_PLUM, width=2, arrow=tk.LAST)

        # Dashed Sandbox Boundary Container below pipeline
        sand_y1 = 280
        sand_y2 = h - 20
        self.canvas.create_rectangle(pipe_left, sand_y1, pipe_right, sand_y2, fill=COLOR_CARD, outline=COLOR_PLUM, width=2, dash=(6, 4))

        # Bottom label inside sandbox container
        self.canvas.create_text(
            pipe_left + 14, sand_y2 - 14,
            text="Protected Sandbox: test_sandbox (honeytokens & mock user files)",
            font=(self.font_serif, 11, "bold"),
            fill=COLOR_PLUM,
            anchor="w",
        )

        # Vertical arrows in the gap between flow boxes (y=236) and sandbox (y=280)
        gap_mid_y = (flow_y2 + sand_y1) / 2
        b1_mid = pipe_left + (step_w / 2)
        self.canvas.create_line(b1_mid, flow_y2, b1_mid, sand_y1 + 20, fill=COLOR_PLUM, width=2, arrow=tk.LAST)
        self.canvas.create_text(b1_mid + 6, gap_mid_y, text="seeds decoys", font=(self.font_mono, 9), fill=COLOR_TEXT_MUTED, anchor="w")

        b2_mid = pipe_left + step_w + box_gap + (step_w / 2)
        self.canvas.create_line(b2_mid, sand_y1 + 20, b2_mid, flow_y2, fill=COLOR_PLUM, width=2, arrow=tk.LAST)
        self.canvas.create_text(b2_mid + 6, gap_mid_y, text="I/O events", font=(self.font_mono, 9), fill=COLOR_TEXT_MUTED, anchor="w")

        # Self-healing loop inside sandbox
        b4_mid = pipe_left + 3 * (step_w + box_gap) + (step_w / 2)
        loop_y = sand_y1 + 45
        self.canvas.create_line(b4_mid, flow_y2, b4_mid, loop_y, b1_mid, loop_y, b1_mid, sand_y1 + 20, fill=COLOR_PLUM, width=2, arrow=tk.LAST, dash=(4, 2))
        self.canvas.create_text((b1_mid + b4_mid) / 2, loop_y - 10, text="self-healing: restore decoy", font=(self.font_mono, 9, "bold"), fill=COLOR_PLUM)

    # ---------------------------------------------------------------------
    # SLIDE 6: NEXT MILESTONES
    # ---------------------------------------------------------------------
    def _render_milestones(self, data: Dict[str, Any], w: int, h: int, title_pt: int, body_pt: int):
        title_y = 16
        self.canvas.create_text(
            50, title_y,
            text=data["title"].upper(),
            font=(self.font_serif, title_pt, "bold"),
            fill=COLOR_TEXT_DARK,
            anchor="nw",
        )
        self._draw_arrow_doodle(340, title_y + 10)

        # Three cards: NEXT, THEN, LATER
        gap = 16
        left_m = 48
        right_m = w - 48
        card_w = (right_m - left_m - (2 * gap)) / 3.0
        card_y1 = 66
        card_y2 = h - 28

        sections = [
            ("NEXT", [
                "1. Test against more realistic ransomware behaviour (fast open-encrypt-close, several processes) and report accuracy honestly.",
                "2. Use Windows kernel-level tracing (ETW) for more reliable attribution than the current heuristic.",
            ]),
            ("THEN", [
                "3. Run as a protected Windows service so malware cannot easily switch it off.",
                "4. Test for false alarms with backup and search-indexing tools.",
            ]),
            ("LATER", [
                "5. Stretch goal: a central dashboard that collects alerts from many machines.",
            ]),
        ]

        # Dashed paper plane path looping across milestone sections
        self._draw_paper_plane_path(left_m + 20, card_y1 + 30, right_m - 20, card_y2 - 40)

        ms_font_pt = max(16, int(body_pt * 0.70))

        for s_idx, (sec_title, ms_list) in enumerate(sections):
            cx1 = left_m + s_idx * (card_w + gap)
            cx2 = cx1 + card_w

            self._draw_card(cx1, card_y1, cx2, card_y2, radius=14, fill=COLOR_CARD, outline=COLOR_BLOB_MID, width=1)

            # Header pill for section
            pill_h = 32
            self._draw_pill(cx1 + 18, card_y1 + 16, cx1 + 115, card_y1 + 16 + pill_h, fill=COLOR_PLUM, outline="")
            self.canvas.create_text(
                cx1 + 66, card_y1 + 16 + (pill_h / 2),
                text=sec_title,
                font=(self.font_serif, 14, "bold"),
                fill="#FFFFFF",
            )

            # Milestones inside card (anchored nw with explicit vertical spacing)
            item_y = card_y1 + 68
            for ms_text in ms_list:
                self.canvas.create_text(
                    cx1 + 18, item_y,
                    text=ms_text,
                    font=(self.font_body, ms_font_pt),
                    fill=COLOR_TEXT_DARK,
                    anchor="nw",
                    width=card_w - 36,
                )
                item_y += max(120, int((card_y2 - card_y1 - 80) / len(ms_list)))
