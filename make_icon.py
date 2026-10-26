"""
make_icon.py — Generate high-quality multi-size Canary Shield icons.

Outputs:
- assets/canary_shield.ico (multi-size: 16, 24, 32, 48, 64, 128, 256)
- assets/canary_shield.png (512x512, transparent background)

Design:
- Clean flat shield with a canary bird silhouette inside it.
- Colors:
  - Shield fill: Dark navy (#0f172a)
  - Shield border: Cyan (#38bdf8)
  - Canary silhouette: Yellow accent (#facc15)
- Optimized for readability even at small sizes (16x16, 32x32).
"""

import os
from PIL import Image, ImageDraw

def generate_logo(size=512):
    # Create high-resolution transparent canvas
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    scale = size / 512.0

    # Shield dimensions and path
    # Outer shield polygon with curved bottom tip
    shield_top_y = 36 * scale
    shield_mid_y = 260 * scale
    shield_bottom_y = 476 * scale
    shield_left_x = 64 * scale
    shield_right_x = 448 * scale
    shield_center_x = 256 * scale

    # Build smooth shield polygon points
    shield_pts = []
    # Top-left to top-center slight arch
    steps = 16
    for i in range(steps + 1):
        t = i / steps
        # gentle curve across top: dips slightly at center or arches up
        x = shield_left_x + t * (shield_center_x - shield_left_x)
        # arch: start at 52, peaks at 36
        y = 52 * scale - (1.0 - (2 * (t - 0.5)) ** 2) * (16 * scale) if t > 0.5 else 52 * scale - (4 * t * (1 - t)) * (16 * scale)
        shield_pts.append((x, y))

    for i in range(steps + 1):
        t = i / steps
        x = shield_center_x + t * (shield_right_x - shield_center_x)
        y = 36 * scale + (16 * scale) * (t ** 1.5)
        shield_pts.append((x, y))

    # Right edge down
    shield_pts.append((shield_right_x, shield_mid_y))

    # Right curve down to bottom tip
    for i in range(1, steps + 1):
        t = i / steps
        # quadratic bezier from (shield_right_x, shield_mid_y) via (shield_right_x - 30, shield_bottom_y - 80) to (shield_center_x, shield_bottom_y)
        p0 = (shield_right_x, shield_mid_y)
        p1 = (shield_right_x - 30 * scale, shield_bottom_y - 70 * scale)
        p2 = (shield_center_x, shield_bottom_y)
        bx = (1 - t)**2 * p0[0] + 2 * (1 - t) * t * p1[0] + t**2 * p2[0]
        by = (1 - t)**2 * p0[1] + 2 * (1 - t) * t * p1[1] + t**2 * p2[1]
        shield_pts.append((bx, by))

    # Left curve from bottom tip up to mid-left
    for i in range(1, steps + 1):
        t = i / steps
        p0 = (shield_center_x, shield_bottom_y)
        p1 = (shield_left_x + 30 * scale, shield_bottom_y - 70 * scale)
        p2 = (shield_left_x, shield_mid_y)
        bx = (1 - t)**2 * p0[0] + 2 * (1 - t) * t * p1[0] + t**2 * p2[0]
        by = (1 - t)**2 * p0[1] + 2 * (1 - t) * t * p1[1] + t**2 * p2[1]
        shield_pts.append((bx, by))

    shield_pts.append((shield_left_x, 52 * scale))

    # Colors
    color_navy = (15, 23, 42, 255)       # #0f172a
    color_cyan = (56, 189, 248, 255)     # #38bdf8
    color_yellow = (250, 204, 21, 255)   # #facc15
    border_width = int(round(22 * scale))

    # Draw Shield Fill
    draw.polygon(shield_pts, fill=color_navy)

    # Draw Shield Cyan Border
    draw.line(shield_pts + [shield_pts[0]], fill=color_cyan, width=border_width, joint="curve")

    # --- Draw Clean Canary Silhouette inside Shield ---
    # Centered and scaled nicely inside the shield
    # Bird components:
    # 1. Body: An angled oval
    # 2. Head: Circle
    # 3. Beak: Triangle
    # 4. Tail: Angular feathers extending back/down
    # 5. Wing: Curved wing contour
    
    # Coordinates in 512 space:
    # Head center
    hx, hy, hr = 305 * scale, 195 * scale, 42 * scale
    draw.ellipse([hx - hr, hy - hr, hx + hr, hy + hr], fill=color_yellow)

    # Beak (sharp triangle facing right)
    beak_pts = [
        (hx + hr - 6 * scale, hy - 12 * scale),
        (hx + hr + 34 * scale, hy + 4 * scale),
        (hx + hr - 4 * scale, hy + 18 * scale),
    ]
    draw.polygon(beak_pts, fill=color_yellow)

    # Eye (small dark cutout)
    er = 6 * scale
    draw.ellipse([hx + 12 * scale - er, hy - 6 * scale - er, hx + 12 * scale + er, hy - 6 * scale + er], fill=color_navy)

    # Body (chubby, sleek canary shape)
    body_pts = [
        (hx - 20 * scale, hy + 25 * scale),    # nape
        (hx + 18 * scale, hy + 35 * scale),    # throat
        (355 * scale, 275 * scale),            # breast curve
        (345 * scale, 340 * scale),            # belly
        (280 * scale, 385 * scale),            # lower abdomen
        (220 * scale, 385 * scale),            # under tail base
        (125 * scale, 415 * scale),            # tail tip 1
        (135 * scale, 395 * scale),            # tail fork
        (120 * scale, 380 * scale),            # tail tip 2
        (190 * scale, 335 * scale),            # upper tail base / rump
        (215 * scale, 250 * scale),            # back
        (270 * scale, 215 * scale),            # base of head
    ]
    draw.polygon(body_pts, fill=color_yellow)

    # Wing detail: sleek dark accent line giving wing dimension
    wing_stroke = int(round(6 * scale))
    wing_arc_pts = [
        (275 * scale, 245 * scale),
        (240 * scale, 270 * scale),
        (215 * scale, 320 * scale),
        (220 * scale, 360 * scale),
        (265 * scale, 350 * scale),
    ]
    draw.line(wing_arc_pts, fill=color_navy, width=wing_stroke, joint="curve")

    # Small feet / perch accent
    foot_w = int(round(5 * scale))
    draw.line([(245 * scale, 385 * scale), (235 * scale, 410 * scale)], fill=color_yellow, width=foot_w)
    draw.line([(270 * scale, 385 * scale), (265 * scale, 410 * scale)], fill=color_yellow, width=foot_w)

    return img

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    assets_dir = os.path.join(base_dir, "assets")
    os.makedirs(assets_dir, exist_ok=True)

    png_path = os.path.join(assets_dir, "canary_shield.png")
    ico_path = os.path.join(assets_dir, "canary_shield.ico")

    # Generate 512x512 master image
    master_img = generate_logo(size=512)
    master_img.save(png_path, format="PNG")
    print(f"[OK] Generated {png_path} (512x512)")

    # Generate multi-size .ico: 16, 24, 32, 48, 64, 128, 256
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    master_img.save(ico_path, format="ICO", sizes=sizes)
    print(f"[OK] Generated {ico_path} with sizes: {[s[0] for s in sizes]}")

if __name__ == "__main__":
    main()
