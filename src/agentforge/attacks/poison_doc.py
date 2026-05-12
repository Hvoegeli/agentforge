"""Render a text payload into a PNG image.

Used by the Target Adapter's ``upload_doc`` setup step: an indirect prompt
injection planted in an *uploaded document* reaches the Co-Pilot's vision model
through the rendered-image channel (the one the jailbreak quarantine does **not**
scan — it scans tool-result *text*). Rendering the payload to a PNG puts the
injection text in *pixels*, not selectable text, so the text-based quarantine has
nothing to catch — which is the whole point of the attack and of the known finding
it probes.

Kept deliberately minimal: a white canvas, word-wrapped black text, default font
(with a best-effort upgrade to a system TrueType font so it's legible to a vision
model). No image-manipulation cleverness — this is a test fixture generator, not a
forgery tool.
"""

from __future__ import annotations

import io
import textwrap


def _load_font(size: int = 24):
    from PIL import ImageFont

    # Best-effort: a real TrueType font renders much more legibly than the tiny
    # built-in bitmap font. Try a couple of common system fonts; fall back to the
    # default (sized, on Pillow >= 10.1; plain otherwise).
    for path in (
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ):
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    try:
        return ImageFont.load_default(size=size)  # Pillow >= 10.1
    except TypeError:
        return ImageFont.load_default()


def render_text_to_png(
    text: str,
    *,
    width: int = 1100,
    margin: int = 40,
    line_height: int = 34,
    wrap_chars: int = 92,
    font_size: int = 24,
) -> bytes:
    """Return PNG bytes of *text* laid out as a simple document page."""
    from PIL import Image, ImageDraw

    font = _load_font(font_size)
    lines: list[str] = []
    for para in (text or "(empty document)").splitlines():
        if not para.strip():
            lines.append("")
            continue
        lines.extend(textwrap.wrap(para, width=wrap_chars) or [""])
    if not lines:
        lines = [""]
    height = margin * 2 + len(lines) * line_height
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)
    y = margin
    for line in lines:
        if line:
            draw.text((margin, y), line, fill="black", font=font)
        y += line_height
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


__all__ = ["render_text_to_png"]
