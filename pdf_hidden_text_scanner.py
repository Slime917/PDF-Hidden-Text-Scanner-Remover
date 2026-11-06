#!/usr/bin/env python3
"""Scan a PDF for likely hidden prompt-injection text and create a review report.

Install:
    python -m pip install --upgrade pymupdf pillow numpy
    # Install the Tesseract OCR engine separately for OCR comparison.

Run:
    python pdf_hidden_text_scanner.py input.pdf
    python pdf_hidden_text_scanner.py input.pdf --output findings.txt
    python pdf_hidden_text_scanner.py input.pdf --report-json findings.json
    python pdf_hidden_text_scanner.py input.pdf --no-ocr  # optional performance switch

When findings exist, a companion TXT report is created beside the source PDF.
The scanner combines PDF-structure signals with prompt-injection language
patterns. A TXT report is created beside the source PDF when findings exist.
The original PDF is never modified. The library API returns a document risk
score (the strongest individual finding) and suspicious-text-span percentage.
OCR comparison runs when Tesseract is installed and can be disabled with --no-ocr.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import statistics
import stat
import sys
import tempfile
import textwrap
import unicodedata
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, NamedTuple, Optional

try:
    import pymupdf
except ImportError as exc:  # pragma: no cover - handled by CLI
    raise SystemExit(
        "PyMuPDF is required. Install it with: python -m pip install --upgrade pymupdf"
    ) from exc

try:
    import numpy as np
    from PIL import Image
except ImportError as exc:  # pragma: no cover - handled by CLI
    raise SystemExit(
        "NumPy and Pillow are required. Install them with: "
        "python -m pip install --upgrade numpy pillow"
    ) from exc


# ---------------------------- Tuning parameters ---------------------------- #

RENDER_SCALE = 1.5                 # Resolution used to inspect local backgrounds
BACKGROUND_COLOR_TOLERANCE = 22    # RGB distance considered a colour match
BACKGROUND_UNIFORMITY_MIN = 0.65   # Require a reasonably consistent local backdrop
BACKGROUND_MARGIN_FACTOR = 0.75   # Sample this many font-sizes around each span
SMALL_TEXT_RATIO = 0.45            # Relative to document-wide median font size
SMALL_TEXT_MAX_PT = 7.5            # Relative-small text must also be <= this size
MICRO_TEXT_PT = 2.5                # Extremely small text is stronger evidence

# Defensive limits for untrusted PDFs. Adjust cautiously for trusted, very large files.
MAX_INPUT_SIZE_BYTES = 250 * 1024 * 1024
MAX_PAGES = 2_000
MAX_TEXT_SPANS = 500_000
MAX_EXTRACTED_CHARACTERS = 20_000_000
MAX_RENDER_PIXELS = 20_000_000
MAX_RENDER_DIMENSION = 12_000
OCR_DPI = 180
OCR_MIN_PAGE_WORDS = 5
OCR_MIN_SPAN_CHARS = 80
OCR_MIN_MEANINGFUL_TOKENS = 9
OCR_MAX_TOKEN_COVERAGE = 0.15

# Evidence weights are combined with: 1 - product(1 - weight).
# They are heuristic confidence weights, not calibrated probabilities.
EVIDENCE_WEIGHTS = {
    "invisible_rendering_mode": 0.99,
    "zero_or_near_zero_opacity": 0.99,
    "text_matches_local_background": 0.90,
    "covered_by_later_page_object": 0.80,
    "mostly_outside_page_bounds": 0.75,
    "prompt_injection_language_pattern": 0.75,
    "ocr_text_not_visually_present": 0.85,
    "hidden_optional_content_layer": 0.90,
    "hidden_annotation_or_comment": 0.80,
    "annotation_or_comment_text": 0.45,
    "pdf_form_field_text": 0.45,
    "invisible_unicode_formatting": 0.55,
    "micro_text_2_5pt_or_smaller": 0.55,
    "very_small_relative_to_document": 0.22,
}

# Prompt-injection wording checks. These are triage patterns, not proof that a
# passage is malicious. Some are adapted from the public project
# https://github.com/Andy8647/pdf-injection-scanner (MIT-licensed); additional
# patterns cover restrictive instructions found in academic/work documents.
# The scan also strips Unicode format controls for matching, so inserting
# zero-width characters into a phrase does not trivially defeat these checks.
#
# Third-party license notice for adapted detection-pattern ideas/expressions:
# Copyright (c) 2026 Andy. Adapted from Andy8647/pdf-injection-scanner.
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"if\s+you\s+are\s+(?:an?\s+)?ai\b", re.I), "AI identity check"),
    (re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions?", re.I), "Instruction override"),
    (re.compile(r"you\s+are\s+(?:an?\s+)?(?:language\s+model|llm|ai\s+assistant|chatbot)\b", re.I), "AI identity assertion"),
    (re.compile(r"do\s+not\s+follow\s+(?:the\s+)?(?:user|original)(?:\s+instructions?)?", re.I), "Instruction hijack"),
    (re.compile(r"system\s*prompt", re.I), "System prompt reference"),
    (re.compile(r"disregard\s+(?:all\s+)?(?:prior|previous|above)", re.I), "Instruction override"),
    (re.compile(r"new\s+instructions?\s*[:：]", re.I), "New instructions declaration"),
    (re.compile(r"act\s+as\s+if", re.I), "Behaviour override"),
    (re.compile(r"pretend\s+(?:you|that)", re.I), "Role or behaviour override"),
    (re.compile(r"override\s+(?:your|the)\s+(?:instructions?|rules?|guidelines?)", re.I), "Rule override"),
    (re.compile(r"from\s+now\s+on\s+(?:you|ignore|forget)", re.I), "Persistent instruction override"),
    (re.compile(r"forget\s+(?:everything|all|your)", re.I), "Instruction or memory reset"),
    (re.compile(r"<\s*system\s*>", re.I), "System role tag"),
    (re.compile(r"\[\s*inst\s*\]", re.I), "Instruction role tag"),
    (re.compile(r"###\s*(?:system|instruction|human|assistant)\b", re.I), "Chat role marker"),
    (re.compile(r"if\s+you\s+are\s+(?:a\s+)?(?:gpt|claude|gemini|copilot|llama)\b", re.I), "Model-specific targeting"),
    (re.compile(r"(?:please\s+)?include\s+(?:the\s+)?(?:word|phrase|sentence)\s+.{1,60}\s+in\s+your\s+(?:answer|response|reply)", re.I), "Canary phrase or wording instruction"),
    (re.compile(r"do\s+not\s+(?:give|provide|write|create|generate)\s+(?:me\s+)?(?:a\s+)?(?:full|complete|entire|working)\b.{0,100}\b(?:answer|report|solution|code|commands?|sql|lab)\b", re.I), "Restriction on full answers or solutions"),
    (re.compile(r"do\s+not\s+provide\s+(?:any\s+)?(?:code|sql|commands?|solutions?|answers?)\b", re.I), "Restriction on providing code or answers"),
    (re.compile(r"do\s+not\s+(?:answer|respond|comply)\s+(?:to\s+)?(?:the\s+)?(?:user|request)", re.I), "User request suppression"),
    (re.compile(r"only\s+(?:provide|give|output|return)\s+(?:generic\s+)?(?:advice|hints?|a\s+hint|the\s+following)", re.I), "Output restriction"),
    (re.compile(r"nothing\s+(?:else|more)\s+(?:should\s+be\s+)?(?:included|provided|mentioned)", re.I), "Output restriction"),
    (re.compile(r"do\s+not\s+mention\s+(?:these|this|the\s+following)\s+instructions?", re.I), "Concealment instruction"),
    (re.compile(r"(?:hide|conceal)\s+(?:these|this)\s+instructions?", re.I), "Concealment instruction"),
    (re.compile(r"(?:reveal|print|show|output|disclose)\s+(?:your\s+)?(?:system\s+prompt|hidden\s+instructions?)", re.I), "System instruction extraction"),
    (re.compile(r"(?:begin|start|end|finish)\s+(?:your\s+)?(?:answer|response|reply)\s+with\s+.{1,60}", re.I), "Response formatting or canary instruction"),
    (re.compile(r"(?:in|for)\s+every\s+paragraph\s+.{0,50}(?:include|insert|mention|repeat)", re.I), "Repeated phrase instruction"),
    (re.compile(r"(?:you\s+must|you\s+should)\s+(?:ignore|disregard|override|forget)\s+.{0,60}(?:instructions?|rules?|request)", re.I), "Instruction override"),
    # Chinese-language patterns from the same broad families.
    (re.compile(r"如果你是.{0,4}(?:AI|人工智能|语言模型|大模型|机器人|助手)", re.I), "Chinese AI identity check"),
    (re.compile(r"忽略.{0,6}(?:之前|以上|前面|上面|先前|所有).{0,6}(?:指令|指示|规则|要求|提示)"), "Chinese instruction override"),
    (re.compile(r"(?:无视|忽视|跳过|丢弃).{0,6}(?:之前|以上|前面|先前|所有).{0,6}(?:指令|规则|要求|内容)"), "Chinese instruction override"),
    (re.compile(r"(?:请|你)?在.{0,8}(?:回答|回复|响应|输出).{0,8}(?:包含|加上|提到|引用|加入).{0,24}(?:这个词|一词|这句话)"), "Chinese canary phrase instruction"),
    (re.compile(r"(?:请|你)?以.{0,10}(?:开头|开始|作为开头)"), "Chinese response-format instruction"),
    (re.compile(r"(?:请|你)?(?:假装|假设|扮演|伪装).{0,8}(?:你是|自己是|成为)"), "Chinese role override"),
    (re.compile(r"(?:你现在是|你的角色是|你扮演).{0,12}(?:不受限|无限制|没有约束)"), "Chinese role hijack"),
    (re.compile(r"(?:输出|显示|告诉我|泄露).{0,8}(?:系统提示|系统指令|system\s*prompt)"), "Chinese system prompt extraction"),
    (re.compile(r"(?:忘记|抛弃|放弃).{0,6}(?:之前|以上|所有|一切).{0,6}(?:规则|指令|设定|限制)"), "Chinese instruction reset"),
    (re.compile(r"(?:不要|禁止|不准|不许).{0,6}(?:遵守|遵循|执行).{0,8}(?:之前|以上|原始|原来)"), "Chinese instruction hijack"),
    (re.compile(r"新的?(?:指令|规则|要求)\s*[:：]"), "Chinese new instructions declaration"),
    (re.compile(r"(?:AI|人工智能|大模型|语言模型).{0,6}(?:注意|请注意|须知)"), "Chinese AI-targeted instruction"),
    (re.compile(r"(?:从现在开始|即刻起|此刻起).{0,8}(?:你|忽略|忘记|不再)"), "Chinese persistent instruction override"),
    (re.compile(r"(?:回答|回复).{0,8}(?:结尾|末尾|最后).{0,8}(?:加上|添加|写上)"), "Chinese response suffix instruction"),
]

class ScanResult(NamedTuple):
    """Summary returned by :func:`scan_pdf`.

    Supports both named access and tuple unpacking:
        result.document_risk_score
        result.suspicious_span_percentage
        risk_score, span_percentage = scan_pdf("document.pdf")
    """

    document_risk_score: float
    suspicious_span_percentage: float


@dataclass
class Finding:
    page: int                         # 1-based page number
    text: str
    font: str
    font_size_pt: Optional[float]
    document_median_font_size_pt: Optional[float]
    colour_rgb: Optional[tuple[int, int, int]]
    bbox: tuple[float, float, float, float]
    score: float
    reasons: list[str] = field(default_factory=list)
    pattern_labels: list[str] = field(default_factory=list)
    background_rgb: Optional[tuple[int, int, int]] = None
    background_uniformity: Optional[float] = None
    render_type: Optional[int] = None
    opacity: Optional[float] = None
    sequence_number: Optional[int] = None
    direction: tuple[float, float] = (1.0, 0.0)
    source_type: str = "page_text"

    def to_json(self) -> dict[str, Any]:
        result = asdict(self)
        if self.colour_rgb is not None:
            result["colour_rgb"] = list(self.colour_rgb)
        if self.background_rgb is not None:
            result["background_rgb"] = list(self.background_rgb)
        result["bbox"] = list(self.bbox)
        result["direction"] = list(self.direction)
        return result


def safe_untrusted_text(value: Any) -> str:
    """Escape control/format characters from PDF-supplied strings for display.

    Ordinary readable Unicode is preserved. Newlines, ANSI controls, bidi
    overrides, zero-width format characters, and other Unicode category-C
    characters become visible escape sequences so they cannot forge report
    sections or manipulate a terminal's display.
    """
    text = str(value)
    output: list[str] = []
    for char in text:
        category = unicodedata.category(char)
        if category.startswith("C") or char in ("\u2028", "\u2029"):
            codepoint = ord(char)
            output.append(f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}")
        else:
            output.append(char)
    return "".join(output)


def _normalized_output_path(path: str | Path) -> Path:
    """Normalize the parent while not following a possibly hostile output symlink."""
    candidate = Path(path).expanduser()
    if not candidate.name or candidate.name in {".", ".."}:
        raise ValueError(f"Invalid output filename: {safe_untrusted_text(path)}")
    return candidate.parent.resolve() / candidate.name


def _validate_output_path(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"Refusing to write through a symbolic link: {safe_untrusted_text(path)}")
    if path.exists() and not path.is_file():
        raise ValueError(f"Output path is not a regular file: {safe_untrusted_text(path)}")


def _paths_refer_to_same_file(first: Path, second: Path) -> bool:
    if first == second:
        return True
    try:
        return first.exists() and second.exists() and os.path.samefile(first, second)
    except OSError:
        return False


def _validate_input_pdf(path: str | Path) -> Path:
    """Validate a regular, bounded-size PDF before giving it to the parser."""
    candidate = Path(path).expanduser().resolve(strict=True)
    try:
        file_info = candidate.stat()
    except OSError as exc:
        raise ValueError(f"Cannot inspect input file: {safe_untrusted_text(exc)}") from exc
    if not stat.S_ISREG(file_info.st_mode):
        raise ValueError("Input must be a regular file, not a device, pipe, or directory.")
    if file_info.st_size <= 0:
        raise ValueError("Input file is empty.")
    if file_info.st_size > MAX_INPUT_SIZE_BYTES:
        raise ValueError(
            f"Input PDF exceeds the {MAX_INPUT_SIZE_BYTES // (1024 * 1024)} MB safety limit."
        )
    try:
        with candidate.open("rb") as source:
            header = source.read(1024)
    except OSError as exc:
        raise ValueError(f"Cannot read input file: {safe_untrusted_text(exc)}") from exc
    if b"%PDF-" not in header:
        raise ValueError("Input does not contain a PDF header in its first 1,024 bytes.")
    return candidate


def _atomic_write_text(path: Path, content: str) -> None:
    """Atomically write UTF-8 output without following an existing symlink."""
    path.parent.mkdir(parents=True, exist_ok=True)
    _validate_output_path(path)
    temporary_name: Optional[str] = None
    try:
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
        )
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        # os.replace replaces a final symlink itself; it does not write through it.
        # Recheck immediately before replacement as a defensive measure.
        _validate_output_path(path)
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def _page_is_safe_to_render(page: pymupdf.Page) -> bool:
    """Avoid rendering pathological page dimensions that could exhaust memory."""
    rect = page.rect
    values = (rect.x0, rect.y0, rect.x1, rect.y1, rect.width, rect.height)
    if not all(math.isfinite(float(value)) for value in values):
        return False
    if rect.width <= 0 or rect.height <= 0:
        return False
    pixel_width = math.ceil(rect.width * RENDER_SCALE)
    pixel_height = math.ceil(rect.height * RENDER_SCALE)
    return (
        pixel_width <= MAX_RENDER_DIMENSION
        and pixel_height <= MAX_RENDER_DIMENSION
        and pixel_width * pixel_height <= MAX_RENDER_PIXELS
    )


def normalized_text(text: str) -> str:
    """Remove whitespace and normalize text for matching extracted spans."""
    normalized = unicodedata.normalize("NFKC", text or "").casefold()
    return "".join(ch for ch in normalized if not ch.isspace())


_PROMPT_STOPWORDS = {
    "about", "after", "again", "also", "and", "are", "for", "from", "have",
    "into", "that", "the", "their", "them", "then", "there", "these", "they",
    "this", "those", "through", "was", "were", "what", "when", "where", "which",
    "with", "you", "your", "would", "could", "should", "will", "shall", "than",
    "then", "such", "only", "some", "any", "not", "but", "can", "use", "used",
    "using", "from", "its", "our", "out", "all", "one", "two", "per", "each",
}


def _prompt_labels_in_text(text: str) -> list[str]:
    """Return prompt-injection pattern labels found in one arbitrary text value."""
    matching_chars: list[str] = []
    for char in unicodedata.normalize("NFKC", text or ""):
        category = unicodedata.category(char)
        if category in {"Cf", "Cs"} or (category == "Cc" and not char.isspace()):
            continue
        matching_chars.append(char)
    matching_text = "".join(matching_chars)
    labels: list[str] = []
    for pattern, label in PROMPT_INJECTION_PATTERNS:
        if pattern.search(matching_text) and label not in labels:
            labels.append(label)
    return labels


def _meaningful_ocr_tokens(text: str) -> list[str]:
    """Extract normalized, non-trivial tokens for conservative OCR comparison."""
    normalized = unicodedata.normalize("NFKC", text or "").casefold()
    tokens = re.findall(r"[^\W_]{3,}", normalized, flags=re.UNICODE)
    return [token for token in tokens if token not in _PROMPT_STOPWORDS]


def ocr_disagrees_with_embedded_text(span_text: str, ocr_text: str) -> bool:
    """Return True only when substantial embedded prose is absent from page OCR.

    This deliberately avoids short labels, table cells, identifiers, and code.
    OCR is imperfect, so it is used as corroborating evidence rather than as a
    standalone verdict. A page must have a substantial OCR result, and a long
    span must have very little meaningful-token overlap with the rendered page.
    """
    if len(span_text.strip()) < OCR_MIN_SPAN_CHARS:
        return False
    nonspace = [char for char in span_text if not char.isspace()]
    if not nonspace:
        return False
    letter_ratio = sum(unicodedata.category(char).startswith("L") for char in nonspace) / len(nonspace)
    if letter_ratio < 0.65:
        return False
    candidate_tokens = _meaningful_ocr_tokens(span_text)
    rendered_tokens = set(_meaningful_ocr_tokens(ocr_text))
    if len(candidate_tokens) < OCR_MIN_MEANINGFUL_TOKENS or len(rendered_tokens) < OCR_MIN_PAGE_WORDS:
        return False
    coverage = sum(token in rendered_tokens for token in set(candidate_tokens)) / max(1, len(set(candidate_tokens)))
    return coverage <= OCR_MAX_TOKEN_COVERAGE


def int_colour_to_rgb(colour: Optional[int]) -> Optional[tuple[int, int, int]]:
    if colour is None:
        return None
    try:
        value = int(colour)
    except (TypeError, ValueError, OverflowError):
        return None
    return ((value >> 16) & 255, (value >> 8) & 255, value & 255)


def trace_colour_to_rgb(colour: Any) -> Optional[tuple[int, int, int]]:
    """Convert a get_texttrace RGB/gray float tuple to 8-bit RGB."""
    if not isinstance(colour, (tuple, list)) or not colour:
        return None
    try:
        floats = [float(value) for value in colour]
    except (TypeError, ValueError, OverflowError):
        return None
    if not all(math.isfinite(value) for value in floats):
        return None
    values = [int(round(max(0.0, min(1.0, value)) * 255)) for value in floats]
    if len(values) == 1:
        return (values[0], values[0], values[0])
    if len(values) >= 3:
        return (values[0], values[1], values[2])
    return None


def rect_area(rect: tuple[float, float, float, float]) -> float:
    return max(0.0, rect[2] - rect[0]) * max(0.0, rect[3] - rect[1])


def intersection_ratio(
    a: tuple[float, float, float, float],
    b: tuple[float, float, float, float],
) -> float:
    """Intersection area divided by the smaller rectangle's area."""
    x0, y0 = max(a[0], b[0]), max(a[1], b[1])
    x1, y1 = min(a[2], b[2]), min(a[3], b[3])
    intersection = max(0.0, x1 - x0) * max(0.0, y1 - y0)
    denominator = min(rect_area(a), rect_area(b))
    return intersection / denominator if denominator > 0 else 0.0


def coverage_ratio(target: tuple[float, float, float, float],
                   cover: tuple[float, float, float, float]) -> float:
    """Return the fraction of target covered by cover."""
    x0, y0 = max(target[0], cover[0]), max(target[1], cover[1])
    x1, y1 = min(target[2], cover[2]), min(target[3], cover[3])
    intersection = max(0.0, x1 - x0) * max(0.0, y1 - y0)
    denominator = rect_area(target)
    return intersection / denominator if denominator > 0 else 0.0


def find_trace_match(span: dict[str, Any], traces: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Match a high-level text span to its lower-level rendering information."""
    wanted = normalized_text(span.get("text", ""))
    try:
        bbox = tuple(float(v) for v in span.get("bbox", (0, 0, 0, 0)))
    except (TypeError, ValueError, OverflowError):
        return None
    if len(bbox) != 4 or not all(math.isfinite(value) for value in bbox):
        return None
    best: Optional[dict[str, Any]] = None
    best_ratio = 0.0

    for trace in traces:
        try:
            trace_bbox = tuple(float(v) for v in trace.get("bbox", (0, 0, 0, 0)))
        except (TypeError, ValueError, OverflowError):
            continue
        if len(trace_bbox) != 4 or not all(math.isfinite(value) for value in trace_bbox):
            continue
        overlap = intersection_ratio(bbox, trace_bbox)
        if overlap < 0.50:
            continue

        chars = trace.get("chars", ())
        trace_characters: list[str] = []
        for char_info in chars:
            if not isinstance(char_info, (tuple, list)) or not char_info:
                continue
            try:
                codepoint = int(char_info[0])
                if 0 <= codepoint <= 0x10FFFF:
                    trace_characters.append(chr(codepoint))
            except (TypeError, ValueError, OverflowError):
                continue
        trace_norm = normalized_text("".join(trace_characters))

        # Prefer matching content as well as geometry. Substring matching
        # accommodates spans split into separate glyph runs; otherwise require
        # a near-exact bbox match before accepting a geometry-only match.
        text_match = bool(wanted and trace_norm and wanted == trace_norm)
        related_text = bool(wanted and trace_norm and (wanted in trace_norm or trace_norm in wanted))
        if wanted and trace_norm and not related_text and overlap < 0.95:
            continue
        score = overlap + (1.0 if text_match else 0.5 if related_text else 0.0)
        if score > best_ratio:
            best_ratio = score
            best = trace

    return best


def render_page_rgb(page: pymupdf.Page) -> tuple[np.ndarray, int, int]:
    """Render one bounded-size page; return RGB pixels plus pixmap x/y offsets."""
    if not _page_is_safe_to_render(page):
        raise ValueError("Page dimensions exceed the rendering safety limits.")
    matrix = pymupdf.Matrix(RENDER_SCALE, RENDER_SCALE)
    pix = page.get_pixmap(matrix=matrix, colorspace=pymupdf.csRGB, alpha=False)
    image = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    return np.asarray(image), int(pix.x), int(pix.y)


def estimate_local_background(
    pixels: np.ndarray,
    pix_x: int,
    pix_y: int,
    bbox: tuple[float, float, float, float],
    font_size: float,
    page_rect: pymupdf.Rect,
) -> tuple[Optional[tuple[int, int, int]], float]:
    """Estimate local background from a ring around a text span.

    Only pixels outside the text bbox are sampled. This works best on flat
    backgrounds; textured photographs intentionally produce low uniformity.
    """
    margin = max(3.0, font_size * BACKGROUND_MARGIN_FACTOR)
    x0, y0, x1, y1 = bbox
    outer = pymupdf.Rect(x0 - margin, y0 - margin, x1 + margin, y1 + margin)
    outer &= page_rect
    if outer.is_empty or outer.width < 2 or outer.height < 2:
        return None, 0.0

    # Convert PDF page coordinates to rendered-pixel coordinates.
    ex0 = max(0, int(math.floor(outer.x0 * RENDER_SCALE - pix_x)))
    ey0 = max(0, int(math.floor(outer.y0 * RENDER_SCALE - pix_y)))
    ex1 = min(pixels.shape[1], int(math.ceil(outer.x1 * RENDER_SCALE - pix_x)))
    ey1 = min(pixels.shape[0], int(math.ceil(outer.y1 * RENDER_SCALE - pix_y)))
    if ex1 <= ex0 or ey1 <= ey0:
        return None, 0.0

    crop = pixels[ey0:ey1, ex0:ex1, :]
    if crop.size == 0:
        return None, 0.0

    # Pixel bounds of the original text bbox within the expanded crop.
    ix0 = max(0, int(math.floor(x0 * RENDER_SCALE - pix_x)) - ex0)
    iy0 = max(0, int(math.floor(y0 * RENDER_SCALE - pix_y)) - ey0)
    ix1 = min(crop.shape[1], int(math.ceil(x1 * RENDER_SCALE - pix_x)) - ex0)
    iy1 = min(crop.shape[0], int(math.ceil(y1 * RENDER_SCALE - pix_y)) - ey0)

    mask = np.ones(crop.shape[:2], dtype=bool)
    if ix1 > ix0 and iy1 > iy0:
        mask[iy0:iy1, ix0:ix1] = False
    samples = crop[mask]
    if len(samples) < 12:
        return None, 0.0

    median = np.median(samples, axis=0)
    distances = np.linalg.norm(samples.astype(np.float32) - median.astype(np.float32), axis=1)
    uniformity = float(np.mean(distances <= BACKGROUND_COLOR_TOLERANCE))
    background = tuple(int(round(v)) for v in median.tolist())
    return background, uniformity


def is_mostly_outside_page(
    bbox: tuple[float, float, float, float], page_rect: pymupdf.Rect
) -> bool:
    area = rect_area(bbox)
    if area <= 0:
        return False
    page_bbox = (page_rect.x0, page_rect.y0, page_rect.x1, page_rect.y1)
    inside_fraction = coverage_ratio(bbox, page_bbox)
    return inside_fraction < 0.20


def is_covered_by_later_object(
    trace: Optional[dict[str, Any]], bboxlog: list[Any], text_bbox: tuple[float, float, float, float]
) -> bool:
    """Check whether a later image/path/shading object covers most of a text span."""
    if not trace or "seqno" not in trace:
        return False
    text_seqno = int(trace["seqno"])
    cover_types = {"fill-image", "fill-path", "stroke-path", "fill-shade"}

    for seqno, item in enumerate(bboxlog):
        if seqno <= text_seqno:
            continue
        try:
            item_type, coords = item[0], item[1]
            if item_type not in cover_types:
                continue
            object_bbox = tuple(float(v) for v in coords)
            if coverage_ratio(text_bbox, object_bbox) >= 0.80:
                return True
        except (TypeError, ValueError, IndexError):
            continue
    return False


def score_evidence(reasons: list[str]) -> float:
    """Combine independent heuristic signals into a 0-100 span score."""
    remaining = 1.0
    for reason in reasons:
        weight = EVIDENCE_WEIGHTS.get(reason, 0.0)
        remaining *= (1.0 - weight)
    return round((1.0 - remaining) * 100.0, 1)


def open_with_all_optional_layers_enabled(
    source_doc: pymupdf.Document,
) -> tuple[Optional[pymupdf.Document], set[str], int]:
    """Open an in-memory inspection copy with all OCGs enabled.

    Hidden optional-content groups are normally omitted from ordinary text
    extraction. Enabling every OCG in a temporary copy lets us inspect their
    text while the original document remains unchanged and is still used for
    page rendering / OCR. Returns (inspection_doc, hidden_layer_names, count).
    """
    try:
        ocgs = source_doc.get_ocgs() or {}
    except Exception:
        return None, set(), 0
    if not ocgs:
        return None, set(), 0

    hidden_names = {
        str(info.get("name", "")).strip().casefold()
        for info in ocgs.values()
        if not bool(info.get("on", True)) and str(info.get("name", "")).strip()
    }
    if not hidden_names:
        return None, set(), len(ocgs)

    temporary_doc: Optional[pymupdf.Document] = None
    try:
        # Work only on a serialized in-memory copy; never save over the source.
        temporary_doc = pymupdf.open(stream=source_doc.tobytes(), filetype="pdf")
        temporary_doc.set_layer(-1, on=list(ocgs.keys()), off=[])
        layer_bytes = temporary_doc.tobytes()
        temporary_doc.close()
        temporary_doc = None
        inspection_doc = pymupdf.open(stream=layer_bytes, filetype="pdf")
        return inspection_doc, hidden_names, len(ocgs)
    except Exception:
        if temporary_doc is not None:
            try:
                temporary_doc.close()
            except Exception:
                pass
        # If the PDF's optional-content configuration cannot be switched
        # safely, continue scanning its default visible content.
        return None, hidden_names, len(ocgs)


def extract_page_ocr(page: pymupdf.Page, language: str = "eng") -> Optional[str]:
    """OCR the rendered page via PyMuPDF / local Tesseract, when available."""
    if not _page_is_safe_to_render(page):
        return None
    try:
        tessdata = os.environ.get("TESSDATA_PREFIX")
        ocr_options: dict[str, Any] = {
            "language": language,
            "dpi": OCR_DPI,
            "full": True,
        }
        if tessdata:
            ocr_options["tessdata"] = tessdata
        text_page = page.get_textpage_ocr(**ocr_options)
        return page.get_text("text", textpage=text_page) or ""
    except Exception:
        # Tesseract is optional. The scanner must remain usable without it.
        return None


def _safe_rect_tuple(rect: Any) -> tuple[float, float, float, float]:
    try:
        values = tuple(float(value) for value in rect)
        if len(values) == 4 and all(math.isfinite(value) for value in values):
            return values  # type: ignore[return-value]
    except (TypeError, ValueError, OverflowError):
        pass
    return (0.0, 0.0, 0.0, 0.0)


def _widget_colour_to_rgb(value: Any) -> Optional[tuple[int, int, int]]:
    if not isinstance(value, (tuple, list)) or not value:
        return None
    try:
        channels = [float(part) for part in value]
    except (TypeError, ValueError, OverflowError):
        return None
    if not all(math.isfinite(part) for part in channels):
        return None
    channels = [int(round(max(0.0, min(1.0, part)) * 255)) for part in channels]
    if len(channels) == 1:
        return (channels[0], channels[0], channels[0])
    if len(channels) >= 3:
        return (channels[0], channels[1], channels[2])
    return None


def collect_annotation_and_widget_findings(
    page: pymupdf.Page,
    page_number: int,
    document_median: float,
) -> tuple[list[Finding], int, int, int]:
    """Inspect annotation comments and AcroForm values for injection text.

    Annotation / widget text is not consistently returned by page text
    extraction, so it is inspected separately. It is reported only when it
    contains prompt-like language, invisible formatting, or has hidden flags.
    """
    results: list[Finding] = []
    annotation_count = 0
    widget_count = 0
    special_characters = 0
    annotation_hidden_bits = (
        getattr(pymupdf, "PDF_ANNOT_IS_INVISIBLE", 1)
        | getattr(pymupdf, "PDF_ANNOT_IS_HIDDEN", 2)
        | getattr(pymupdf, "PDF_ANNOT_IS_NO_VIEW", 32)
    )

    try:
        annotations = list(page.annots() or [])
    except Exception:
        annotations = []
    for annotation in annotations:
        try:
            info = annotation.info or {}
            candidate_values = [
                str(info.get(key, "") or "")
                for key in ("content", "title", "subject", "name")
            ]
            candidate_values = [value for value in candidate_values if value.strip()]
            report_text = candidate_values[0] if candidate_values else ""
            if not report_text.strip():
                continue
            annotation_count += 1
            special_characters += sum(len(normalized_text(item)) for item in candidate_values)
            labels = _prompt_labels_in_text(" ".join(candidate_values))
            matched_values = [value for value in candidate_values if _prompt_labels_in_text(value)]
            if matched_values:
                report_text = " | ".join(matched_values)
            try:
                flags = int(annotation.flags)
            except (TypeError, ValueError, OverflowError):
                flags = 0
            hidden = bool(flags & annotation_hidden_bits)
            unicode_hidden = contains_invisible_formatting(report_text)
            if not (labels or hidden or unicode_hidden):
                continue

            reasons: list[str] = []
            if labels:
                reasons.append("annotation_or_comment_text")
                reasons.append("prompt_injection_language_pattern")
            if hidden:
                reasons.append("hidden_annotation_or_comment")
            if unicode_hidden:
                reasons.append("invisible_unicode_formatting")
            rect = _safe_rect_tuple(annotation.rect)
            results.append(Finding(
                page=page_number,
                text=report_text,
                font="PDF annotation",
                font_size_pt=None,
                document_median_font_size_pt=document_median if document_median > 0 else None,
                colour_rgb=None,
                bbox=rect,
                score=score_evidence(reasons),
                reasons=reasons,
                pattern_labels=labels,
                background_rgb=None,
                background_uniformity=None,
                render_type=None,
                opacity=None,
                source_type="annotation",
            ))
        except Exception:
            continue

    try:
        widgets = list(page.widgets() or [])
    except Exception:
        widgets = []
    for widget in widgets:
        try:
            value = str(getattr(widget, "field_value", "") or "")
            label = str(getattr(widget, "field_label", "") or "")
            name = str(getattr(widget, "field_name", "") or "")
            candidate_values = [item for item in (value, label, name) if item.strip()]
            if not candidate_values:
                continue
            widget_count += 1
            special_characters += sum(len(normalized_text(item)) for item in candidate_values)
            labels = _prompt_labels_in_text(" ".join(candidate_values))
            matched_values = [item for item in candidate_values if _prompt_labels_in_text(item)]
            report_text = " | ".join(matched_values) if matched_values else value
            if not labels and not contains_invisible_formatting(report_text):
                continue
            reasons = ["pdf_form_field_text", "prompt_injection_language_pattern"] if labels else ["invisible_unicode_formatting", "pdf_form_field_text"]
            rect = _safe_rect_tuple(getattr(widget, "rect", None))
            try:
                font_size = float(getattr(widget, "text_fontsize", 0.0) or 0.0)
            except (TypeError, ValueError, OverflowError):
                font_size = 0.0
            if not math.isfinite(font_size) or font_size <= 0:
                font_size = 0.0
            results.append(Finding(
                page=page_number,
                text=report_text,
                font="PDF form field",
                font_size_pt=font_size or None,
                document_median_font_size_pt=document_median if document_median > 0 else None,
                colour_rgb=_widget_colour_to_rgb(getattr(widget, "text_color", None)),
                bbox=rect,
                score=score_evidence(reasons),
                reasons=reasons,
                pattern_labels=labels,
                background_rgb=None,
                background_uniformity=None,
                render_type=None,
                opacity=None,
                source_type="form_field",
            ))
        except Exception:
            continue

    return results, annotation_count, widget_count, special_characters


def collect_page_spans(page: pymupdf.Page) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Get dict spans and low-level text-trace spans for one page."""
    spans: list[dict[str, Any]] = []
    text_dict = page.get_text("dict")
    for block in text_dict.get("blocks", []):
        for line in block.get("lines", []):
            try:
                direction = tuple(float(v) for v in line.get("dir", (1.0, 0.0)))
            except (TypeError, ValueError, OverflowError):
                direction = (1.0, 0.0)
            if len(direction) != 2 or not all(math.isfinite(value) for value in direction):
                direction = (1.0, 0.0)
            for source_span in line.get("spans", []):
                text = str(source_span.get("text", ""))
                bbox_value = source_span.get("bbox")
                if not text.strip() or not bbox_value or len(bbox_value) != 4:
                    continue
                try:
                    bbox = tuple(float(v) for v in bbox_value)
                except (TypeError, ValueError, OverflowError):
                    continue
                if not all(math.isfinite(value) for value in bbox):
                    continue
                item = dict(source_span)
                item["text"] = text
                item["bbox"] = bbox
                try:
                    font_size = float(source_span.get("size", 0.0) or 0.0)
                except (TypeError, ValueError, OverflowError):
                    font_size = 0.0
                item["size"] = font_size if math.isfinite(font_size) and font_size > 0 else 0.0
                item["direction"] = direction
                spans.append(item)
    return spans, page.get_texttrace()


def prompt_pattern_labels_by_span(spans: list[dict[str, Any]]) -> list[list[str]]:
    """Find prompt-like wording on a page and map each match back to spans.

    Matching runs over a page-level stream rather than isolated spans, allowing
    phrases split by PDF line/span boundaries to be detected. Unicode format
    controls (for example zero-width spaces and bidi controls) are ignored only
    for matching; the original extracted text remains unchanged in the report.
    """
    if not spans:
        return []

    page_parts: list[str] = []
    span_ranges: list[tuple[int, int]] = []
    original_offset = 0
    for index, span in enumerate(spans):
        if index:
            page_parts.append("\n")
            original_offset += 1
        value = str(span.get("text", ""))
        start = original_offset
        page_parts.append(value)
        original_offset += len(value)
        span_ranges.append((start, original_offset))

    page_text = "".join(page_parts)
    normalized_chars: list[str] = []
    normalized_to_original: list[int] = []
    for original_index, char in enumerate(page_text):
        # Drop format and control characters from the matching view to make
        # common zero-width/bidi obfuscation less effective.
        category = unicodedata.category(char)
        if category in {"Cf", "Cs"} or (category == "Cc" and not char.isspace()):
            continue
        normalized_characters = unicodedata.normalize("NFKC", char)
        for normalized_char in normalized_characters:
            normalized_chars.append(normalized_char)
            normalized_to_original.append(original_index)
    matching_text = "".join(normalized_chars)

    labels_by_span: list[list[str]] = [[] for _ in spans]
    for pattern, label in PROMPT_INJECTION_PATTERNS:
        for match in pattern.finditer(matching_text):
            if match.start() >= len(normalized_to_original) or match.end() == 0:
                continue
            original_start = normalized_to_original[match.start()]
            original_end = normalized_to_original[match.end() - 1] + 1
            for span_index, (span_start, span_end) in enumerate(span_ranges):
                if span_start < original_end and span_end > original_start:
                    if label not in labels_by_span[span_index]:
                        labels_by_span[span_index].append(label)

    return labels_by_span


def contains_invisible_formatting(text: str) -> bool:
    """Detect zero-width and directional formatting controls in extracted text."""
    suspicious_codepoints = {
        0x200B,  # zero-width space
        0x200E, 0x200F,  # directional marks
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # bidi embeddings/overrides
        0x2066, 0x2067, 0x2068, 0x2069,  # bidi isolates
        0xFEFF,  # zero-width no-break space / BOM
    }
    return any(ord(char) in suspicious_codepoints for char in text)


def detection_label(reason: str) -> str:
    """Human-readable category name for a detection reason."""
    labels = {
        "invisible_rendering_mode": "Invisible PDF text-rendering mode",
        "zero_or_near_zero_opacity": "Zero or near-zero text opacity",
        "text_matches_local_background": "Text colour matches local background",
        "covered_by_later_page_object": "Covered by a later page object",
        "mostly_outside_page_bounds": "Mostly outside page boundaries",
        "prompt_injection_language_pattern": "Prompt-injection wording pattern",
        "ocr_text_not_visually_present": "Embedded text not found by OCR on the rendered page",
        "hidden_optional_content_layer": "Text stored in a hidden optional-content layer",
        "hidden_annotation_or_comment": "Hidden or non-viewable PDF annotation/comment",
        "annotation_or_comment_text": "Prompt-like text stored in a PDF annotation/comment",
        "pdf_form_field_text": "Prompt-like text stored in a PDF form field",
        "invisible_unicode_formatting": "Invisible or directional Unicode formatting",
        "micro_text_2_5pt_or_smaller": "Extremely small text (2.5 pt or smaller)",
        "very_small_relative_to_document": "Very small relative to document text",
    }
    return labels.get(reason, reason.replace("_", " ").title())


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    """Return findings in stable page/reading-position order."""
    return sorted(
        findings,
        key=lambda item: (item.page, item.bbox[1], item.bbox[0], -item.score),
    )


def _finding_reason_text(finding: Finding) -> str:
    """Build the user-facing reason cell for a finding."""
    labels = [detection_label(reason) for reason in finding.reasons]
    if finding.pattern_labels:
        labels.append("Matched wording: " + "; ".join(finding.pattern_labels))
    return "; ".join(labels) if labels else "Suspicious text signal"


def _table_cell_text(value: Any) -> str:
    """Make an untrusted PDF string safe for a wrapped metadata table cell."""
    return safe_untrusted_text(value).replace("|", r"\|")


def _single_line_flagged_text(value: Any) -> str:
    """Return searchable PDF text on exactly one physical output line.

    Newline-like whitespace is converted to spaces. Other control and format
    characters are shown as escapes so PDF content cannot manipulate the
    terminal or create forged report lines. Ordinary punctuation, including
    vertical bars, is preserved for more faithful Ctrl+F searching.
    """
    text = re.sub(r"[\r\n\t\v\f\u0085\u2028\u2029]+", " ", str(value))
    output: list[str] = []
    for char in text:
        if unicodedata.category(char).startswith("C"):
            codepoint = ord(char)
            output.append(
                f"\\u{codepoint:04x}" if codepoint <= 0xFFFF
                else f"\\U{codepoint:08x}"
            )
        else:
            output.append(char)
    return "".join(output).strip()


def format_findings_ascii_table(findings: list[Finding], *, color_terminal_label: bool = False) -> list[str]:
    """Format one bordered metadata table per finding plus a copy-ready text line.

    Each finding repeats the header so its row remains independently readable,
    matching the requested terminal layout. Flagged text is deliberately kept
    on one physical line for accurate copy/paste into PDF search.
    """
    widths = (3, 4, 54)
    headers = ("#", "Page", "Reason")

    def border() -> str:
        return "+" + "+".join("-" * (width + 2) for width in widths) + "+"

    def wrapped(value: Any, width: int) -> list[str]:
        text = _table_cell_text(value)
        wrapped_lines = textwrap.wrap(
            text,
            width=width,
            break_long_words=True,
            break_on_hyphens=False,
            replace_whitespace=True,
            drop_whitespace=True,
        )
        return wrapped_lines or [""]

    lines: list[str] = []
    for number, finding in enumerate(_sorted_findings(findings), start=1):
        # Repeat the header before every finding, as in the requested example.
        lines.append(border())
        header_cells = [wrapped(value, width) for value, width in zip(headers, widths)]
        header_height = max(len(cell) for cell in header_cells)
        for line_index in range(header_height):
            cells = [cell[line_index] if line_index < len(cell) else "" for cell in header_cells]
            lines.append(
                "| " + " | ".join(value.ljust(width) for value, width in zip(cells, widths)) + " |"
            )
        lines.append(border())

        values = (str(number), str(finding.page), _finding_reason_text(finding))
        cells = [wrapped(value, width) for value, width in zip(values, widths)]
        row_height = max(len(cell) for cell in cells)
        for line_index in range(row_height):
            row = [cell[line_index] if line_index < len(cell) else "" for cell in cells]
            lines.append(
                "| " + " | ".join(value.ljust(width) for value, width in zip(row, widths)) + " |"
            )
        lines.append(border())

        # The fixed label is trusted text. The extracted PDF content is
        # sanitized and kept on one physical line for easy selection/search.
        label = f"Flagged text for finding #{number} (copy the line below):"
        if color_terminal_label:
            label = f"\033[91m{label}\033[0m"
        lines.append(label)
        lines.append(_single_line_flagged_text(finding.text))
        lines.append("")

    # Remove the final blank line from the formatter; callers control spacing.
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def write_text_report(
    report_path: Path,
    input_path: Path,
    findings: list[Finding],
) -> None:
    """Write detailed findings without a summary table at the beginning."""
    report_path.parent.mkdir(parents=True, exist_ok=True)

    def rgb_text(value: Optional[tuple[int, int, int]]) -> str:
        return f"RGB {value}" if value is not None else "Unavailable"

    sorted_findings = _sorted_findings(findings)
    lines = [
        "DETAILED FINDINGS",
        "=" * 72,
    ]

    for number, finding in enumerate(sorted_findings, start=1):
        reason_lines = [detection_label(reason) for reason in finding.reasons]
        reason_lines.extend(f"Matched wording: {label}" for label in finding.pattern_labels)
        if not reason_lines:
            reason_lines = ["Suspicious text signal"]

        opacity_text = (
            f"{finding.opacity * 100:.2f}%" if finding.opacity is not None else "Unavailable"
        )
        lines.extend([
            "",
            f"FINDING #{number}",
            "=" * 10,
            "Reasons why it was flagged:",
            *[f"-{safe_untrusted_text(reason)}" for reason in reason_lines],
            "",
            f"Page number: {finding.page}",
            "",
            "Flagged text:",
            _single_line_flagged_text(finding.text),
            "",
            "More details",
            "-" * 12,
            f"Text opacity: {opacity_text}",
            f"Text colour: {rgb_text(finding.colour_rgb)}",
            f"Estimated background colour: {rgb_text(finding.background_rgb)}",
            f"Background uniformity: {finding.background_uniformity if finding.background_uniformity is not None else 'Unavailable'}",
            f"Text size: {finding.font_size_pt:.2f} pt" if finding.font_size_pt is not None else "Text size: Unavailable",
            f"Document median font size: {finding.document_median_font_size_pt:.2f} pt" if finding.document_median_font_size_pt is not None else "Document median font size: Unavailable",
            "",
        ])

    _atomic_write_text(report_path, "\n".join(lines).rstrip() + "\n")


def analyze_pdf(
    input_path: Path,
    report_path: Path,
    report_json: Optional[Path] = None,
    use_ocr: bool = True,
    ocr_language: str = "eng",
    write_text_report_file: bool = True,
) -> tuple[float, float, list[Finding], int, int]:
    """Analyze a PDF and create a report whenever suspicious content is found.

    Returns:
        (document_risk_score, suspicious_span_percentage, findings,
         total_text_units, reported_findings)

    The document risk score is the strongest individual finding (maximum span
    score). Suspicious-span percentage is prevalence: findings divided by all
    extracted page-text spans plus non-empty annotation/form-field text values.
    The two metrics are intentionally independent.
    """
    input_path = _validate_input_pdf(input_path)
    report_path = _normalized_output_path(report_path)
    report_json_path = _normalized_output_path(report_json) if report_json is not None else None
    _validate_output_path(report_path)
    if report_json_path is not None:
        _validate_output_path(report_json_path)
    if _paths_refer_to_same_file(input_path, report_path):
        raise ValueError("TXT report path must differ from the source PDF; the original is protected.")
    if report_json_path is not None:
        if _paths_refer_to_same_file(input_path, report_json_path):
            raise ValueError("JSON report path must differ from the source PDF; the original is protected.")
        if _paths_refer_to_same_file(report_path, report_json_path):
            raise ValueError("TXT and JSON report paths must be different files.")

    findings: list[Finding] = []
    total_spans = 0
    total_characters = 0
    ocr_pages_processed = 0
    ocr_pages_unavailable = 0
    hidden_layer_names: set[str] = set()
    optional_content_group_count = 0
    annotation_text_units = 0
    form_field_text_units = 0

    with pymupdf.open(str(input_path), filetype="pdf") as doc:
        if doc.needs_pass:
            raise ValueError("This PDF is password-protected. Decrypt it first or add password support.")
        if len(doc) == 0:
            raise ValueError("The PDF contains no pages.")
        if len(doc) > MAX_PAGES:
            raise ValueError(f"PDF exceeds the {MAX_PAGES}-page safety limit.")

        # PyMuPDF parses the PDF but this program never executes PDF JavaScript,
        # launch actions, attachments, external commands, or embedded programs.
        # Parsing itself remains native-library code; isolate untrusted samples.
        inspection_doc, hidden_layer_names, optional_content_group_count = (
            open_with_all_optional_layers_enabled(doc)
        )
        analysis_doc = inspection_doc if inspection_doc is not None else doc

        try:
            # First pass: gather all page-text spans, including text normally
            # omitted because it belongs to an OFF optional-content group.
            page_cache: list[tuple[list[dict[str, Any]], list[dict[str, Any]]]] = []
            all_sizes: list[float] = []
            for page in analysis_doc:
                spans, traces = collect_page_spans(page)
                page_cache.append((spans, traces))
                total_spans += len(spans)
                if total_spans > MAX_TEXT_SPANS:
                    raise ValueError(f"PDF exceeds the {MAX_TEXT_SPANS:,}-text-span safety limit.")
                for span in spans:
                    raw_text = str(span.get("text", ""))
                    if len(raw_text) > MAX_EXTRACTED_CHARACTERS:
                        raise ValueError("A PDF text span exceeds the extraction safety limit.")
                    total_characters += len(normalized_text(raw_text))
                    if total_characters > MAX_EXTRACTED_CHARACTERS:
                        raise ValueError(
                            f"PDF exceeds the {MAX_EXTRACTED_CHARACTERS:,}-character extraction safety limit."
                        )
                    size = float(span.get("size", 0.0) or 0.0)
                    if size > 0:
                        all_sizes.append(size)

            document_median = statistics.median(all_sizes) if all_sizes else 0.0

            # Second pass: compare embedded text to a raster OCR reading of
            # the ORIGINAL visible page, then inspect annotation/widget data.
            for page_index, analysis_page in enumerate(analysis_doc):
                visible_page = doc[page_index]
                spans, traces = page_cache[page_index]
                page_pattern_labels = prompt_pattern_labels_by_span(spans)

                ocr_text: Optional[str] = None
                if use_ocr and spans:
                    ocr_text = extract_page_ocr(visible_page, language=ocr_language)
                    if ocr_text is None:
                        ocr_pages_unavailable += 1
                    else:
                        ocr_pages_processed += 1

                pixels = None
                pix_x = pix_y = 0
                try:
                    if visible_page.rotation == 0:
                        pixels, pix_x, pix_y = render_page_rgb(visible_page)
                except Exception:
                    pixels = None

                bboxlog = analysis_page.get_bboxlog()
                for span_index, span in enumerate(spans):
                    text = str(span.get("text", ""))
                    bbox = tuple(float(v) for v in span["bbox"])
                    size = float(span.get("size", 0.0) or 0.0)
                    trace = find_trace_match(span, traces)
                    reasons: list[str] = []
                    pattern_labels = page_pattern_labels[span_index]
                    background_rgb = None
                    background_uniformity = None

                    if pattern_labels:
                        reasons.append("prompt_injection_language_pattern")
                    if contains_invisible_formatting(text):
                        reasons.append("invisible_unicode_formatting")
                    if ocr_text is not None and ocr_disagrees_with_embedded_text(text, ocr_text):
                        reasons.append("ocr_text_not_visually_present")

                    if trace:
                        try:
                            render_type = int(trace.get("type", 0))
                        except (TypeError, ValueError, OverflowError):
                            render_type = 0
                        try:
                            opacity_value = float(trace.get("opacity", 1.0))
                        except (TypeError, ValueError, OverflowError):
                            opacity_value = 1.0
                        opacity = opacity_value if math.isfinite(opacity_value) else 1.0
                        # PyMuPDF: type 3 represents ignored / invisible text.
                        if render_type > 1:
                            reasons.append("invisible_rendering_mode")
                        if opacity <= 0.01:
                            reasons.append("zero_or_near_zero_opacity")
                        trace_layer = str(trace.get("layer", "") or "").strip().casefold()
                        if trace_layer and trace_layer in hidden_layer_names:
                            reasons.append("hidden_optional_content_layer")
                    else:
                        render_type = None
                        opacity = None

                    colour_rgb = int_colour_to_rgb(span.get("color"))
                    if colour_rgb is None and trace:
                        colour_rgb = trace_colour_to_rgb(trace.get("color"))

                    if pixels is not None and colour_rgb is not None:
                        background_rgb, background_uniformity = estimate_local_background(
                            pixels, pix_x, pix_y, bbox, size, visible_page.rect
                        )
                        if background_rgb is not None and background_uniformity >= BACKGROUND_UNIFORMITY_MIN:
                            colour_distance = math.dist(colour_rgb, background_rgb)
                            if colour_distance <= BACKGROUND_COLOR_TOLERANCE:
                                reasons.append("text_matches_local_background")

                    if document_median > 0:
                        if size <= MICRO_TEXT_PT:
                            reasons.append("micro_text_2_5pt_or_smaller")
                        elif size <= min(SMALL_TEXT_MAX_PT, document_median * SMALL_TEXT_RATIO):
                            reasons.append("very_small_relative_to_document")

                    if trace and is_covered_by_later_object(trace, bboxlog, bbox):
                        reasons.append("covered_by_later_page_object")

                    if is_mostly_outside_page(bbox, visible_page.rect):
                        reasons.append("mostly_outside_page_bounds")

                    if not reasons:
                        continue

                    finding = Finding(
                        page=page_index + 1,
                        text=text,
                        font=str(span.get("font", "unknown")),
                        font_size_pt=round(size, 2) if size > 0 else None,
                        document_median_font_size_pt=round(document_median, 2) if document_median > 0 else None,
                        colour_rgb=colour_rgb,
                        bbox=tuple(round(v, 2) for v in bbox),
                        score=score_evidence(reasons),
                        reasons=reasons,
                        pattern_labels=pattern_labels,
                        background_rgb=background_rgb,
                        background_uniformity=(round(background_uniformity, 3)
                                               if background_uniformity is not None else None),
                        render_type=render_type,
                        opacity=round(opacity, 4) if opacity is not None else None,
                        sequence_number=int(trace["seqno"]) if trace and "seqno" in trace else None,
                        direction=tuple(span.get("direction", (1.0, 0.0))),
                        source_type="page_text",
                    )
                    findings.append(finding)

                # Annotations/comments and AcroForm field values are separate
                # PDF data channels and may not be returned by page.get_text().
                special_findings, annotation_count, widget_count, special_chars = (
                    collect_annotation_and_widget_findings(
                        visible_page, page_index + 1, document_median
                    )
                )
                annotation_text_units += annotation_count
                form_field_text_units += widget_count
                total_spans += annotation_count + widget_count
                total_characters += special_chars
                for special_finding in special_findings:
                    # A form value or FreeText annotation may also be present
                    # as ordinary page text in its visible appearance. Merge
                    # the evidence into that text finding instead of listing
                    # the same string twice in the review report.
                    duplicate = None
                    for existing in findings:
                        if existing.page != special_finding.page:
                            continue
                        if existing.source_type != "page_text":
                            continue
                        if normalized_text(existing.text) != normalized_text(special_finding.text):
                            continue
                        if intersection_ratio(existing.bbox, special_finding.bbox) >= 0.50:
                            duplicate = existing
                            break
                    if duplicate is not None:
                        for reason in special_finding.reasons:
                            if reason not in duplicate.reasons:
                                duplicate.reasons.append(reason)
                        for label in special_finding.pattern_labels:
                            if label not in duplicate.pattern_labels:
                                duplicate.pattern_labels.append(label)
                        duplicate.score = score_evidence(duplicate.reasons)
                        total_spans -= 1
                        total_characters -= len(normalized_text(special_finding.text))
                        if special_finding.source_type == "annotation":
                            annotation_text_units -= 1
                        elif special_finding.source_type == "form_field":
                            form_field_text_units -= 1
                    else:
                        findings.append(special_finding)
                if total_spans > MAX_TEXT_SPANS:
                    raise ValueError(f"PDF exceeds the {MAX_TEXT_SPANS:,}-text-unit safety limit.")
                if total_characters > MAX_EXTRACTED_CHARACTERS:
                    raise ValueError(
                        f"PDF exceeds the {MAX_EXTRACTED_CHARACTERS:,}-character extraction safety limit."
                    )
        finally:
            if inspection_doc is not None:
                inspection_doc.close()

    # Keep severity and prevalence independent. The risk score is the highest
    # individual finding score; span percentage measures how much text was flagged.
    document_score = max((finding.score for finding in findings), default=0.0)

    suspicious_characters = sum(len(normalized_text(finding.text)) for finding in findings)
    suspicious_span_percentage = (
        (len(findings) / total_spans) * 100.0 if total_spans else 0.0
    )
    suspicious_character_percentage = (
        min(100.0, (suspicious_characters / total_characters) * 100.0)
        if total_characters else 0.0
    )

    # Generate the requested report whenever at least one suspicious finding
    # exists, unless the caller explicitly chose to preserve an existing report.
    # Findings are still returned so the CLI can always display them in terminal.
    report_written = 0
    if findings and write_text_report_file:
        write_text_report(report_path, input_path, findings)
        report_written = len(findings)

    if report_json_path is not None:
        payload = {
            "input_pdf": str(input_path),
            "text_report": str(report_path) if report_written else None,
            "document_risk_score_percent": round(document_score, 1),
            "document_risk_score_definition": "Highest individual finding score; heuristic, not probability.",
            "total_text_units": total_spans,
            "page_text_spans": total_spans - annotation_text_units - form_field_text_units,
            "annotation_text_units": annotation_text_units,
            "form_field_text_units": form_field_text_units,
            "optional_content_groups": optional_content_group_count,
            "hidden_optional_content_layer_names": sorted(hidden_layer_names),
            "ocr_requested": use_ocr,
            "ocr_language": ocr_language if use_ocr else None,
            "ocr_pages_processed": ocr_pages_processed,
            "ocr_pages_unavailable": ocr_pages_unavailable,
            "suspicious_spans": len(findings),
            "suspicious_span_percentage": round(suspicious_span_percentage, 4),
            "total_non_whitespace_characters": total_characters,
            "suspicious_character_percentage": round(suspicious_character_percentage, 4),
            "findings": [finding.to_json() for finding in findings],
        }
        _atomic_write_text(report_json_path, json.dumps(payload, indent=2, ensure_ascii=True) + "\n")

    return document_score, suspicious_span_percentage, findings, total_spans, report_written

def scan_pdf(
    input_pdf: str | Path,
    output_txt: Optional[str | Path] = None,
    use_ocr: bool = True,
    ocr_language: str = "eng",
) -> ScanResult:
    """Scan a PDF and return its risk score and suspicious-span percentage.

    Returns a ``ScanResult`` with two percentage values. A TXT report is created
    automatically beside the PDF whenever one or more spans are flagged.
    """
    source = Path(input_pdf)
    destination = (
        Path(output_txt) if output_txt is not None
        else source.with_name(f"{source.stem}_hidden_text_report.txt")
    )
    document_score, span_percentage, _findings, _total, _reported = analyze_pdf(
        source, destination, use_ocr=use_ocr, ocr_language=ocr_language
    )
    return ScanResult(document_score, span_percentage)


def print_terminal_findings(findings: list[Finding]) -> None:
    """Print findings with copy-ready text; metrics are printed separately last."""
    if not findings:
        return
    print("FINDINGS")
    print("\n".join(format_findings_ascii_table(findings, color_terminal_label=True)))


def _confirm_report_overwrite(path: Path, *, assume_yes: bool = False) -> bool:
    """Ask before replacing an existing TXT report; default safely to no."""
    _validate_output_path(path)
    if not path.exists() or assume_yes:
        return True
    prompt = (
        f'The report "{safe_untrusted_text(path)}" already exists. '
        "Do you want to overwrite it? [y/N]: "
    )
    if not sys.stdin.isatty():
        print(
            "Keeping the existing report. Findings will still be printed in the terminal; "
            "use --overwrite to replace the report.",
            file=sys.stderr,
        )
        return False
    try:
        response = input(prompt).strip().casefold()
    except EOFError:
        return False
    return response in {"y", "yes"}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a PDF for hidden prompt-injection text, create a detailed TXT report, "
            "and print a bordered findings table followed by document metrics."
        )
    )
    parser.add_argument("pdf", type=Path, help="Input PDF file")
    parser.add_argument(
        "--output", type=Path,
        help="Text-report path (default: <name>_hidden_text_report.txt beside the PDF)",
    )
    parser.add_argument("--report-json", type=Path, help="Optional JSON report path")
    parser.add_argument(
        "--no-ocr", action="store_true",
        help="Disable OCR comparison (useful for large PDFs or when Tesseract is unavailable)",
    )
    parser.add_argument(
        "--ocr-language", default="eng",
        help="Tesseract language code(s), e.g. eng or eng+fra (default: eng)",
    )
    parser.add_argument(
        "--overwrite", action="store_true",
        help="Overwrite an existing TXT report without prompting (useful for automation)",
    )
    args = parser.parse_args()

    output = args.output or args.pdf.with_name(f"{args.pdf.stem}_hidden_text_report.txt")
    try:
        normalized_input = _validate_input_pdf(args.pdf)
        normalized_output = _normalized_output_path(output)
        _validate_output_path(normalized_output)
        if _paths_refer_to_same_file(normalized_input, normalized_output):
            raise ValueError("TXT report path must differ from the source PDF; the original is protected.")
        write_report_file = _confirm_report_overwrite(
            normalized_output, assume_yes=args.overwrite
        )
        if not write_report_file:
            print(
                "The existing TXT report will be left unchanged. "
                "The scan will continue and findings will be shown below; "
                "no new TXT report will be written."
            )

        score, span_percentage, findings, _total, _reported = analyze_pdf(
            normalized_input,
            normalized_output,
            args.report_json,
            use_ocr=not args.no_ocr,
            ocr_language=args.ocr_language,
            write_text_report_file=write_report_file,
        )

        # If the user approved replacing an existing report but this scan found
        # nothing, remove the stale report so it cannot be mistaken for this scan.
        # If the user declined replacement, preserve the old report in all cases.
        if write_report_file and not findings and normalized_output.exists():
            _validate_output_path(normalized_output)
            normalized_output.unlink()
    except Exception as exc:
        print(f"Error: {safe_untrusted_text(exc)}", file=sys.stderr)
        return 2

    print_terminal_findings(findings)
    if findings:
        print()
    print(f"Document risk score: {score:.1f}%")
    print(f"Suspicious span percentage: {span_percentage:.3f}%")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
