#!/usr/bin/env python3
"""Interactive PDF cleanup utility built on pdf_hidden_text_scanner.py.

Creates a separate cleaned PDF; never overwrites the source. Removes selected
scanner findings plus recurring header/footer text detected heuristically.
"""
from __future__ import annotations
import argparse
import math
import re
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

import pymupdf
import pdf_hidden_text_scanner as scanner


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().casefold()


def get_header_footer_rects(doc: pymupdf.Document):
    """Find repeated text spans in top/bottom 12% of pages (>=60% pages, min 2)."""
    occurrences = defaultdict(list)
    page_count = len(doc)
    if page_count < 2:
        return []
    for pno, page in enumerate(doc):
        h = page.rect.height
        spans, _ = scanner.collect_page_spans(page)
        for s in spans:
            text = str(s.get("text", "")).strip()
            if not text:
                continue
            x0, y0, x1, y1 = map(float, s.get("bbox", (0, 0, 0, 0)))
            top_or_bottom = y1 <= h * 0.12 or y0 >= h * 0.88
            if top_or_bottom:
                key = (norm(text), "top" if y1 <= h * 0.12 else "bottom")
                occurrences[key].append((pno, (x0, y0, x1, y1)))
    min_pages = max(2, math.ceil(page_count * 0.60))
    result = []
    for (_text, _region), items in occurrences.items():
        pages = {p for p, _ in items}
        if len(pages) >= min_pages:
            result.extend((p, rect) for p, rect in items)
    return result


def print_findings(findings):
    """Use the scanner's own terminal formatter for an identical findings layout."""
    scanner.print_terminal_findings(findings)


def parse_selection(raw: str, count: int):
    raw = raw.strip().casefold()
    if raw == "q":
        return None
    if raw == "":
        return set(range(1, count + 1))
    match = re.fullmatch(r"(in|ex)\s+([0-9,\s]+)", raw)
    if not match:
        raise ValueError("Enter nothing, 'in 1,2', 'ex 2,3', or 'q'.")
    mode, nums = match.groups()
    values = [int(x) for x in re.findall(r"\d+", nums)]
    if not values or any(n < 1 or n > count for n in values):
        raise ValueError(f"Finding numbers must be between 1 and {count}.")
    selected = set(values)
    return selected if mode == "in" else set(range(1, count + 1)) - selected


def main():
    ap = argparse.ArgumentParser(description="Remove selected hidden/suspicious PDF text and recurring headers/footers.")
    ap.add_argument("pdf", type=Path, help="Source PDF")
    ap.add_argument("--no-ocr", action="store_true", help="Disable OCR during scanner analysis")
    ap.add_argument("--ocr-language", default="eng")
    args = ap.parse_args()
    source = scanner._validate_input_pdf(args.pdf)
    output = source.with_name(source.stem + "_cleaned.pdf")
    if output.exists():
        print(f"Output already exists: {output}")
        answer = input("Overwrite cleaned PDF? [y/N]: ").strip().casefold()
        if answer not in {"y", "yes"}:
            print("Cancelled.")
            return 1

    # Use a temporary report path because analyze_pdf is the scanner's public analysis core.
    with tempfile.TemporaryDirectory(prefix="pdf_cleanup_scan_") as tmp:
        tmp_report = Path(tmp) / "scan_report.txt"
        score, span_percentage, findings, _, _ = scanner.analyze_pdf(
            source, tmp_report, use_ocr=not args.no_ocr, ocr_language=args.ocr_language
        )
    # Keep selection numbers aligned with the scanner's displayed page/reading order.
    findings = scanner._sorted_findings(findings)
    print_findings(findings)
    if findings:
        print()
    # Match the scanner's terminal summary exactly and place it immediately
    # below the findings, before the interactive removal-selection prompt.
    print(f"Document risk score: {score:.1f}%")
    print(f"Suspicious span percentage: {span_percentage:.3f}%")
    if not findings:
        print("No scanner findings detected.")
    print("\nRemoval selection:")
    print("  Enter = remove all scanner findings")
    print("  in 1,2,4 = remove only these finding numbers")
    print("  ex 3,4 = remove all findings except these")
    print("  q = cancel")
    while True:
        try:
            selection = parse_selection(input("Selection: "), len(findings))
            break
        except ValueError as e:
            print(e)
    if selection is None:
        print("Cancelled; source PDF unchanged.")
        return 0

    # Findings are 1-based; redact page-text findings only. Other finding types
    # may not have a meaningful page-text rectangle, so skip if bbox is empty.
    chosen = [f for i, f in enumerate(findings, 1) if i in selection]
    with pymupdf.open(str(source)) as doc:
        redactions = defaultdict(list)
        for f in chosen:
            if f.source_type == "page_text" and f.bbox and f.page >= 1 and f.page <= len(doc):
                redactions[f.page - 1].append(f.bbox)
        # Remove recurring headers and footers on all pages, independent of selection.
        header_footer = get_header_footer_rects(doc)
        for pno, rect in header_footer:
            redactions[pno].append(rect)
        for pno, rects in redactions.items():
            page = doc[pno]
            for rect in rects:
                r = pymupdf.Rect(rect)
                if not r.is_empty and r.is_valid:
                    page.add_redact_annot(r, fill=False, cross_out=False)
            if rects:
                page.apply_redactions(images=0, graphics=0, text=0)
        # Save to a temporary sibling and replace only the output copy.
        temp_out = output.with_name(output.stem + ".tmp.pdf")
        if temp_out.exists():
            temp_out.unlink()
        doc.save(str(temp_out), garbage=4, deflate=True)
    temp_out.replace(output)
    print(f"\nCleaned PDF saved: {output}")
    print(f"Selected findings removed: {len(chosen)}")
    print(f"Recurring header/footer text spans removed: {len(header_footer)}")
    print("Original PDF was not modified.")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Error: {scanner.safe_untrusted_text(exc)}", file=sys.stderr)
        raise SystemExit(2)
