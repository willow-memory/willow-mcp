"""
nest-seed/ocr.py — text extraction router by file type.

Tries the best available method for each type, degrades gracefully if
a dependency is missing. Returns (text, method_used) or ("", "failed").

Supported:
  Images (.jpg .jpeg .png .tiff .bmp .webp)  → pytesseract (requires tesseract)
  PDF (.pdf)                                  → pdfplumber (text), fallback pdf2image+tesseract
  Office (.docx)                              → python-docx
  Plaintext (.txt .md code/markup …)          → read directly
"""
from __future__ import annotations

from pathlib import Path

IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".bmp", ".webp"}
PDF_SUFFIX = ".pdf"
OFFICE_SUFFIXES = {".docx"}
# Anything we can read as UTF-8 and hand to the classifier as-is. Source code
# counts: a .py / .sh / .jsx file is text the LLM can categorise (code, config…).
TEXT_SUFFIXES = {
    ".txt", ".md", ".csv", ".rst", ".tex", ".lean", ".json", ".yaml", ".yml",
    ".py", ".sh", ".js", ".jsx", ".ts", ".tsx", ".html", ".xml",
    ".toml", ".ini", ".cfg", ".log", ".sql",
}


def extract(path: Path) -> tuple[str, str]:
    """Return (text, method). text is empty string on failure."""
    suffix = path.suffix.lower()
    if suffix in TEXT_SUFFIXES:
        return _read_text(path)
    if suffix in IMAGE_SUFFIXES:
        return _ocr_image(path)
    if suffix == PDF_SUFFIX:
        return _extract_pdf(path)
    if suffix in OFFICE_SUFFIXES:
        return _extract_docx(path)
    return "", "unsupported"


def _read_text(path: Path) -> tuple[str, str]:
    try:
        return path.read_text(errors="replace"), "plaintext"
    except OSError as e:
        return "", f"read_error:{e}"


def _ocr_image(path: Path) -> tuple[str, str]:
    try:
        import pytesseract
        from PIL import Image
        img = Image.open(path)
        text = pytesseract.image_to_string(img)
        return text, "tesseract"
    except ImportError:
        return "", "missing:pytesseract"
    except Exception as e:
        return "", f"ocr_error:{e}"


def _extract_pdf(path: Path) -> tuple[str, str]:
    # Try pdfplumber first (native text layer)
    try:
        import pdfplumber
        with pdfplumber.open(path) as pdf:
            pages = [p.extract_text() or "" for p in pdf.pages]
        text = "\n\n".join(pages).strip()
        if text:
            return text, "pdfplumber"
    except ImportError:
        pass
    except Exception:
        pass

    # Fallback: pdf2image + tesseract (scanned PDFs)
    try:
        from pdf2image import convert_from_path
        import pytesseract
        images = convert_from_path(str(path), dpi=200)
        pages = [pytesseract.image_to_string(img) for img in images]
        text = "\n\n".join(pages).strip()
        return text, "pdf2image+tesseract"
    except ImportError:
        return "", "missing:pdfplumber+pdf2image"
    except Exception as e:
        return "", f"pdf_error:{e}"


def _extract_docx(path: Path) -> tuple[str, str]:
    try:
        from docx import Document
        doc = Document(str(path))
        text = "\n".join(p.text for p in doc.paragraphs if p.text.strip())
        return text, "python-docx"
    except ImportError:
        return "", "missing:python-docx"
    except Exception as e:
        return "", f"docx_error:{e}"


def supported_suffixes() -> set[str]:
    return IMAGE_SUFFIXES | {PDF_SUFFIX} | OFFICE_SUFFIXES | TEXT_SUFFIXES
