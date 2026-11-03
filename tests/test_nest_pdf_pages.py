"""A PDF is read one page at a time: a scanned PDF's pages are rendered,
read and let go one by one, and a text page is closed once read, so memory
stays about one page's worth however long the PDF. Rendering every page at
once (a 300-page scan at 200 dpi is over 3 GB) once froze a 14 GB machine.

The libraries are stand-ins: nothing here needs tesseract, poppler or a PDF."""

import sys
import types

from willow_mcp.nest import ocr


class Image:
    live = 0
    most = 0

    def __init__(self, n):
        self.n = n
        Image.live += 1
        Image.most = max(Image.most, Image.live)

    def close(self):
        Image.live -= 1


def stand_ins(monkeypatch, pages=300, text_layer=""):
    calls, closed = [], []

    class Page:
        def __init__(self, n):
            self.n = n

        def extract_text(self):
            return text_layer

        def close(self):
            closed.append(self.n)

    every = [Page(n) for n in range(1, pages + 1)]

    class Pdf:
        pages = every

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def convert_from_path(path, dpi, first_page=None, last_page=None):
        calls.append((first_page, last_page))
        lo, hi = first_page or 1, last_page or pages
        return [Image(n) for n in range(lo, hi + 1)]

    monkeypatch.setitem(sys.modules, "pdfplumber", types.SimpleNamespace(open=lambda p: Pdf()))
    monkeypatch.setitem(
        sys.modules,
        "pdf2image",
        types.SimpleNamespace(convert_from_path=convert_from_path, pdfinfo_from_path=lambda p: {"Pages": pages}),
    )
    monkeypatch.setitem(sys.modules, "pytesseract", types.SimpleNamespace(image_to_string=lambda img: f"page {img.n}"))
    Image.live = Image.most = 0
    return calls, closed


def test_a_scan_is_rendered_one_page_at_a_time_and_each_let_go(monkeypatch, tmp_path):
    calls, closed = stand_ins(monkeypatch, pages=300, text_layer="")
    text, how = ocr._extract_pdf(tmp_path / "scan.pdf")
    assert how == "pdf2image+tesseract"
    assert calls == [(n, n) for n in range(1, 301)], "never the whole PDF in one call"
    assert Image.most == 1 and Image.live == 0, "one page image alive at a time"
    assert text.split("\n\n") == [f"page {n}" for n in range(1, 301)], "in page order"


def test_a_text_page_is_closed_once_read(monkeypatch, tmp_path):
    calls, closed = stand_ins(monkeypatch, pages=40, text_layer="words")
    text, how = ocr._extract_pdf(tmp_path / "book.pdf")
    assert how == "pdfplumber" and calls == []
    assert closed == list(range(1, 41))
