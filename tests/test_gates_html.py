"""Tests for gates_html.py — the shared page shell/CSS/JS between the
static gates snapshot and the live dashboard.

Mostly structural: the two callers (gates_panel.render_html,
gates_serve._render_page) already have their own tests exercising the
assembled output end to end; this file pins the few things that would
silently break both of them at once if this shared module regressed.
"""
from willow_mcp import gates_html


def test_page_embeds_title_and_subtitle():
    html = gates_html.page(title="My Title", subtitle="My subtitle text",
                            top_extra="", body_scripts="")
    assert "<title>My Title</title>" in html
    assert "<h1>My Title</h1>" in html
    assert "My subtitle text" in html


def test_page_includes_shared_css_and_js():
    html = gates_html.page(title="t", subtitle="s", top_extra="", body_scripts="")
    assert "renderDashboard" in html
    assert "buildSummary" in html
    assert ".btn.on" in html
    assert ".perm-row" in html


def test_page_includes_toast_container():
    html = gates_html.page(title="t", subtitle="s", top_extra="", body_scripts="")
    assert 'id="toast"' in html


def test_page_includes_top_extra_and_body_scripts():
    html = gates_html.page(title="t", subtitle="s",
                            top_extra="<div class='marker'>TOPEXTRA</div>",
                            body_scripts="const MARKER = 'BODYSCRIPT';")
    assert "TOPEXTRA" in html
    assert "BODYSCRIPT" in html


def test_page_is_self_contained_single_script_block():
    html = gates_html.page(title="t", subtitle="s", top_extra="", body_scripts="")
    assert html.count("<script>") == html.count("</script>") == 1


def test_category_order_js_matches_python_source_of_truth():
    """The JS-side CATEGORY_ORDER is a literal duplicate (a JS string can't
    import Python) — this pins that the categories/order stay in sync
    rather than silently drifting the next time one side changes."""
    from willow_mcp.gates_panel import CATEGORY_ORDER

    for key, title in CATEGORY_ORDER:
        assert f'["{key}", "{title}"]' in gates_html.SHARED_JS


def test_a_rows_label_is_set_as_text_never_as_html():
    """A row's state_label is text: the buttons set it with textContent, and so
    does the worker chip, so a label holding markup shows as itself."""
    html = gates_html.page(title="t", subtitle="s", top_extra="", body_scripts="")
    assert "${worker.state_label}" not in html
    assert 'querySelector(".n").textContent = worker.state_label' in html
    assert "innerHTML" not in "".join(
        line for line in html.splitlines() if "state_label" in line
    )
