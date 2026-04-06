from io import StringIO


def render_pdf_from_html(html: str) -> bytes:
    """Phase-1 placeholder for PDF generation from HTML templates."""
    return html.encode("utf-8")


def export_controls_csv(rows: list[dict]) -> str:
    buffer = StringIO()
    headers = ["control_id", "category", "score", "compliant"]
    buffer.write(",".join(headers) + "\n")
    for row in rows:
        buffer.write(
            f"{row.get('control_id','')},{row.get('category','')},{row.get('score','')},{row.get('compliant','')}\n"
        )
    return buffer.getvalue()
