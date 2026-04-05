import csv
import io
from jinja2 import Template
from weasyprint import HTML


def render_html_report(data: dict) -> str:
    template = Template("""
    <html><body>
      <h1>FortiWeb Maturity Report</h1>
      <p>Overall Score: {{ assessment.overall_score }}</p>
      <p>Maturity Level: {{ assessment.maturity_level }}</p>
      <h2>Controls</h2>
      <ul>
        {% for c in controls %}
          <li>{{ c.control_code }} - {{ c.score }}/{{ c.max_score }} ({{ c.maturity_level }})</li>
        {% endfor %}
      </ul>
    </body></html>
    """)
    return template.render(**data)


def build_pdf_bytes(data: dict) -> bytes:
    html = render_html_report(data)
    return HTML(string=html).write_pdf()


def build_csv_bytes(data: dict) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["control_code", "category", "score", "max_score", "maturity_level", "recommendation"])
    writer.writeheader()
    for c in data.get("controls", []):
        writer.writerow({k: c.get(k) for k in writer.fieldnames})
    return buf.getvalue().encode()
