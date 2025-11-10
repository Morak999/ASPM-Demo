from flask import Flask, render_template_string
import json
import os

app = Flask(__name__)

# Function to gather scan results
def load_reports():
    results = []

    # SAST (CodeQL)
    codeql_path = os.path.join("reports", "codeql_report.json")
    if os.path.exists(codeql_path):
        with open(codeql_path) as f:
            data = json.load(f)
            for alert in data.get("alerts", []):
                results.append({
                    "tool": "CodeQL (SAST)",
                    "vulnerability": alert.get("rule", {}).get("id", "Unknown"),
                    "severity": alert.get("rule", {}).get("severity", "medium").capitalize(),
                    "description": alert.get("rule", {}).get("description", "")
                })
    else:
        results.append({
            "tool": "CodeQL (SAST)",
            "vulnerability": "No results yet",
            "severity": "Info",
            "description": "Run CodeQL workflow on GitHub to generate report."
        })

    # DAST (ZAP)
    zap_path = os.path.join("reports", "zap-report.html")
    if os.path.exists(zap_path):
        with open(zap_path) as f:
            content = f.read()
            alert_count = content.lower().count("alert")
            results.append({
                "tool": "OWASP ZAP (DAST)",
                "vulnerability": f"{alert_count} potential alerts",
                "severity": "High" if alert_count > 5 else "Medium",
                "description": "DAST scan results from ZAP."
            })
    else:
        results.append({
            "tool": "OWASP ZAP (DAST)",
            "vulnerability": "No report found",
            "severity": "Info",
            "description": "Run DAST workflow on GitHub to generate zap-report.html."
        })

    # SCA (Dependabot)
    results.append({
        "tool": "Dependabot (SCA)",
        "vulnerability": "Dependabot monitors your dependencies directly on GitHub.",
        "severity": "Auto",
        "description": "Check the Security → Dependabot tab for live dependency alerts."
    })

    return results


@app.route('/')
def dashboard():
    data = load_reports()

    html = """
    <html>
    <head>
        <title>ASPM Dashboard Simulation</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f8f8f8; padding: 20px; }
            h1 { color: #333; }
            table { border-collapse: collapse; width: 100%; background: white; }
            th, td { padding: 10px; border: 1px solid #ccc; text-align: left; }
            th { background-color: #333; color: #fff; }
        </style>
    </head>
    <body>
        <h1>🛡️ ASPM Dashboard Simulation</h1>
        <p>This dashboard combines SAST (CodeQL), DAST (ZAP), and SCA (Dependabot) scan results.</p>
        <table>
            <tr>
                <th>Tool</th>
                <th>Vulnerability</th>
                <th>Severity</th>
                <th>Description</th>
            </tr>
            {% for item in data %}
            <tr>
                <td>{{ item.tool }}</td>
                <td>{{ item.vulnerability }}</td>
                <td>{{ item.severity }}</td>
                <td>{{ item.description }}</td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """

    return render_template_string(html, data=data)


if __name__ == '__main__':
    app.run(debug=True)
