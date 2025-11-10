# dashboard_app.py
from flask import Flask, render_template_string, send_from_directory
import pandas as pd
import json
import os
import matplotlib.pyplot as plt
import numpy as np

app = Flask(__name__)
REPORTS_DIR = "reports"

# --- Priority Factor weights (context engine simulation) ---
PRIORITY_WEIGHTS = {
    "Environment": {"Production": 3, "Staging": 1.5, "Dev": 1},
    "Severity": {"Low": 2, "Medium": 4, "High": 7, "Critical": 9},
    "Exploitability": {"Easy": 3, "Moderate": 2, "Hard": 1},
    "AssetValue": {"High": 3, "Medium": 2, "Low": 1},
}

# --- Severity to 0-10 score ---
SEVERITY_MAPPING = {
    "None": 0,
    "Low": (0.1, 3.9),
    "Medium": (4.0, 6.9),
    "High": (7.0, 8.9),
    "Critical": (9.0, 10)
}

def severity_to_score(severity):
    severity = severity.capitalize()
    if severity in SEVERITY_MAPPING:
        low, high = SEVERITY_MAPPING[severity]
        return np.round(np.random.uniform(low, high), 1)
    return 0

# --- Exploit maturity detection ---
def detect_exploit_keywords(text):
    text = (text or "").lower()
    for k in ['exploit', 'poc', 'proof of concept', 'metasploit', 'weaponized', 'rce', 'remote code execution']:
        if k in text:
            return 10.0
    return 0.0

# --- Load CodeQL (SAST) ---
def load_codeql():
    try:
        with open(os.path.join(REPORTS_DIR, "codeql_report.json")) as f:
            data = json.load(f)
        rows = []
        for item in data.get("results", []):
            rows.append({
                "tool": "CodeQL (SAST)",
                "id": item.get("ruleId"),
                "title": item.get("ruleId"),
                "description": item.get("message"),
                "severity": item.get("level").capitalize(),
                "sev_score": severity_to_score(item.get("level")),
                "exploit_maturity": detect_exploit_keywords(item.get("message")),
                "exposure": 5.0,
                "runtime_evidence": 0.0,
                "Environment": np.random.choice(["Production","Staging","Dev"]),
                "Exploitability": np.random.choice(["Easy","Moderate","Hard"]),
                "AssetValue": np.random.choice(["High","Medium","Low"])
            })
        return pd.DataFrame(rows)
    except:
        return pd.DataFrame()

# --- Load Dependabot (SCA) ---
def load_dependabot():
    try:
        with open(os.path.join(REPORTS_DIR, "dependabot_summary.json")) as f:
            data = json.load(f)
        rows = []
        for alert in data.get("alerts", []):
            pkg = alert.get("package", {}).get("name", "package")
            desc = alert.get("advisory", {}).get("description", alert.get("summary", ""))
            sev = alert.get("severity", "Medium")
            rows.append({
                "tool": "Dependabot (SCA)",
                "id": f"dep-{pkg}",
                "title": f"{pkg} vulnerability",
                "description": desc,
                "severity": sev.capitalize(),
                "sev_score": severity_to_score(sev),
                "exploit_maturity": detect_exploit_keywords(desc),
                "exposure": 5.0,
                "runtime_evidence": 2.0,
                "Environment": np.random.choice(["Production","Staging","Dev"]),
                "Exploitability": np.random.choice(["Easy","Moderate","Hard"]),
                "AssetValue": np.random.choice(["High","Medium","Low"])
            })
        return pd.DataFrame(rows)
    except:
        return pd.DataFrame()

# --- Load OWASP ZAP (DAST) ---
def load_zap():
    try:
        zap_text_path = os.path.join(REPORTS_DIR, "zap-report.html")
        with open(zap_text_path, "r", encoding="utf-8", errors="ignore") as f:
            zap_text = f.read()
        alert_count = len([m for m in ["alert","vulnerability"] if m in zap_text.lower()])
        sev = "High" if alert_count>5 else ("Medium" if alert_count>0 else "Low")
        sev_score = severity_to_score(sev)
        exploit_maturity = detect_exploit_keywords(zap_text)
        runtime_evidence = 8.0 if alert_count>0 else 0.0
        exposure = 8.0 if "127.0.0.1" not in zap_text else 6.0
        return pd.DataFrame([{
            "tool": "OWASP ZAP",
            "id": "zap-summary",
            "title": f"{alert_count} findings",
            "description": zap_text[:1000],
            "severity": sev,
            "sev_score": sev_score,
            "exploit_maturity": exploit_maturity,
            "exposure": exposure,
            "runtime_evidence": runtime_evidence,
            "Environment": "Production",
            "Exploitability": "Easy",
            "AssetValue": "High"
        }])
    except:
        return pd.DataFrame()

# --- Compute final RiskScore (JIT-style) ---
def calculate_risk(df):
    scores = []
    for _, row in df.iterrows():
        # Base weighted score
        score = 0
        score += PRIORITY_WEIGHTS["Environment"].get(row.get("Environment", ""), 0)
        score += PRIORITY_WEIGHTS["Severity"].get(row.get("severity", ""), 0)
        score += PRIORITY_WEIGHTS["Exploitability"].get(row.get("Exploitability", ""), 0)
        score += PRIORITY_WEIGHTS["AssetValue"].get(row.get("AssetValue", ""), 0)

        # Scale base score to 0-10 range (max possible sum is 22)
        scaled_score = (score / 22) * 10

        # Add randomized adjustment (~±10% of scaled score)
        random_adjustment = np.random.uniform(-0.1, 0.1) * scaled_score
        final_score = scaled_score + random_adjustment

        # Ensure 0-10 range
        scores.append(round(min(max(final_score, 0), 10), 1))

    df["RiskScore"] = scores
    df.sort_values("RiskScore", ascending=False, inplace=True)
    return df

@app.route("/")
def dashboard():
    df_codeql = load_codeql()
    df_dep = load_dependabot()
    df_zap = load_zap()

    df_all = pd.concat([df_codeql, df_dep, df_zap], ignore_index=True)
    df_all = calculate_risk(df_all)

    # --- Visualization ---
    plt.figure(figsize=(12,6))
    colors = df_all["RiskScore"].apply(lambda x: "red" if x>=7 else ("orange" if x>=4 else "green"))
    plt.barh(df_all["title"], df_all["RiskScore"], color=colors)
    plt.xlabel("JIT Risk Score (0-10)")
    plt.title("Consolidated ASPM Dashboard")
    chart_path = os.path.join(REPORTS_DIR, "vuln_chart.png")
    plt.tight_layout()
    plt.savefig(chart_path)
    plt.close()

    # --- Render dashboard ---
    html_template = f"""
    <h1>ASPM Dashboard (JIT Agentic Simulation)</h1>
    <h2>Visualized Risk Ranking</h2>
    <img src="/reports/vuln_chart.png" width="700"/>
    <h2>Detailed Vulnerabilities Table</h2>
    {df_all.to_html(index=False)}
    <p><strong>Explanation:</strong> Each vulnerability is scored using contextual Priority Factors (Environment, Severity, Exploitability, AssetValue). RiskScore (0-10) simulates JIT’s agentic investigation and prioritization guidance for remediation.</p>
    """
    return render_template_string(html_template)

# Serve reports folder for chart
@app.route("/reports/<path:path>")
def send_report(path):
    return send_from_directory(REPORTS_DIR, path)

if __name__ == "__main__":
    app.run(debug=True)
