# dashboard_app.py
from flask import Flask, render_template_string
import json, os, re

app = Flask(__name__)

# ----- helper: safe read json -----
def try_load_json(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None

# ----- helper: read text/html -----
def try_read_text(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception:
        return ''

# ----- convert severity string -> 0-10 proxy -----
def severity_to_score(s):
    s = (s or '').lower()
    if 'crit' in s or 'high' in s: return 9.0
    if 'med' in s or 'medium' in s: return 5.0
    if 'low' in s: return 2.0
    return 3.0

# ----- basic keyword detector for exploitability (PoC/Exploit keywords) -----
def detect_exploit_keywords(text):
    txt = (text or "").lower()
    for k in ['exploit', 'poc', 'proof of concept', 'metasploit', 'weaponized', 'rce', 'remote code execution']:
        if k in txt:
            return 10.0
    return 0.0

# ----- main loader that builds consolidated findings list -----
def load_reports():
    results = []

    # 1) SAST - CodeQL
    codeql = try_load_json(os.path.join('reports', 'codeql_report.json'))
    if codeql and isinstance(codeql.get('alerts'), list):
        for a in codeql['alerts']:
            rule = a.get('rule', {}) if isinstance(a, dict) else a
            vuln_id = rule.get('id', 'codeql-alert')
            desc = rule.get('description') or a.get('message') or ''
            sev = rule.get('severity') or 'medium'
            sev_score = severity_to_score(sev)
            exploit_maturity = detect_exploit_keywords(desc)
            results.append({
                'tool': 'CodeQL (SAST)',
                'id': vuln_id,
                'title': vuln_id,
                'description': desc,
                'severity': sev.capitalize(),
                'sev_score': sev_score,
                'exploit_maturity': exploit_maturity,
                'exposure': 5.0,
                'runtime_evidence': 0.0
            })
    else:
        results.append({
            'tool': 'CodeQL (SAST)',
            'id': 'no-codeql',
            'title': 'No CodeQL report',
            'description': 'Run CodeQL on GitHub to produce alerts.',
            'severity': 'None',
            'sev_score': 0.0,
            'exploit_maturity': 0.0,
            'exposure': 0.0,
            'runtime_evidence': 0.0
        })

    # 2) DAST - OWASP ZAP
    zap_text = try_read_text(os.path.join('reports', 'zap-report.html'))
    if zap_text:
        alert_count = max(0, len(re.findall(r'alert', zap_text, flags=re.IGNORECASE)))
        vuln_count = max(0, len(re.findall(r'vulnerability', zap_text, flags=re.IGNORECASE)))
        total_flags = alert_count + vuln_count
        desc = zap_text[:1000]
        sev = 'High' if total_flags > 5 else ('Medium' if total_flags > 0 else 'Low')
        sev_score = severity_to_score(sev)
        exploit_maturity = detect_exploit_keywords(zap_text)
        runtime_evidence = 8.0 if total_flags > 0 else 0.0
        exposure = 8.0 if '127.0.0.1' not in zap_text else 6.0
        results.append({
            'tool': 'OWASP ZAP (DAST)',
            'id': 'zap-summary',
            'title': f'{total_flags} DAST findings',
            'description': f'ZAP scan summary (found {total_flags} flags).',
            'severity': sev,
            'sev_score': sev_score,
            'exploit_maturity': exploit_maturity,
            'exposure': exposure,
            'runtime_evidence': runtime_evidence
        })
    else:
        results.append({
            'tool': 'OWASP ZAP (DAST)',
            'id': 'no-zap',
            'title': 'No ZAP report',
            'description': 'Run DAST workflow to generate zap-report.html.',
            'severity': 'None',
            'sev_score': 0.0,
            'exploit_maturity': 0.0,
            'exposure': 0.0,
            'runtime_evidence': 0.0
        })

    # 3) SCA - Dependabot
    dep_path = os.path.join('reports', 'dependabot_summary.json')
    dep = try_load_json(dep_path)
    if dep and isinstance(dep.get('alerts'), list):
        for a in dep['alerts']:
            pkg = a.get('package', {}).get('name') or 'package'
            desc = a.get('advisory', {}).get('description', '') or a.get('summary', '')
            sev = a.get('severity', 'medium')
            sev_score = severity_to_score(sev)
            exploit_maturity = detect_exploit_keywords(desc)
            results.append({
                'tool': 'Dependabot (SCA)',
                'id': f'dep-{pkg}',
                'title': f'{pkg} vulnerability',
                'description': desc,
                'severity': sev.capitalize(),
                'sev_score': sev_score,
                'exploit_maturity': exploit_maturity,
                'exposure': 5.0,
                'runtime_evidence': 2.0
            })
    else:
        results.append({
            'tool': 'Dependabot (SCA)',
            'id': 'no-dep',
            'title': 'Dependabot: check GitHub Security tab',
            'description': 'Dependabot findings are available in GitHub Security → Dependabot alerts.',
            'severity': 'None',
            'sev_score': 0.0,
            'exploit_maturity': 0.0,
            'exposure': 0.0,
            'runtime_evidence': 0.0
        })

    # ----- Compute final exploit likelihood score (weighted 0-10) -----
    w_sev = 0.35
    w_exploit = 0.30
    w_exposure = 0.20
    w_runtime = 0.15

    for r in results:
        sev = float(r.get('sev_score', 0.0))
        expl = float(r.get('exploit_maturity', 0.0))
        exposure = float(r.get('exposure', 0.0))
        runtime = float(r.get('runtime_evidence', 0.0))
        score = (w_sev*sev + w_exploit*expl + w_exposure*exposure + w_runtime*runtime)
        r['exploit_score'] = round(min(score, 10.0), 2)

    results.sort(key=lambda x: x['exploit_score'], reverse=True)
    return results

# ----- web UI -----
@app.route('/')
def dashboard():
    findings = load_reports()
    html = """
    <html><head>
      <title>ASPM Dashboard (ranked)</title>
      <style>
        body{font-family:Arial;margin:24px;background:#f4f6f8}
        table{width:100%;border-collapse:collapse;background:#fff}
        th,td{padding:10px;border:1px solid #ddd;text-align:left}
        th{background:#222;color:#fff}
        .score{font-weight:bold}
      </style>
    </head>
    <body>
      <h1>ASPM Dashboard Simulation — Ranked by Exploit Likelihood</h1>
      <p>Combines CodeQL, OWASP ZAP, and Dependabot. Higher score = more likely to be exploited.</p>
      <table>
        <tr>
          <th>Rank</th><th>Tool</th><th>ID</th><th>Title</th><th>Severity</th>
          <th>Exploit Score (0-10)</th><th>Exploit Maturity</th><th>Exposure</th>
          <th>Runtime Evidence</th><th>Description</th>
        </tr>
        {% for i,item in enumerate(findings) %}
        <tr>
          <td>{{ i+1 }}</td>
          <td>{{ item.tool }}</td>
          <td>{{ item.id }}</td>
          <td>{{ item.title }}</td>
          <td>{{ item.severity }}</td>
          <td class="score">{{ item.exploit_score }}</td>
          <td>{{ item.exploit_maturity }}</td>
          <td>{{ item.exposure }}</td>
          <td>{{ item.runtime_evidence }}</td>
          <td style="max-width:420px">{{ item.description|truncate(200) }}</td>
        </tr>
        {% endfor %}
      </table>
    </body></html>
    """
    return render_template_string(html, findings=findings, enumerate=enumerate)


if __name__ == "__main__":
    app.run(debug=True)
