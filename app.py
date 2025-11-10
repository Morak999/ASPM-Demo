from flask import Flask, request, send_from_directory, jsonify, render_template_string

app = Flask(__name__, static_folder='.', template_folder='.')

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Demo purpose only — this is insecure and helps SAST tools detect a reflected XSS
    html = f"<p>You searched for: <strong>{query}</strong></p>"
    html += "<p>(Demo only: Do not use this pattern in real apps!)</p>"
    return render_template_string(html)

@app.route('/api/items')
def api_items():
    return jsonify({
        "items": [
            {"id": 1, "name": "Flask Demo Item", "version": "1.0.0"},
            {"id": 2, "name": "Security Test Item", "version": "2.1.4"}
        ]
    })

if __name__ == "__main__":
    app.run(debug=True)
