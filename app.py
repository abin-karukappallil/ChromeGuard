from flask import Flask, request, render_template, jsonify
from werkzeug.utils import secure_filename
import json
import tempfile
import os

app = Flask(__name__)

def analyze_manifest(manifest_data):
    results = {
        "Dangerous Permissions": [],
        "Remote Scripts Detected": [],
        "Background Scripts": [],
        "Suspicious Hosts": []
    }

    dangerous_permissions = {"tabs", "webRequest", "cookies", "nativeMessaging"}
    permissions = set(manifest_data.get("permissions", []))
    results["Dangerous Permissions"] = list(permissions.intersection(dangerous_permissions))

    if "content_scripts" in manifest_data:
        results["Remote Scripts Detected"] = [
            script for script in manifest_data["content_scripts"]
            if any("http" in match for match in script.get("matches", []))
        ]

    if "background" in manifest_data:
        results["Background Scripts"] = manifest_data["background"].get("scripts", [])

    if "externally_connectable" in manifest_data:
        results["Suspicious Hosts"] = [
            host for host in manifest_data["externally_connectable"].get("matches", [])
            if "*" in host
        ]

    return results

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        
        file = request.files['file']
        if not file.filename.endswith('.json'):
            return jsonify({"error": "Invalid file type"}), 400

        manifest_data = json.loads(file.read())
        results = analyze_manifest(manifest_data)
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
