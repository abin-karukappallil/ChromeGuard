import os
import json
from flask import Flask, request, render_template

app = Flask(__name__)

# Configurations
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'json'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Helper function to validate uploaded files
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Helper function to analyze the manifest.json
def analyze_manifest(manifest_path):
    try:
        with open(manifest_path, 'r') as file:
            manifest_data = json.load(file)

        # Analysis logic
        results = {}

        # Check for dangerous permissions
        dangerous_permissions = {"tabs", "webRequest", "cookies", "nativeMessaging"}
        permissions = set(manifest_data.get("permissions", []))
        results["Dangerous Permissions"] = list(permissions.intersection(dangerous_permissions))

        # Check for remote scripts
        remote_scripts = []
        if "content_scripts" in manifest_data:
            for script in manifest_data["content_scripts"]:
                if any("http" in match for match in script.get("matches", [])):
                    remote_scripts.append(script)
        results["Remote Scripts Detected"] = remote_scripts

        # Analyze background scripts
        background_scripts = manifest_data.get("background", {}).get("scripts", [])
        results["Background Scripts"] = background_scripts

        # Check for suspicious hosts
        suspicious_hosts = []
        if "externally_connectable" in manifest_data:
            matches = manifest_data["externally_connectable"].get("matches", [])
            suspicious_hosts = [host for host in matches if "*" in host]
        results["Suspicious Hosts"] = suspicious_hosts

        return results
    except Exception as e:
        return {"Error": str(e)}

# Routes
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if a file was uploaded
        if 'file' not in request.files:
            return render_template('index.html', error="No file uploaded.")
        file = request.files['file']

        # Validate the file
        if file.filename == '' or not allowed_file(file.filename):
            return render_template('index.html', error="Invalid file type. Only manifest.json is allowed.")

        # Save the file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Analyze the uploaded manifest.json
        results = analyze_manifest(file_path)

        return render_template('index.html', results=results)

    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)
