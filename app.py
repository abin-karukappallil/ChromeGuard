from flask import Flask, render_template, request, jsonify
from extension_analyzer import analyze_extension  # Import analysis logic
import os

app = Flask(__name__)

@app.route('/')
def home():
    """Render the homepage."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze the browser extension provided by the user."""
    try:
        # Retrieve the extension path from the form
        extension_path = request.form.get('extension_path')
        if not extension_path:
            return jsonify({"error": "Please provide an extension path"}), 400

        # Validate the provided path
        if not os.path.exists(extension_path):
            return jsonify({"error": "The provided path does not exist."}), 400
        if not os.path.isfile(os.path.join(extension_path, "manifest.json")):
            return jsonify({"error": "manifest.json file not found in the provided path."}), 400

        # Call the analyze function
        results = analyze_extension(extension_path)
        return jsonify(results)  # Return results as JSON
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
