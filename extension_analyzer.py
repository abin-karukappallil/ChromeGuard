import os
import json

def load_manifest(extension_path):
    """Load the manifest.json file from the extension path."""
    try:
        manifest_path = os.path.join(extension_path, "manifest.json")
        with open(manifest_path, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def analyze_extension(extension_path):
    """Analyze the extension's manifest.json file for potential risks."""
    manifest_data = load_manifest(extension_path)
    if not manifest_data:
        return {"error": "Invalid extension path or missing manifest.json file."}

    results = {}
    dangerous_permissions = {"tabs", "webRequest", "cookies", "nativeMessaging"}
    permissions = set(manifest_data.get("permissions", []))
    results["Dangerous Permissions"] = list(permissions.intersection(dangerous_permissions))

    if "content_scripts" in manifest_data:
        scripts = manifest_data["content_scripts"]
        remote_scripts = [
            s for s in scripts if any("http" in match for match in s.get("matches", []))
        ]
        results["Remote Scripts Detected"] = remote_scripts

    if "background" in manifest_data:
        background_scripts = manifest_data["background"].get("scripts", [])
        results["Background Scripts"] = background_scripts

    if "externally_connectable" in manifest_data:
        hosts = manifest_data["externally_connectable"].get("matches", [])
        results["Suspicious Hosts"] = [host for host in hosts if "*" in host]

    return results
