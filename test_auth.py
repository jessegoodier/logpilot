import os
import sys

sys.path.insert(0, "src")

from functools import wraps

from flask import Flask, jsonify, render_template_string, request


# Simulate the auth decorator
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = os.environ.get("API_KEY")
        if not api_key or api_key == "no-key":
            return f(*args, **kwargs)

        provided_key = request.args.get("api_key")
        if not provided_key:
            provided_key = request.headers.get("X-API-Key")

        if not provided_key or provided_key != api_key:
            if request.headers.get("Accept") == "application/json":
                return jsonify({"error": "API key required"}), 401
            return render_template_string(
                """
                <form method="POST" action="/login">
                    <h2>API Key Required</h2>
                    <input type="text" name="api_key" placeholder="Enter API Key">
                    <button type="submit">Submit</button>
                </form>
            """
            )
        return f(*args, **kwargs)

    return decorated


app = Flask(__name__)


@app.route("/api/test")
@require_api_key
def test_endpoint():
    return jsonify({"message": "success"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
