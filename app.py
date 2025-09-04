# app.py
# Main entry point for the modular Flask backend
# Moved from your original single app.py — only Flask init, CORS, and blueprint registration remain here.

from flask import Flask, request, jsonify
from flask_cors import CORS

from config import init_config

# Import blueprints from each module
from auth.routes import auth_bp
from campaigns.routes import campaigns_bp
from classification.routes import classification_bp
from files.routes import files_bp
from responses.routes import responses_bp
from campaign_files.routes import campaign_files_bp
from email_generation.routes import email_generation_bp
from emails.routes import emails_bp
from email_accounts.routes_simple import email_accounts_bp

# Initialize Flask
app = Flask(__name__)

# Apply CORS to all routes and allow credentials
CORS(
    app,
    origins=["http://localhost:3000"],
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)

# Load configs (env vars, AWS, Supabase, Sessions)
init_config(app)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(campaigns_bp)
app.register_blueprint(classification_bp)
app.register_blueprint(files_bp)
app.register_blueprint(responses_bp)
app.register_blueprint(campaign_files_bp)
app.register_blueprint(email_generation_bp)
app.register_blueprint(emails_bp)
app.register_blueprint(email_accounts_bp)
# Health check route
@app.route("/")
def home():
    return {"message": "Flask Auth Backend is Running!"}

# Debug route to show all available endpoints
@app.route("/debug/routes")
def debug_routes():
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            "endpoint": rule.endpoint,
            "methods": list(rule.methods),
            "rule": str(rule)
        })
    return jsonify({"routes": routes})

# Handle OPTIONS requests for CORS preflight
@app.route("/<path:path>", methods=["OPTIONS"])
def handle_options(path):
    response = jsonify({"message": "OK"})
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response

if __name__ == "__main__":
    app.run(debug=True, port=5000)
