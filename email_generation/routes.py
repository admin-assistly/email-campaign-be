# email_generation/routes.py
# Endpoints for generating intro emails and threaded replies

from flask import Blueprint, request, jsonify
from email_generation.services import (
    create_session, run_intro, create_response_session, run_response,
    fetch_result, build_thread_history_and_latest
)
from flask import current_app

email_generation_bp = Blueprint("email_generation", __name__, url_prefix="/api")

@email_generation_bp.route("/generate-intro-email", methods=["POST"])
def generate_intro_email():
    data = request.get_json()
    campaign_name = data.get("campaign_name")
    campaign_description = data.get("campaign_description")

    if not campaign_name or not campaign_description:
        return jsonify({"error": "campaign_name and campaign_description are required"}), 400

    INTRO_TASK_ID = current_app.config["INTRO_TASK_ID"]
    TEAM_ID = current_app.config["TEAM_ID"]

    session_id = create_session(INTRO_TASK_ID, TEAM_ID, campaign_name, campaign_description)
    if not session_id:
        return jsonify({"error": "Session creation failed"}), 500

    run_id = run_intro(INTRO_TASK_ID, session_id, campaign_name, campaign_description)
    if not run_id:
        return jsonify({"error": "Run creation failed"}), 500

    email_content = fetch_result(run_id)
    if email_content:
        return jsonify({"generated_email": email_content})
    else:
        return jsonify({"error": "Timed out waiting for email generation."}), 504

@email_generation_bp.route("/generate-threaded-reply", methods=["POST"])
def generate_threaded_reply():
    data = request.get_json()
    email_id = data.get("email_id")

    if not email_id:
        return jsonify({"error": "email_id is required"}), 400

    RESPONDER_TASK_ID = current_app.config["RESPONDER_TASK_ID"]
    TEAM_ID = current_app.config["TEAM_ID"]

    thread_history, latest_message = build_thread_history_and_latest(email_id)
    if not thread_history and not latest_message:
        return jsonify({"error": "No thread history or latest message found for this email_id"}), 400

    session_id = create_response_session(RESPONDER_TASK_ID, TEAM_ID, thread_history, latest_message)
    if not session_id:
        return jsonify({"error": "Session creation failed"}), 500

    run_id = run_response(RESPONDER_TASK_ID, session_id, thread_history, latest_message)
    if not run_id:
        return jsonify({"error": "Run creation failed"}), 500

    email_content = fetch_result(run_id)
    if email_content:
        return jsonify({"generated_email": email_content})
    else:
        return jsonify({"error": "Timed out waiting for email generation."}), 504

@email_generation_bp.route("/generate-prompt", methods=["GET"])
def generate_prompt():
    email_id = request.args.get("email_id")
    if not email_id:
        return jsonify({"error": "email_id is required"}), 400
    try:
        email_id = int(email_id)
    except ValueError:
        return jsonify({"error": "email_id must be an integer"}), 400

    thread_history, latest_message = build_thread_history_and_latest(email_id)
    if not thread_history and not latest_message:
        return jsonify({"error": "No thread history or latest message found for this email_id"}), 400

    return jsonify({"thread_history": thread_history, "latest_message": latest_message})
