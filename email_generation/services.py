# email_generation/services.py
# Moved from your snippet: create_session, run_intro, create_response_session, run_response, fetch_result, build_thread_history_and_latest

import uuid
import time
import requests
from flask import current_app

def _ai():
    cfg = current_app.config
    return (
        cfg["AI_BASE_URL"],
        cfg["AI_HEADERS"],
        cfg["INTRO_TASK_ID"],
        cfg["RESPONDER_TASK_ID"],
        cfg["TEAM_ID"],
    )

def create_session(task_id, team_id, campaign_name, campaign_description):
    AI_BASE_URL, AI_HEADERS, *_ = _ai()
    session_data = {
        "task_id": task_id,
        "team_id": team_id,
        "created_by_user_id": str(uuid.uuid4()),
        "archived": False,
        "team_metadata": {},
        "structured_input": {
            "question": (
                f"Generate a cold intro email template for the following campaign.\n"
                f"Campaign Name: {campaign_name}\n"
                f"Campaign Description: {campaign_description}"
            ),
            "model_answer": (
                f"Campaign: {campaign_name}\n"
                f"Description: {campaign_description}\n"
                "The email should be friendly, concise, and use the placeholder {first_name} for the recipient's name."
            ),
            "learner": (
                f"Please write a cold email template for the campaign '{campaign_name}' "
                f"with the following description: {campaign_description}. "
                "Use {first_name} as a placeholder for the recipient's name."
            )
        }
    }
    try:
        res = requests.post(f"{AI_BASE_URL}/v1/session", json=session_data, headers=AI_HEADERS, timeout=10)
        res.raise_for_status()
        return res.json()["data"]["id"]
    except Exception as e:
        print(f"Session creation failed: {e}")
        return None

def run_intro(task_id, session_id, campaign_name, campaign_description):
    AI_BASE_URL, AI_HEADERS, *_ = _ai()
    prompt = (
        f"Write ONLY the body of a cold outreach email for this campaign:\n"
        f"Campaign Name: {campaign_name}\n"
        f"Campaign Description: {campaign_description}\n"
        "Start with: Hi {first_name},\n"
        "No subject, no greeting other than 'Hi {first_name},', no closing, no signature, no explanations, no extra text, no formatting, no metadata. Output only the email body as plain text."
    )
    payload = {
        "session_id": session_id,
        "task_id": task_id,
        "run_task": {"source": "intro_ui", "content": prompt, "message_type": "string"},
        "batch_mode": False,
        "created_by_user_id": str(uuid.uuid4())
    }
    try:
        res = requests.post(f"{AI_BASE_URL}/v1/run", json=payload, headers=AI_HEADERS, timeout=10)
        res.raise_for_status()
        return res.json()["data"]["id"]
    except Exception as e:
        print(f"Run creation failed: {e}")
        return None

def create_response_session(task_id, team_id, thread_history, latest_message):
    AI_BASE_URL, AI_HEADERS, *_ = _ai()
    session_data = {
        "task_id": task_id,
        "team_id": team_id,
        "created_by_user_id": str(uuid.uuid4()),
        "archived": False,
        "team_metadata": {},
        "structured_input": {
            "question": f"Generate a response to this email thread: {thread_history}",
            "model_answer": f"Professional response considering the context: {thread_history}",
            "learner": f"Please generate a professional email response to this thread. Latest message: {latest_message}"
        }
    }
    try:
        res = requests.post(f"{AI_BASE_URL}/v1/session", json=session_data, headers=AI_HEADERS, timeout=10)
        res.raise_for_status()
        return res.json()["data"]["id"]
    except Exception as e:
        print(f"Response session creation failed: {e}")
        return None

def run_response(task_id, session_id, thread_history, latest_message):
    AI_BASE_URL, AI_HEADERS, *_ = _ai()
    prompt = (
        f"Thread history:\n{thread_history}\n\n"
        f"Latest message:\n{latest_message}\n\n"
        "Write ONLY the body of a professional reply to the latest message, addressing all questions and context. "
        "Do NOT include a subject, greeting, closing, signature, explanations, extra text, formatting, or metadata. "
        "Output only the reply body as plain text. Limit to 250 words."
    )
    payload = {
        "session_id": session_id,
        "task_id": task_id,
        "run_task": {"source": "response_ui", "content": prompt, "message_type": "string"},
        "batch_mode": False,
        "created_by_user_id": str(uuid.uuid4())
    }
    try:
        res = requests.post(f"{AI_BASE_URL}/v1/run", json=payload, headers=AI_HEADERS, timeout=10)
        res.raise_for_status()
        return res.json()["data"]["id"]
    except Exception as e:
        print(f"Response run creation failed: {e}")
        return None

def fetch_result(run_id):
    AI_BASE_URL, AI_HEADERS, *_ = _ai()
    for attempt in range(12):  # Poll for up to 1 minute (12*5s)
        try:
            res = requests.get(f"{AI_BASE_URL}/v1/run/{run_id}", headers=AI_HEADERS, timeout=10)
            data = res.json()
            team_result = data["data"].get("team_result")
            if not team_result:
                time.sleep(5)
                continue
            task_result = team_result.get("task_result", {})
            messages = task_result.get("messages", [])
            if messages:
                return messages[-1].get("content", "")
            time.sleep(5)
        except Exception as e:
            print(f"Error fetching result on attempt {attempt+1}: {e}")
            time.sleep(5)
    return None

def build_thread_history_and_latest(email_id):
    # uses Supabase directly
    supabase = current_app.supabase
    try:
        email = supabase.table("emails").select("body").eq("id", email_id).single().execute().data
    except Exception as e:
        print(f"Error fetching email: {e}")
        return None, None
    if not email:
        return None, None

    thread = [email["body"]]
    responses = supabase.table("responses").select("id,body,created_at").eq("email_id", email_id).order("created_at", desc=False).execute().data
    for resp in responses[:-1]:
        thread.append(resp["body"])
    latest_message = responses[-1]["body"] if responses else ""
    thread_history = "\n---\n".join(thread)
    return thread_history, latest_message
