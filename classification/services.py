# classification/services.py
# AI email classification services
# Moved from original app.py: call_ai_classifier() and parse_classification_result()

import requests
import uuid
import json

def call_ai_classifier(email_data):
    """Send email to Aegis for classification - moved from original app.py"""

    print(f"[DEBUG] Starting AI classification for email data: {email_data}")

    # Aegis Configuration - Update these with your actual values
    aegis_api_url = "http://127.0.0.1:8000"  # Update with your Aegis URL
    api_key = "dev_mock_key_12345"  # Update with your API key

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key
    }

    # Test Aegis connectivity first - try different health endpoints
    health_endpoints = ["/health", "/", "/api/health", "/status"]
    aegis_accessible = False

    for endpoint in health_endpoints:
        try:
            health_check = requests.get(f"{aegis_api_url}{endpoint}", timeout=5)
            print(f"[DEBUG] Aegis health check {endpoint}: {health_check.status_code}")
            if health_check.status_code in [200, 404]:
                aegis_accessible = True
                break
        except Exception as e:
            print(f"[DEBUG] Aegis {endpoint} not accessible: {e}")
            continue

    if not aegis_accessible:
        print(f"[ERROR] Aegis service not accessible at {aegis_api_url}")
        return None

    # Create session first
    session_data = {
        "task_id": "01987be7-6de5-7849-aebf-17167c8c3361",
        "team_id": "01987d5d-2a37-7e6d-b152-d8db3c3f34e9",
        "created_by_user_id": str(uuid.uuid4()),
        "archived": False,
        "team_metadata": {},
        "structured_input": {
            "input_config": {
                "email_subject": "",
                "email_body": "",
                "sender": "",
                "campaign_id": ""
            }
        }
    }

    try:
        print(f"[DEBUG] Creating session with Aegis at {aegis_api_url}")
        session_response = requests.post(
            f"{aegis_api_url}/v1/session",
            json=session_data,
            headers=headers,
            timeout=30
        )

        print(f"[DEBUG] Session response status: {session_response.status_code}")
        if session_response.status_code not in [200, 201]:
            print(f"[ERROR] Session creation failed: {session_response.text}")
            return None

        session_result = session_response.json()
        session_id = session_result.get('data', {}).get('id')
        print(f"[DEBUG] Created session: {session_id}")

        # Run classification using string format
        email_content = (
            f"**Email Subject:** {email_data['subject']}\n\n"
            f"**Email Body:**\n{email_data['body']}\n\n"
            f"**Sender:** {email_data['sender']}\n\n"
            f"**Campaign ID:** {email_data.get('campaign_id', 'auto_reply')}"
        )

        print(f"[DEBUG] Sending email content to AI classifier")
        print(f"[DEBUG] Content length: {len(email_content)} characters")

        classification_data = {
            "session_id": session_id,
            "task_id": "01987be7-6de5-7849-aebf-17167c8c3361",
            "run_task": {
                "source": "email_reply_reader",
                "content": email_content,
                "message_type": "string"
            },
            "batch_mode": False,
            "created_by_user_id": str(uuid.uuid4())
        }

        run_response = requests.post(
            f"{aegis_api_url}/v1/run",
            json=classification_data,
            headers=headers,
            timeout=60
        )

        print(f"[DEBUG] Run response status: {run_response.status_code}")
        if run_response.status_code in [200, 201]:
            run_result = run_response.json()
            run_id = run_result.get('data', {}).get('id')
            print(f"[DEBUG] Started classification run: {run_id}")

            # Wait for processing with progressive checks
            import time
            for attempt in range(3):
                print(f"[DEBUG] Waiting for AI processing... (attempt {attempt + 1})")
                time.sleep(5)

                # Get results
                result_response = requests.get(
                    f"{aegis_api_url}/v1/run/{run_id}",
                    headers=headers
                )

                print(f"[DEBUG] Result response status: {result_response.status_code}")
                if result_response.status_code == 200:
                    result_data = result_response.json()
                    status = result_data.get('data', {}).get('status')
                    print(f"[DEBUG] Processing status: {status}")

                    if status == 'complete':
                        print(f"[DEBUG] Processing complete, parsing result...")
                        return parse_classification_result(result_data, email_data)
                    elif status in ['failed', 'error']:
                        print(f"[ERROR] AI classification failed with status: {status}")
                        return None
                    else:
                        print(f"[DEBUG] Still processing, waiting more...")
                        continue

            print(f"[ERROR] AI classification timed out after multiple attempts")
        else:
            print(f"[ERROR] Classification run failed: {run_response.text}")

        return None

    except Exception as e:
        print(f"[ERROR] Classification error: {e}")
        import traceback
        traceback.print_exc()
        return None

def parse_classification_result(result_data, original_email):
    """Parse classification result from Aegis response - moved from original app.py"""
    try:
        print(f"[DEBUG] Full result data: {result_data}")

        messages = result_data.get('data', {}).get('team_result', {}).get('task_result', {}).get('messages', [])
        print(f"[DEBUG] Found {len(messages)} messages")

        agent_message = None
        for msg in messages:
            print(f"[DEBUG] Message source: {msg.get('source')}, content preview: {str(msg.get('content', ''))[:100]}")
            if msg.get('source') == 'email_classifier_agent' or 'classification' in str(msg.get('content', '')).lower():
                agent_message = msg
                break

        if not agent_message:
            task_result = result_data.get('data', {}).get('team_result', {}).get('task_result', {})
            if 'output' in task_result:
                agent_message = {'content': task_result['output']}
            elif 'result' in task_result:
                agent_message = {'content': task_result['result']}

        if agent_message and agent_message.get('content'):
            content = str(agent_message['content'])
            print(f"[DEBUG] Processing agent content: {content[:200]}...")

            json_str = None
            if '```json' in content:
                json_start = content.find('```json') + 7
                json_end = content.find('```', json_start)
                json_str = content[json_start:json_end].strip()
            elif '{' in content and '}' in content:
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                json_str = content[json_start:json_end]
            else:
                print(f"[DEBUG] No JSON found, analyzing text content")
                content_lower = content.lower()
                if any(phrase in content_lower for phrase in ["interested", "qualified", "positive response", "wants to know more"]):
                    if any(phrase in content_lower for phrase in ["later", "follow up", "more information", "details"]):
                        return "interested_later"
                    else:
                        return "interested"
                elif any(phrase in content_lower for phrase in ["not interested", "declined", "negative", "remove", "unsubscribe"]):
                    return "not_interested"
                else:
                    return "interested_later"

            if json_str:
                print(f"[DEBUG] Extracted JSON: {json_str}")
                classification = json.loads(json_str)
                
                # Check multiple possible field names that the AI might return
                classification_value = (
                    classification.get("classification", "") or 
                    classification.get("category", "") or 
                    classification.get("result", "") or 
                    classification.get("status", "")
                ).lower()
                
                print(f"[DEBUG] AI Classification: {classification_value}")

                if classification_value in ["interested", "qualified", "positive", "yes"]:
                    return "interested"
                elif classification_value in ["not_interested", "not interested", "negative", "no", "decline", "declined"]:
                    return "not_interested"
                elif classification_value in ["interested_later", "interested later", "later", "follow_up", "follow up", "more_info", "more info", "information", "details"]:
                    return "interested_later"
                else:
                    return "interested_later"

    except Exception as e:
        print(f"[ERROR] Error parsing AI classification: {e}")
        print(f"[ERROR] Result data structure: {result_data}")

    print(f"[WARNING] AI classification failed completely, using fallback")
    return "interested_later"
