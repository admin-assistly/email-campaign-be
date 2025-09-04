# responses/routes.py
# Handles email responses, threading, and deletion
# Moved from original app.py: /api/responses endpoints and threading logic

import os
import boto3
from flask import Blueprint, request, jsonify, current_app
from email.utils import make_msgid
from db.postgres import get_db_connection
from classification.routes import classify_response  # for async classification trigger
from auth.middleware import get_current_user_email, get_current_user_id, require_auth  # for getting current user's email and auth decorator
import threading

responses_bp = Blueprint("responses", __name__, url_prefix="/api")

# --- Get Response by Message ID ---
@responses_bp.route("/responses/by-message-id", methods=["GET"])
@require_auth
def get_response_by_message_id():
    message_id = request.args.get('message_id')
    if not message_id:
        return jsonify({"error": "message_id parameter is required"}), 400
    
    # Get current user ID for filtering
    current_user_id = get_current_user_id()
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Clean the message ID and try multiple variations
        clean_mid = message_id.strip().strip('<>')
        
        # Try exact match first, then variations, but only for current user's campaigns
        cur.execute("""
            SELECT r.id, r.email_id, r.parent_response_id, r.responder_email, r.body, 
                   r.created_at, r.message_id, r.in_reply_to
            FROM responses r
            JOIN emails e ON r.email_id = e.id
            JOIN campaigns c ON e.campaign_id = c.id
            WHERE (r.message_id = %s OR r.message_id = %s OR r.message_id = %s)
            AND c.created_by = %s
            ORDER BY r.created_at DESC
        """, (message_id, clean_mid, f"<{clean_mid}>", current_user_id))
        
        responses = cur.fetchall()
        
        if responses:
            # Return as list to match expected format in IMAP fetcher
            result = []
            for response in responses:
                result.append({
                    "id": response[0],
                    "email_id": response[1],
                    "parent_response_id": response[2],
                    "responder_email": response[3],
                    "body": response[4],
                    "created_at": response[5],
                    "message_id": response[6],
                    "in_reply_to": response[7]
                })
            return jsonify(result)
        else:
            return jsonify([])  # Return empty list instead of 404
            
    except Exception as e:
        print(f"Error fetching response by message_id: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()

# --- Create Response ---
@responses_bp.route("/responses", methods=["POST"])
def create_response():
    data = request.json
    message_id = data.get('message_id')
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        email_id = data.get('email_id')
        parent_response_id = data.get('parent_response_id')

        # Pre-check for duplicate - check both with and without angle brackets
        if message_id:
            # Clean the message ID
            clean_mid = message_id.strip().strip('<>')
            print(f"[DEBUG] Checking for duplicate with message_id: {message_id}, clean_mid: {clean_mid}")
            cur.execute("SELECT id FROM responses WHERE message_id = %s OR message_id = %s OR message_id = %s", 
                       (message_id, clean_mid, f"<{clean_mid}>"))
            existing = cur.fetchone()
            if existing:
                print(f"[DEBUG] Duplicate detected for message_id: {message_id}, existing ID: {existing[0]}")
                return jsonify({
                    "id": existing[0], 
                    "duplicate": True,
                    "email_id": email_id,
                    "parent_response_id": parent_response_id,
                    "responder_email": data['responder_email'],
                    "message_id": message_id
                }), 200
            else:
                print(f"[DEBUG] No duplicate found for message_id: {message_id}")

        # Try to find parent by in_reply_to
        if not parent_response_id and data.get('in_reply_to'):
            cur.execute("SELECT id, email_id FROM responses WHERE message_id = %s", (data['in_reply_to'],))
            parent = cur.fetchone()
            if parent:
                parent_response_id = parent[0]
                if not email_id:
                    email_id = parent[1]
            else:
                cur.execute("SELECT id FROM emails WHERE message_id = %s", (data['in_reply_to'],))
                email_row = cur.fetchone()
                if email_row:
                    email_id = email_row[0]

        # Try to match by responder_email and subject (for replies TO the campaign)
        if not email_id:
            cur.execute(
                "SELECT id FROM emails WHERE recipient_email = %s AND subject = %s ORDER BY created_at DESC LIMIT 1",
                (data['responder_email'], data.get('subject'))
            )
            result = cur.fetchone()
            if result:
                email_id = result[0]
                print(f"[DEBUG] Email matched by (recipient_email, subject): {email_id}")

        # Try to match by responder_email only (for replies TO the campaign)
        if not email_id:
            cur.execute(
                "SELECT id FROM emails WHERE recipient_email = %s ORDER BY created_at DESC LIMIT 1",
                (data['responder_email'],)
            )
            result = cur.fetchone()
            if result:
                email_id = result[0]
                print(f"[DEBUG] Email matched by recipient_email only: {email_id}")

        # Try to match by subject similarity (for admin replies FROM the campaign)
        if not email_id and data.get('subject'):
            # Remove "RE:" prefix for matching
            clean_subject = data['subject'].replace('RE:', '').replace('Re:', '').strip()
            cur.execute(
                "SELECT id FROM emails WHERE subject ILIKE %s ORDER BY created_at DESC LIMIT 1",
                (f"%{clean_subject}%",)
            )
            result = cur.fetchone()
            if result:
                email_id = result[0]
                print(f"[DEBUG] Email matched by subject similarity: {email_id}")

        # Try to match by any email sent to the responder_email (for admin replies)
        if not email_id:
            cur.execute(
                "SELECT id FROM emails WHERE recipient_email = %s ORDER BY created_at DESC LIMIT 1",
                (data['responder_email'],)
            )
            result = cur.fetchone()
            if result:
                email_id = result[0]
                print(f"[DEBUG] Email matched by responder_email as recipient: {email_id}")

        # For admin replies, try to match by the TO email address (who they're replying to)
        if not email_id and data.get('from_imap') and data['responder_email'].endswith('@charterglobal.com'):
            # Extract the TO email from the references or in_reply_to
            to_email = None
            if data.get('in_reply_to'):
                # Try to find the original email that this is replying to
                cur.execute("SELECT recipient_email FROM emails WHERE message_id = %s", (data['in_reply_to'],))
                email_row = cur.fetchone()
                if email_row:
                    to_email = email_row[0]
                    print(f"[DEBUG] Found TO email from in_reply_to: {to_email}")
            
            if to_email:
                # Find the email sent to this recipient
                cur.execute(
                    "SELECT id FROM emails WHERE recipient_email = %s ORDER BY created_at DESC LIMIT 1",
                    (to_email,)
                )
                result = cur.fetchone()
                if result:
                    email_id = result[0]
                    print(f"[DEBUG] Email matched by TO email address: {email_id}")

        # If still no match, try to find the correct campaign email
        if not email_id:
            print(f"[DEBUG] No email match found, trying campaign-specific matching...")
            
            # For sent messages from admin, try to find the specific conversation thread
            if data.get('from_imap') and data['responder_email'].endswith('@charterglobal.com'):
                # Try to find the conversation by looking at the references chain
                if data.get('references_chain'):
                    references = data['references_chain'].split()
                    for ref in references:
                        clean_ref = ref.strip().strip('<>')
                        if clean_ref and clean_ref != data.get('message_id', '').strip().strip('<>'):
                            print(f"[DEBUG] Checking reference: {clean_ref}")
                            # Look for responses with this message_id
                            cur.execute("""
                                SELECT email_id FROM responses 
                                WHERE message_id = %s OR message_id = %s OR message_id = %s
                                LIMIT 1
                            """, (clean_ref, f"<{clean_ref}>", clean_ref.strip('<>')))
                            ref_result = cur.fetchone()
                            if ref_result:
                                email_id = ref_result[0]
                                print(f"[DEBUG] Found email_id from reference chain: {email_id}")
                                break
                
                # If still no match, try to find by recipient email in the same time period
                if not email_id and data.get('recipient_email'):
                    # First, try to find if there are any existing responses for this recipient
                    # that might indicate which campaign this conversation belongs to
                    cur.execute("""
                        SELECT DISTINCT r.email_id, r.created_at
                        FROM responses r
                        JOIN emails e ON r.email_id = e.id
                        WHERE e.recipient_email = %s 
                        AND r.created_at >= NOW() - INTERVAL '7 days'
                        ORDER BY r.created_at DESC 
                        LIMIT 1
                    """, (data.get('recipient_email'),))
                    result = cur.fetchone()
                    if result:
                        email_id = result[0]
                        print(f"[DEBUG] Found email_id from existing conversation: {email_id}")
                    else:
                        # Only if no existing conversation, try to find a recent email
                        cur.execute("""
                            SELECT id FROM emails 
                            WHERE recipient_email = %s 
                            AND created_at >= NOW() - INTERVAL '7 days'
                            ORDER BY created_at DESC 
                            LIMIT 1
                        """, (data.get('recipient_email'),))
                        result = cur.fetchone()
                        if result:
                            email_id = result[0]
                            print(f"[DEBUG] Found email_id by recent recipient: {email_id}")
                
                # If still no match, this might be a new conversation - skip it
                if not email_id:
                    print(f"[DEBUG] Could not find matching campaign email for sent message")
                    return jsonify({"error": "Could not match reply to any campaign email."}), 400
                
                # Additional validation: Check if this sent message is actually part of an existing conversation
                # by looking for any responses in the same thread
                if email_id and data.get('message_id'):
                    cur.execute("""
                        SELECT COUNT(*) FROM responses 
                        WHERE email_id = %s 
                        AND created_at >= NOW() - INTERVAL '1 hour'
                    """, (email_id,))
                    response_count = cur.fetchone()[0]
                    
                    if response_count == 0:
                        print(f"[DEBUG] No recent responses found for email_id {email_id}, this might be a wrong match")
                        # Check if there are any responses at all for this email
                        cur.execute("SELECT COUNT(*) FROM responses WHERE email_id = %s", (email_id,))
                        total_responses = cur.fetchone()[0]
                        if total_responses == 0:
                            print(f"[DEBUG] No responses found for email_id {email_id}, skipping to avoid wrong campaign linking")
                            return jsonify({"error": "Could not match reply to any campaign email."}), 400
            else:
                # For regular responses, try to find by recipient email
                if data.get('recipient_email'):
                    cur.execute("""
                        SELECT id FROM emails 
                        WHERE recipient_email = %s 
                        ORDER BY created_at DESC 
                        LIMIT 1
                    """, (data.get('recipient_email'),))
                    result = cur.fetchone()
                    if result:
                        email_id = result[0]
                        print(f"[DEBUG] Found email_id by recipient: {email_id}")
                    else:
                        return jsonify({"error": "Could not match reply to any campaign email."}), 400
                else:
                    return jsonify({"error": "Could not match reply to any campaign email."}), 400

        # Insert the response
        try:
            cur.execute(
                '''
                INSERT INTO responses (email_id, parent_response_id, responder_email, body, created_at, message_id, 
                                     in_reply_to, references_chain, subject, from_imap)
                VALUES (%s, %s, %s, %s, NOW(), %s, %s, %s, %s, %s)
                RETURNING id
                ''',
                (
                    email_id,
                    parent_response_id,
                    data['responder_email'],
                    data['body'],
                    message_id,
                    data.get('in_reply_to'),
                    data.get('references_chain'),
                    data.get('subject'),
                    data.get('from_imap', False)
                )
            )
            response_id = cur.fetchone()[0]
        except Exception as insert_error:
            # Check if this is a unique constraint violation
            if "duplicate key value violates unique constraint" in str(insert_error) and message_id:
                print(f"[DEBUG] Database constraint violation for message_id: {message_id}")
                # Try to get the existing response ID
                cur.execute("SELECT id FROM responses WHERE message_id = %s", (message_id,))
                existing = cur.fetchone()
                if existing:
                    print(f"[DEBUG] Found existing response ID: {existing[0]}")
                    return jsonify({
                        "id": existing[0], 
                        "duplicate": True,
                        "email_id": email_id,
                        "parent_response_id": parent_response_id,
                        "responder_email": data['responder_email'],
                        "message_id": message_id
                    }), 200
            # Re-raise the error if it's not a duplicate key violation
            raise insert_error

        # Check if this is from admin and should send email
        is_from_admin = data['responder_email'].endswith('@charterglobal.com')
        is_from_imap = data.get('from_imap', False)
        
        # Only send email if it's from admin AND NOT from IMAP (to prevent duplicates)
        if is_from_admin and not is_from_imap:
            try:
                cur.execute('''
                    SELECT e.recipient_email, e.subject, e.message_id 
                    FROM emails e 
                    WHERE e.id = %s
                ''', (email_id,))
                email_row = cur.fetchone()
                if email_row:
                    recipient_email = email_row[0]
                    original_subject = email_row[1]
                    original_message_id = email_row[2]
                    subject = data.get('subject', f"Re: {original_subject}")
                    body = data['body']

                    ses = boto3.client('ses', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
                    
                    # Use the actual user's email as sender instead of hardcoded email
                    # Use the actual user's email as sender instead of hardcoded email
                    # Use the actual user's email as sender instead of hardcoded email
                    user_email = get_current_user_email()
                    user_email = get_current_user_email()
                    user_email = get_current_user_email()
                    if not user_email:
                        print(f"❌ No user email found in session - authentication required")
                        return jsonify({"error": "Not authenticated; cannot determine sender"}), 401
                    
                    if user_email.endswith('@charterglobal.com'):
                        sender = user_email
                        print(f"📧 Using authenticated user email as sender: {sender}")
                    else:
                        # Fallback to environment variable if user email is not Charter Global
                        sender = os.environ.get('SES_SENDER_EMAIL', 'aipoc@charterglobal.com')
                        print(f"⚠️ Using fallback sender: {sender} (user: {user_email})")
                    
                    reply_msg_id = make_msgid(domain="charterglobal.com")

                    raw_message = (
                        "MIME-Version: 1.0\r\n"
                        f"From: {sender}\r\n"
                        f"To: {recipient_email}\r\n"
                        f"Subject: {subject}\r\n"
                        f"Message-ID: {reply_msg_id}\r\n"
                        f"In-Reply-To: {original_message_id}\r\n"
                        f"References: {original_message_id}\r\n"
                        "Content-Type: text/plain; charset=UTF-8\r\n"
                        "\r\n"
                        f"{body}"
                    )

                    # Send the email with detailed error handling
                    try:
                        response = ses.send_raw_email(
                            Source=sender,
                            Destinations=[recipient_email],
                            RawMessage={'Data': raw_message.encode('utf-8')}
                        )
                        print(f"✅ Email sent to {recipient_email} via SES from {sender}")
                        print(f"📧 SES Message ID: {response.get('MessageId', 'N/A')}")
                    except ses.exceptions.MessageRejected as e:
                        print(f"❌ SES Message Rejected: {e}")
                        print(f"   Error Code: {e.response['Error']['Code']}")
                        print(f"   Error Message: {e.response['Error']['Message']}")
                    except ses.exceptions.MailFromDomainNotVerifiedException as e:
                        print(f"❌ Mail From Domain Not Verified: {e}")
                    except ses.exceptions.ConfigurationSetDoesNotExistException as e:
                        print(f"❌ Configuration Set Does Not Exist: {e}")
                    except Exception as e:
                        print(f"❌ SES Error: {e}")
                        print(f"   Error Type: {type(e).__name__}")
            except Exception as email_error:
                print(f"❌ Failed to send email: {email_error}")
                print(f"   Error Type: {type(email_error).__name__}")
        elif is_from_admin and is_from_imap:
            print(f"[DEBUG] Skipping email send (IMAP detected sent email)")
        else:
            print(f"[DEBUG] Skipping email send (not admin email)")

        conn.commit()

        # Trigger async classification
        if response_id:
            try:
                def classify_async():
                    # Import here to avoid circular imports
                    from classification.routes import classify_response
                    try:
                        print(f"[DEBUG] Starting classification for response {response_id}")
                        classify_response(response_id)
                        print(f"[DEBUG] Classification completed for response {response_id}")
                    except Exception as e:
                        print(f"[ERROR] Failed to classify response {response_id}: {e}")
                thread = threading.Thread(target=classify_async)
                thread.daemon = True
                thread.start()
                print(f"[DEBUG] Classification thread started for response {response_id}")
            except Exception as e:
                print(f"[ERROR] Failed to start classification for response {response_id}: {e}")

        return jsonify({
            "id": response_id,
            "email_id": email_id,
            "parent_response_id": parent_response_id,
            "responder_email": data['responder_email'],
            "message_id": message_id
        }), 201
    except Exception as e:
        print("Error inserting response:", e)
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()

# --- Get Latest Responses (1 per thread) ---
@responses_bp.route("/responses", methods=["GET"])
@require_auth
def get_responses():
    conn = get_db_connection()
    cur = conn.cursor()

    # Get current user ID for filtering
    current_user_id = get_current_user_id()

    campaign_id = request.args.get('campaign_id')
    where_clause = "WHERE c.created_by = %s"
    params = [current_user_id]
    
    if campaign_id:
        where_clause += " AND e.campaign_id = %s"
        params.append(campaign_id)

    # Get all responses grouped by email_id to create conversation threads
    cur.execute(f"""
        SELECT 
            r.id,
            r.email_id,
            r.parent_response_id,
            r.created_at,
            r.responder_email,
            r.body,
            r.message_id,
            r.in_reply_to,
            e.recipient_email,
            e.subject,
            e.campaign_id,
            c.name AS campaign_name
        FROM responses r
        JOIN emails e   ON r.email_id = e.id
        JOIN campaigns c ON e.campaign_id = c.id
        {where_clause}
        ORDER BY r.email_id, r.created_at
    """, params)

    responses = cur.fetchall()
    
    # Group responses by email_id to create conversation threads
    threads_by_email = {}
    for row in responses:
        email_id = row[1]
        if email_id not in threads_by_email:
            threads_by_email[email_id] = {
                "email_id": email_id,
                "campaign_id": row[10],
                "campaign_name": row[11],
                "subject": row[9],
                "recipient_email": row[8],
                "conversation": [],
                "total_responses": 0,
                "latest_response_time": None,
                "root_response_id": None,
                "latest_response_id": None
            }
        
        response_obj = {
            "id": row[0],
            "parent_response_id": row[2],
            "created_at": row[3],
            "responder_email": row[4],
            "body": row[5],
            "message_id": row[6],
            "in_reply_to": row[7],
            "status": "Unread",
            "children": []
        }
        
        threads_by_email[email_id]["conversation"].append(response_obj)
        threads_by_email[email_id]["total_responses"] += 1
        
        # Track latest response time and IDs
        if not threads_by_email[email_id]["latest_response_time"] or row[3] > threads_by_email[email_id]["latest_response_time"]:
            threads_by_email[email_id]["latest_response_time"] = row[3]
            threads_by_email[email_id]["latest_response_id"] = row[0]
        
        # Set root response ID (first response in thread)
        if not threads_by_email[email_id]["root_response_id"]:
            threads_by_email[email_id]["root_response_id"] = row[0]

    # Convert to list and sort by latest response time
    threads = list(threads_by_email.values())
    threads.sort(key=lambda x: x["latest_response_time"] or "", reverse=True)

    cur.close()
    conn.close()
    return jsonify(threads)

# --- Fetch Full Thread ---
def fetch_response_thread(conn, response_id):
    cur = conn.cursor()
    cur.execute("""
        SELECT 
            r.id, r.email_id, r.parent_response_id, r.created_at,
            r.responder_email, r.body,
            e.recipient_email, e.subject, e.campaign_id,
            c.name as campaign_name
        FROM responses r
        LEFT JOIN emails e ON r.email_id = e.id
        LEFT JOIN campaigns c ON e.campaign_id = c.id
        WHERE r.id = %s
    """, (response_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        return None

    response = {
        "id": row[0],
        "email_id": row[1],
        "parent_response_id": row[2],
        "created_at": row[3],
        "responder_email": row[4],
        "body": row[5],
        "recipient_email": row[6],
        "subject": row[7],
        "campaign_id": row[8],
        "campaign_name": row[9],
        "children": []
    }

    cur.execute("SELECT id FROM responses WHERE parent_response_id = %s ORDER BY created_at", (response_id,))
    child_ids = [r[0] for r in cur.fetchall()]
    for child_id in child_ids:
        child = fetch_response_thread(conn, child_id)
        if child:
            response["children"].append(child)

    cur.close()
    return response

# --- Get Thread by Response ID ---
@responses_bp.route("/responses/<int:response_id>", methods=["GET"])
@require_auth
def get_response_by_id(response_id):
    print(f"Fetching response thread for ID: {response_id}")
    
    # Get current user ID for filtering
    current_user_id = get_current_user_id()
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # First, verify this response belongs to the current user's campaign
    cur.execute("""
        SELECT r.email_id FROM responses r
        JOIN emails e ON r.email_id = e.id
        JOIN campaigns c ON e.campaign_id = c.id
        WHERE r.id = %s AND c.created_by = %s
    """, (response_id, current_user_id))
    
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return jsonify({"error": "Response not found or access denied"}), 404
    
    email_id = row[0]
    print(f"Found email_id: {email_id} for response {response_id}")
    
    # Get ALL responses for this email_id (entire conversation) - already verified user access
    cur.execute("""
        SELECT 
            r.id, r.email_id, r.parent_response_id, r.created_at,
            r.responder_email, r.body, r.message_id, r.in_reply_to,
            e.recipient_email, e.subject, e.campaign_id,
            c.name as campaign_name
        FROM responses r
        LEFT JOIN emails e ON r.email_id = e.id
        LEFT JOIN campaigns c ON e.campaign_id = c.id
        WHERE r.email_id = %s
        ORDER BY r.created_at ASC
    """, (email_id,))
    
    responses = cur.fetchall()
    print(f"Found {len(responses)} responses for email_id {email_id}")
    
    if not responses:
        cur.close()
        conn.close()
        return jsonify({"error": "No responses found for this email"}), 404
    
    # Create the root response (first response in the conversation)
    root_response = {
        "id": responses[0][0],
        "email_id": responses[0][1],
        "parent_response_id": responses[0][2],
        "created_at": responses[0][3],
        "responder_email": responses[0][4],
        "body": responses[0][5],
        "message_id": responses[0][6],
        "in_reply_to": responses[0][7],
        "recipient_email": responses[0][8],
        "subject": responses[0][9],
        "campaign_id": responses[0][10],
        "campaign_name": responses[0][11],
        "children": []
    }
    
    # Add all other responses as children (flat structure for frontend)
    for i in range(1, len(responses)):
        child_response = {
            "id": responses[i][0],
            "email_id": responses[i][1],
            "parent_response_id": responses[i][2],
            "created_at": responses[i][3],
            "responder_email": responses[i][4],
            "body": responses[i][5],
            "message_id": responses[i][6],
            "in_reply_to": responses[i][7],
            "recipient_email": responses[i][8],
            "subject": responses[i][9],
            "campaign_id": responses[i][10],
            "campaign_name": responses[i][11],
            "children": []
        }
        root_response["children"].append(child_response)
    
    cur.close()
    conn.close()
    return jsonify(root_response)

# --- Delete Response ---
@responses_bp.route("/responses/<int:response_id>", methods=["DELETE"])
@require_auth
def delete_response(response_id):
    # Get current user ID for filtering
    current_user_id = get_current_user_id()
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Verify this response belongs to the current user's campaign before deleting
    cur.execute("""
        SELECT r.id FROM responses r
        JOIN emails e ON r.email_id = e.id
        JOIN campaigns c ON e.campaign_id = c.id
        WHERE r.id = %s AND c.created_by = %s
    """, (response_id, current_user_id))
    
    if not cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({"error": "Response not found or access denied"}), 404
    
    # Now delete the response
    cur.execute('DELETE FROM responses WHERE id = %s RETURNING id', (response_id,))
    deleted = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    
    if not deleted:
        return jsonify({"error": "Response not found"}), 404
    return jsonify({"success": True})
