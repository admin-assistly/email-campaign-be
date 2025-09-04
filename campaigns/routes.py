# campaigns/routes.py
# Campaign-related routes

from flask import Blueprint, request, jsonify
from auth.middleware import require_auth, get_current_user_email, get_current_user_id, validate_user_owns_campaign
from db.postgres import get_db_connection
import boto3
import os
from datetime import datetime
import time

import csv
import requests
from urllib.parse import urlparse
from email.utils import make_msgid

campaigns_bp = Blueprint("campaigns", __name__, url_prefix="/api")

# --- Get Campaigns ---
@campaigns_bp.route("/campaigns", methods=["GET"])
@require_auth
def get_campaigns():
    print(f"🔍 [CAMPAIGNS-GET] Starting get_campaigns")
    user_id = get_current_user_id()
    print(f"🔍 [CAMPAIGNS-GET] User ID: {user_id}")
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT c.id, c.name, c.subject, c.description, c.created_by, c.created_at,
               COUNT(e.id) as recipients
        FROM campaigns c
        LEFT JOIN emails e ON c.id = e.campaign_id
        WHERE c.created_by = %s
        GROUP BY c.id
        ORDER BY c.created_at DESC
    """, (user_id,))
    campaigns = [
        {
            "id": row[0],
            "name": row[1],
            "subject": row[2],
            "description": row[3],
            "created_by": row[4],
            "created_at": row[5],
            "recipients": row[6]
        }
        for row in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return jsonify(campaigns)

# --- Create Campaign ---
@campaigns_bp.route("/campaigns", methods=["POST"])
@require_auth
def create_campaign():
    data = request.json
    
    # Validate required fields
    if not data.get('name') or not data.get('subject'):
        return jsonify({"error": "Missing required fields: name and subject"}), 400
    
    # Use the authenticated user's ID instead of email
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "User not found"}), 404
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute(
            'INSERT INTO campaigns (name, subject, description, created_by) VALUES (%s, %s, %s, %s) RETURNING id',
            (data['name'], data['subject'], data.get('description'), user_id)
        )
        campaign_id = cur.fetchone()[0]
        conn.commit()
        
        return jsonify({
            "id": campaign_id,
            "name": data['name'],
            "subject": data['subject'],
            "description": data.get('description'),
            "created_by": user_id
        }), 201
        
    except Exception as e:
        conn.rollback()
        print(f"Error creating campaign: {e}")
        return jsonify({"error": "Failed to create campaign"}), 500
    finally:
        cur.close()
        conn.close()






# --- Update Campaign ---
@campaigns_bp.route("/campaigns/<int:campaign_id>", methods=["PUT"])
@require_auth
def update_campaign(campaign_id):
    try:
        data = request.json
        conn = get_db_connection()
        cur = conn.cursor()
        
        # First, check if campaign exists and is in draft status
        cur.execute("""
            SELECT c.id, COUNT(e.id) as recipients
            FROM campaigns c
            LEFT JOIN emails e ON c.id = e.campaign_id
            WHERE c.id = %s
            GROUP BY c.id
        """, (campaign_id,))
        
        campaign = cur.fetchone()
        if not campaign:
            return jsonify({"error": "Campaign not found"}), 404
            
        # Check if user owns this campaign
        is_owner, error_msg = validate_user_owns_campaign(campaign_id)
        if not is_owner:
            return jsonify({"error": error_msg}), 403
            
        if campaign[1] > 0:  # recipients > 0 means already sent
            return jsonify({"error": "Cannot edit sent campaigns"}), 400
        
        # Update campaign details
        cur.execute("""
            UPDATE campaigns 
            SET name = %s, subject = %s, description = %s
            WHERE id = %s
        """, (data['name'], data['subject'], data.get('description'), campaign_id))
        
        # Handle file association update if provided
        if 'file_id' in data and data['file_id']:
            # Remove existing file association
            cur.execute('DELETE FROM campaign_files WHERE campaign_id = %s', (campaign_id,))
            # Add new file association
            cur.execute('INSERT INTO campaign_files (campaign_id, file_id) VALUES (%s, %s)', 
                       (campaign_id, data['file_id']))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({"success": True, "message": "Campaign updated successfully"})
        
    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500
    

# --- Delete Campaign ---
@campaigns_bp.route("/campaigns/<int:campaign_id>", methods=["DELETE"])
@require_auth
def delete_campaign(campaign_id):
    # Check if user owns this campaign
    is_owner, error_msg = validate_user_owns_campaign(campaign_id)
    if not is_owner:
        return jsonify({"error": error_msg}), 403
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM campaigns WHERE id = %s RETURNING id', (campaign_id,))
    deleted = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if not deleted:
        return jsonify({"error": "Campaign not found"}), 404
    return jsonify({"success": True})

# --- Send Campaign ---
@campaigns_bp.route("/campaigns/<int:campaign_id>/send", methods=["POST"])
@require_auth
def send_campaign(campaign_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Check if user owns this campaign
        is_owner, error_msg = validate_user_owns_campaign(campaign_id)
        if not is_owner:
            return jsonify({"error": error_msg}), 403

        # Get campaign details
        cur.execute('SELECT subject, description FROM campaigns WHERE id = %s', (campaign_id,))
        campaign = cur.fetchone()
        if not campaign:
            return jsonify({"error": "Campaign not found"}), 404

        subject = campaign[0]
        body = campaign[1] or ""

        # Get associated file
        cur.execute('SELECT file_id FROM campaign_files WHERE campaign_id = %s', (campaign_id,))
        file_row = cur.fetchone()
        if not file_row:
            return jsonify({"error": "No file associated with this campaign"}), 400

        file_id = file_row[0]

        # Get file URL
        cur.execute('SELECT file_url FROM files WHERE id = %s', (file_id,))
        file_url_row = cur.fetchone()
        if not file_url_row:
            return jsonify({"error": "File not found"}), 404

        file_url = file_url_row[0]
        parsed = urlparse(file_url)
        bucket_name = os.environ['BUCKET_NAME']
        object_key = parsed.path.lstrip("/")

        # Download CSV from S3
        s3 = boto3.client(
            's3',
            aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
            region_name=os.environ['AWS_REGION']
        )

        presigned_url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': object_key},
            ExpiresIn=300
        )

        response = requests.get(presigned_url)
        if response.status_code != 200:
            return jsonify({"error": "Failed to download CSV file"}), 500

        subscribers = []
        decoded_content = response.content.decode('utf-8').splitlines()
        reader = csv.DictReader(decoded_content)
        for row in reader:
            if 'email' in row:
                subscribers.append(row['email'])

        if not subscribers:
            return jsonify({"error": "No subscribers found in CSV"}), 400

        # Get user's connected email account
        user_id = get_current_user_id()
        conn_email = get_db_connection()
        cur_email = conn_email.cursor()
        
        cur_email.execute("""
            SELECT email_address, provider_type, is_active
            FROM user_email_accounts 
            WHERE user_id = %s AND is_active = true
            ORDER BY created_at DESC
            LIMIT 1
        """, (user_id,))
        
        email_account = cur_email.fetchone()
        cur_email.close()
        conn_email.close()
        
        if not email_account:
            return jsonify({
                "error": "No email account connected. Please connect your email account first.",
                "connection_required": True
            }), 400
        
        sender_email = email_account[0]
        provider_type = email_account[1]
        
        # For now, we'll use SES for sending but with the user's connected email
        # In the future, we can implement SMTP sending using the user's OAuth tokens
        from auth.utils import check_email_verification_status
        ses = boto3.client('ses', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
        
        # Check if user's connected email is verified for sending
        user_email_verified = check_email_verification_status(ses, sender_email)
        
        if not user_email_verified:
            return jsonify({
                "error": f"Your connected email address ({sender_email}) is not verified for sending. Please verify your email address first.",
                "user_email": sender_email,
                "verification_required": True
            }), 400
        
        # Use user's connected email as sender
        sender = sender_email
        sent_count = 0
        failed = []

        for recipient in subscribers:
            try:
                # Generate a unique Message-ID using user's connected email domain
                user_domain = sender_email.split('@')[1] if '@' in sender_email else "charterglobal.com"
                msg_id = make_msgid(domain=user_domain)

                # Build the raw email message with improved headers for deliverability
                current_time = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
                
                # Add reply-to and list management headers to reduce spam classification
                reply_to = sender_email
                list_unsubscribe = f"<mailto:{sender_email}?subject=unsubscribe>"
                
                raw_message = (
                    "MIME-Version: 1.0\r\n"
                    f"From: {sender}\r\n"
                    f"To: {recipient}\r\n"
                    f"Reply-To: {reply_to}\r\n"
                    f"Subject: {subject}\r\n"
                    f"Message-ID: {msg_id}\r\n"
                    f"Date: {current_time}\r\n"
                    f"List-Unsubscribe: {list_unsubscribe}\r\n"
                    f"X-Mailer: EmailCampaign/1.0\r\n"
                    f"X-Priority: 3\r\n"
                    f"X-MSMail-Priority: Normal\r\n"
                    "Content-Type: text/plain; charset=UTF-8\r\n"
                    "Content-Transfer-Encoding: 8bit\r\n"
                    "\r\n"
                    f"{body}"
                )
                ses.send_raw_email(
                    Source=sender,
                    Destinations=[recipient],
                    RawMessage={'Data': raw_message.encode('utf-8')}
                )

                # Store the Message-ID in the emails table
                cur.execute(
                    'INSERT INTO emails (campaign_id, recipient_email, subject, body, created_at, message_id) VALUES (%s, %s, %s, %s, NOW(), %s)',
                    (campaign_id, recipient, subject, body, msg_id)
                )

                sent_count += 1
                
                # Add small delay to prevent spam filter triggers
                if sent_count % 10 == 0:  # Every 10 emails
                    import time
                    time.sleep(1)  # 1 second delay
                    
            except Exception as e:
                failed.append({"email": recipient, "error": str(e)})

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            "sent": sent_count,
            "failed": failed,
            "total": len(subscribers)
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


