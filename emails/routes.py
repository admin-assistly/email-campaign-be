from flask import Blueprint, jsonify, request
from db.postgres import get_db_connection

emails_bp = Blueprint("emails", __name__, url_prefix="/api")

# GET /api/emails  
@emails_bp.route("/emails", methods=["GET"])
def get_emails():
    message_id = request.args.get("message_id")
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        if message_id:
            cur.execute("""
                SELECT id, campaign_id, recipient_email, subject, body, created_at, message_id
                FROM emails
                WHERE REPLACE(REPLACE(message_id,'<',''),'>','') = REPLACE(REPLACE(%s,'<',''),'>','')
                ORDER BY created_at DESC
            """, (message_id,))
        else:
            cur.execute("""
                SELECT id, campaign_id, recipient_email, subject, body, created_at, message_id
                FROM emails
                ORDER BY created_at DESC
            """)
        emails = [
            {
                "id": row[0],
                "campaign_id": row[1],
                "recipient_email": row[2],
                "subject": row[3],
                "body": row[4],
                "created_at": row[5],
                "message_id": row[6],
            }
            for row in cur.fetchall()
        ]
        return jsonify(emails)
    finally:
        cur.close()
        conn.close()


# GET /api/emails/<int:email_id>  
@emails_bp.route("/emails/<int:email_id>", methods=["GET"])
def get_email_by_id(email_id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('''
            SELECT id, campaign_id, recipient_email, subject, body, created_at, message_id 
            FROM emails 
            WHERE id = %s
        ''', (email_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Email not found"}), 404

        email = {
            "id": row[0],
            "campaign_id": row[1],
            "recipient_email": row[2],
            "subject": row[3],
            "body": row[4],
            "created_at": row[5],
            "message_id": row[6]
        }
        return jsonify(email)
    except Exception as e:
        print("Error fetching email:", e)
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()

# POST /api/emails  
@emails_bp.route("/emails", methods=["POST"])
def create_email():
    data = request.json
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            'INSERT INTO emails (campaign_id, recipient_email, subject, body, created_at) VALUES (%s, %s, %s, %s, NOW()) RETURNING id',
            (data['campaign_id'], data['recipient_email'], data['subject'], data['body'])
        )
        email_id = cur.fetchone()[0]
        conn.commit()
        return jsonify({"id": email_id}), 201
    except Exception as e:
        print("Error inserting email:", e)
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()
