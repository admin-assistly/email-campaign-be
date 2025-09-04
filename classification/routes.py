# classification/routes.py
# Classification endpoints
# Moved from original app.py: /api/responses/<id>/classify, /api/metrics/classifications, /api/metrics/campaign-performance

from flask import Blueprint, request, jsonify
from db.postgres import get_db_connection
from classification.services import call_ai_classifier

classification_bp = Blueprint("classification", __name__, url_prefix="/api")

# --- Classify a Response ---
@classification_bp.route("/responses/<int:response_id>/classify", methods=["POST"])
def classify_response(response_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Get response data
        cur.execute("""
            SELECT r.id, r.body, r.responder_email, e.subject, e.campaign_id
            FROM responses r
            JOIN emails e ON r.email_id = e.id
            WHERE r.id = %s
        """, (response_id,))
        response_data = cur.fetchone()
        if not response_data:
            return jsonify({"error": "Response not found"}), 404

        # Check if already classified
        cur.execute("""
            SELECT classification FROM responses 
            WHERE id = %s AND classification IS NOT NULL
        """, (response_id,))
        if cur.fetchone():
            return jsonify({"error": "Response already classified"}), 400

        # Prepare data for AI classifier
        email_data = {
            "subject": response_data[3],
            "sender": response_data[2],
            "body": response_data[1],
            "campaign_id": response_data[4]
        }

        classification = call_ai_classifier(email_data)

        if classification:
            cur.execute("""
                UPDATE responses 
                SET classification = %s
                WHERE id = %s
            """, (classification, response_id))
            conn.commit()

            print(f"[DEBUG] Successfully classified response {response_id} as: {classification}")

            return jsonify({
                "id": response_id,
                "classification": classification
            })
        else:
            print(f"[ERROR] Classification failed for response {response_id}")
            return jsonify({"error": "Classification failed"}), 500

    except Exception as e:
        print(f"[ERROR] Error in classification endpoint: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()

# --- Classification Metrics ---
@classification_bp.route("/metrics/classifications", methods=["GET"])
def get_classification_metrics():
    try:
        campaign_id = request.args.get('campaign_id')
        conn = get_db_connection()
        cur = conn.cursor()

        if campaign_id:
            cur.execute("""
                SELECT 
                    r.classification,
                    COUNT(*) as count
                FROM responses r
                JOIN emails e ON r.email_id = e.id
                WHERE e.campaign_id = %s AND r.classification IS NOT NULL
                GROUP BY r.classification
            """, (campaign_id,))
        else:
            cur.execute("""
                SELECT 
                    r.classification,
                    COUNT(*) as count
                FROM responses r
                WHERE r.classification IS NOT NULL
                GROUP BY r.classification
            """)

        results = cur.fetchall()
        metrics = {
            "interested": 0,
            "not_interested": 0,
            "interested_later": 0,
            "request_info": 0,
            "out_of_office": 0,
            "unsubscribe": 0,
            "spam_complaint": 0,
            "other": 0
        }

        for classification, count in results:
            if classification in metrics:
                metrics[classification] = count
            else:
                metrics["other"] += count

        cur.close()
        conn.close()
        return jsonify(metrics)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Campaign Performance Metrics ---
@classification_bp.route("/metrics/campaign-performance", methods=["GET"])
def get_campaign_performance():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT 
                c.id,
                c.name,
                COUNT(e.id) as emails_sent,
                COUNT(r.id) as responses_received,
                COUNT(CASE WHEN r.classification = 'interested' THEN 1 END) as interested,
                COUNT(CASE WHEN r.classification = 'not_interested' THEN 1 END) as not_interested,
                COUNT(CASE WHEN r.classification = 'interested_later' THEN 1 END) as interested_later,
                COUNT(CASE WHEN r.classification IS NOT NULL THEN 1 END) as classified
            FROM campaigns c
            LEFT JOIN emails e ON c.id = e.campaign_id
            LEFT JOIN responses r ON e.id = r.email_id
            GROUP BY c.id, c.name
            ORDER BY c.created_at DESC
        """)

        results = cur.fetchall()
        campaigns = []

        for row in results:
            campaign = {
                "id": row[0],
                "name": row[1],
                "emails_sent": row[2],
                "responses_received": row[3],
                "response_rate": round((row[3] / row[2] * 100), 1) if row[2] > 0 else 0,
                "interested": row[4],
                "not_interested": row[5],
                "interested_later": row[6],
                "classified": row[7]
            }
            campaigns.append(campaign)

        cur.close()
        conn.close()
        return jsonify(campaigns)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
