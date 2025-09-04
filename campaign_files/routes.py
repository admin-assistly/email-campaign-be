# campaign_files/routes.py
# Endpoints to associate uploaded files with campaigns

from flask import Blueprint, request, jsonify
from db.postgres import get_db_connection
from auth.middleware import require_auth

campaign_files_bp = Blueprint("campaign_files", __name__, url_prefix="/api")

# --- Link file to campaign ---
@campaign_files_bp.route("/campaign-files", methods=["POST"])
@require_auth
def create_campaign_file():
    try:
        data = request.json
        campaign_id = data.get('campaign_id')
        file_id = data.get('file_id')
        
        if not campaign_id or not file_id:
            return jsonify({'error': 'Missing campaign_id or file_id'}), 400

        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if campaign exists
        cur.execute("SELECT id FROM campaigns WHERE id = %s", (campaign_id,))
        if not cur.fetchone():
            return jsonify({'error': f'Campaign {campaign_id} not found'}), 404
        
        # Check if file exists
        cur.execute("SELECT id FROM files WHERE id = %s", (file_id,))
        if not cur.fetchone():
            return jsonify({'error': f'File {file_id} not found'}), 404
        
        # Insert the association
        cur.execute(
            '''
            INSERT INTO campaign_files (campaign_id, file_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
            RETURNING id
            ''',
            (campaign_id, file_id)
        )
        link_id = cur.fetchone()[0] if cur.rowcount > 0 else None
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'id': link_id, 'campaign_id': campaign_id, 'file_id': file_id})
        
    except Exception as e:
        print(f"Error in create_campaign_file: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

# --- Get all campaign-file links ---
@campaign_files_bp.route("/campaign-files", methods=["GET"])
@require_auth
def get_campaign_files():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT id, campaign_id, file_id FROM campaign_files')
        campaign_files = [
            {"id": row[0], "campaign_id": row[1], "file_id": row[2]}
            for row in cur.fetchall()
        ]
        cur.close()
        conn.close()
        return jsonify(campaign_files)
    except Exception as e:
        print(f"Error in get_campaign_files: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500
