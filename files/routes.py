# files/routes.py
# File upload, retrieval, presigned URL generation, and deletion
# Moved from original app.py: /api/upload-file, /api/files, /api/files/<id>/presigned-url, /api/files/<id> DELETE

import os
import boto3
from flask import Blueprint, request, jsonify, session
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from db.postgres import get_db_connection

files_bp = Blueprint("files", __name__, url_prefix="/api")

# --- Upload File ---
@files_bp.route("/upload-file", methods=["POST"])
def upload_file():
    # Check if user is authenticated
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    user_id = session['user_id']
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    filename = secure_filename(file.filename)
    s3 = boto3.client(
        's3',
        aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
        aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
        region_name=os.environ['AWS_REGION']
    )
    bucket = os.environ['BUCKET_NAME']

    # Upload to S3
    s3.upload_fileobj(file, bucket, filename, ExtraArgs={'ContentType': file.content_type})
    file_url = f"https://{bucket}.s3.{os.environ['AWS_REGION']}.amazonaws.com/{filename}"

    # Save metadata in DB with dynamic user_id
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO files (filename, uploaded_by, uploaded_at, file_url) VALUES (%s, %s, NOW(), %s) RETURNING id',
        (filename, user_id, file_url)
    )
    file_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'id': file_id, 'file_url': file_url, 'filename': filename})

# --- List All Files ---
@files_bp.route("/files", methods=["GET"])
def get_files():
    # Check if user is authenticated
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    user_id = session['user_id']
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Get query parameter to determine if user wants all files or just their own
    show_all = request.args.get('all', 'false').lower() == 'true'
    
    if show_all:
        # Admin functionality - show all files (you might want to add admin check here)
        cur.execute('SELECT id, filename, uploaded_by, uploaded_at, file_url FROM files ORDER BY uploaded_at DESC')
    else:
        # Show only user's own files
        cur.execute('SELECT id, filename, uploaded_by, uploaded_at, file_url FROM files WHERE uploaded_by = %s ORDER BY uploaded_at DESC', (user_id,))
    
    files = [
        {
            "id": row[0],
            "filename": row[1],
            "uploaded_by": row[2],
            "uploaded_at": row[3],
            "file_url": row[4]
        }
        for row in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return jsonify(files)

# --- Generate Presigned URL ---
@files_bp.route("/files/<int:file_id>/presigned-url", methods=["GET"])
def get_presigned_url(file_id):
    # Check if user is authenticated
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    user_id = session['user_id']
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if file exists and user has access to it
        cur.execute('SELECT file_url, uploaded_by FROM files WHERE id = %s', (file_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            return jsonify({'error': 'File not found'}), 404
        
        # Check if user owns the file (you might want to add admin check here)
        if row[1] != user_id:
            return jsonify({'error': 'Unauthorized to access this file'}), 403

        file_url = row[0]
        parsed = urlparse(file_url)
        bucket = os.environ['BUCKET_NAME']
        object_key = parsed.path.lstrip(f"/{bucket}/")

        s3 = boto3.client(
            's3',
            aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
            region_name=os.environ['AWS_REGION']
        )

        presigned_url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket, 'Key': object_key},
            ExpiresIn=300
        )

        return jsonify({'presigned_url': presigned_url})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Failed to generate presigned URL', 'details': str(e)}), 500

# --- Delete File ---
@files_bp.route("/files/<int:file_id>", methods=["DELETE"])
def delete_file(file_id):
    # Check if user is authenticated
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    user_id = session['user_id']
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # First check if file exists and belongs to user (or user is admin)
    cur.execute('SELECT id, uploaded_by FROM files WHERE id = %s', (file_id,))
    file_data = cur.fetchone()
    
    if not file_data:
        cur.close()
        conn.close()
        return jsonify({"error": "File not found"}), 404
    
    # Check if user owns the file (you might want to add admin check here)
    if file_data[1] != user_id:
        cur.close()
        conn.close()
        return jsonify({"error": "Unauthorized to delete this file"}), 403
    
    # Delete the file
    cur.execute('DELETE FROM files WHERE id = %s RETURNING id', (file_id,))
    deleted = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    
    if not deleted:
        return jsonify({"error": "File not found"}), 404
    return jsonify({"success": True})
