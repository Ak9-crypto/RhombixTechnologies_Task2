
---

### 🖥️ `server/app.py`
```python
from flask import Flask, request, jsonify, send_file
import os, uuid, sqlite3, datetime

UPLOAD_DIR = 'storage'
os.makedirs(UPLOAD_DIR, exist_ok=True)
DB = 'server.db'
app = Flask(__name__)

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (file_id TEXT PRIMARY KEY, owner_id TEXT, recipient_id TEXT,
                  filename TEXT, path TEXT, sha256 TEXT, uploaded_at TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, file_id TEXT, action TEXT,
                  user_id TEXT, ts TEXT, ip TEXT, note TEXT)''')
    conn.commit(); conn.close()

def log_audit(file_id, action, user_id, ip, note=''):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('INSERT INTO audit (file_id, action, user_id, ts, ip, note) VALUES (?,?,?,?,?,?)',
              (file_id, action, user_id, datetime.datetime.utcnow().isoformat(), ip, note))
    conn.commit(); conn.close()

@app.route('/upload', methods=['POST'])
def upload():
    user_id = request.headers.get('X-User') or 'anonymous'
    recipient_id = request.form.get('recipient_id')
    filename = request.form.get('filename')
    sha256 = request.form.get('sha256')

    ciphertext = request.files.get('ciphertext')
    encrypted_key = request.form.get('encrypted_key')
    nonce = request.form.get('nonce')
    tag = request.form.get('tag')

    if not (ciphertext and encrypted_key and recipient_id):
        return jsonify({'error': 'missing fields'}), 400

    file_id = str(uuid.uuid4())
    path = os.path.join(UPLOAD_DIR, file_id + '.blob')
    ciphertext.save(path)

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('INSERT INTO files VALUES (?,?,?,?,?,?,?)',
              (file_id, user_id, recipient_id, filename, path, sha256, datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()

    meta_path = path + '.meta'
    with open(meta_path, 'w') as f:
        f.write(f'encrypted_key:{encrypted_key}\nnonce:{nonce}\ntag:{tag}\n')

    log_audit(file_id, 'upload', user_id, request.remote_addr, note=f'Uploaded for {recipient_id}')
    return jsonify({'file_id': file_id}), 201

@app.route('/download/<file_id>', methods=['GET'])
def download(file_id):
    user_id = request.headers.get('X-User') or 'anonymous'
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('SELECT owner_id, recipient_id, filename, path, sha256 FROM files WHERE file_id=?', (file_id,))
    row = c.fetchone(); conn.close()

    if not row: return jsonify({'error': 'not found'}), 404
    owner_id, recipient_id, filename, path, sha256 = row
    if user_id not in (owner_id, recipient_id):
        log_audit(file_id, 'unauthorized_download_attempt', user_id, request.remote_addr)
        return jsonify({'error': 'access denied'}), 403

    meta_path = path + '.meta'
    encrypted_key = nonce = tag = None
    with open(meta_path, 'r') as f:
        for line in f:
            if line.startswith('encrypted_key:'): encrypted_key = line.split(':',1)[1].strip()
            if line.startswith('nonce:'): nonce = line.split(':',1)[1].strip()
            if line.startswith('tag:'): tag = line.split(':',1)[1].strip()

    log_audit(file_id, 'download', user_id, request.remote_addr)
    return jsonify({
        'filename': filename,
        'sha256': sha256,
        'encrypted_key': encrypted_key,
        'nonce': nonce,
        'tag': tag,
        'download_url': f'/download_blob/{file_id}'
    })

@app.route('/download_blob/<file_id>', methods=['GET'])
def download_blob(file_id):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('SELECT path FROM files WHERE file_id=?', (file_id,))
    row = c.fetchone(); conn.close()
    if not row: return jsonify({'error': 'not found'}), 404
    path = row[0]
    return send_file(path, as_attachment=True)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
