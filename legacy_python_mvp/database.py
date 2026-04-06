import sqlite3
import hashlib
import time
import json
import os

DB_FILE = "proof_of_work.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS file_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                file_path TEXT NOT NULL,
                content_diff TEXT NOT NULL,
                current_hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                signature TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS session_credentials (
                vc_id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                project_context TEXT NOT NULL,
                ai_insight TEXT NOT NULL,
                skill_tags TEXT NOT NULL,
                file_paths TEXT NOT NULL,
                full_vc_json TEXT NOT NULL,
                status INTEGER DEFAULT 1
            )
        ''')
        
        # Phase 3.5: Add status column for soft-delete/revocation if it doesn't exist
        try:
            conn.execute('ALTER TABLE session_credentials ADD COLUMN status INTEGER DEFAULT 1')
        except sqlite3.OperationalError:
            pass # Column already exists

def get_latest_hash() -> str:
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.execute('SELECT current_hash FROM file_snapshots ORDER BY id DESC LIMIT 1')
        row = cursor.fetchone()
        return row[0] if row else "0" * 64

def commit_snapshot(file_path: str, content_diff: str, signature: str = "") -> str:
    timestamp = time.time()
    previous_hash = get_latest_hash()
    
    # Cryptographic Iron Rule: hash(timestamp + content_diff + previous_hash)
    raw_data = f"{timestamp}{content_diff}{previous_hash}".encode('utf-8')
    current_hash = hashlib.sha256(raw_data).hexdigest()
    
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            INSERT INTO file_snapshots 
            (timestamp, file_path, content_diff, current_hash, previous_hash, signature)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, file_path, content_diff, current_hash, previous_hash, signature))
        
    print(f"[OK] Chain Updated | Hash: {current_hash[:16]}... | Prev: {previous_hash[:8]}...")
    return current_hash

def commit_credential(vc_dict: dict) -> None:
    vc_id = vc_dict.get("credentialSubject", {}).get("id", "")
    timestamp = vc_dict.get("issuanceDate", time.time())
    
    file_paths = vc_dict.get("credentialSubject", {}).get("proofOfWork", {}).get("filePaths", [])
    project_context = "/"
    if file_paths:
        project_context = os.path.dirname(file_paths[0]) or "/"
        
    ai_evaluation = vc_dict.get("credentialSubject", {}).get("proofOfWork", {}).get("aiEvaluation", "")
    
    insight = ai_evaluation
    skills = []
    
    if "[WORKLOAD AUDIT]" in ai_evaluation and "[VERIFIED SKILL TAGS]" in ai_evaluation:
        parts = ai_evaluation.split("[VERIFIED SKILL TAGS]")
        insight = parts[0].replace("[WORKLOAD AUDIT]", "").strip()
        skills_text = parts[1].strip()
        skills = [line.strip().strip("* ") for line in skills_text.split("\\n") if line.strip().startswith("*")]
        
    ai_insight = insight
    skill_tags = ", ".join(skills)
    file_paths_json = json.dumps(file_paths)
    full_vc_json = json.dumps(vc_dict)
    
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            INSERT OR REPLACE INTO session_credentials 
            (vc_id, timestamp, project_context, ai_insight, skill_tags, file_paths, full_vc_json, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        ''', (vc_id, timestamp, project_context, ai_insight, skill_tags, file_paths_json, full_vc_json))
        
    print(f"[OK] Credential Archived | VC ID: {vc_id}")

def burn_credential(vc_id: str) -> bool:
    """Phase 3.5: Soft-delete a credential by setting its status to 0."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute('UPDATE session_credentials SET status = 0 WHERE vc_id = ?', (vc_id,))
        print(f"[OK] Credential Incinerated | VC ID: {vc_id}")
        return True
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to burn credential: {e}")
        return False

if __name__ == "__main__":
    init_db()
