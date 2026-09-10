import hashlib, json, sqlite3, threading
from contextlib import contextmanager
from datetime import datetime, timezone
from config import DATA_DIR, DB_PATH, EVIDENCE_DIR, LOG_PATH

SCHEMA='''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(
 user_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, username TEXT NOT NULL,
 username_norm TEXT NOT NULL UNIQUE, email TEXT NOT NULL, email_norm TEXT NOT NULL UNIQUE,
 employee_id TEXT, employee_id_norm TEXT UNIQUE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('Administrator','Investigator','Auditor')),
 status TEXT NOT NULL CHECK(status IN ('Pending approval','Active','Locked','Disabled','Rejected')),
 failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT, must_change_password INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, last_login TEXT);
CREATE TABLE IF NOT EXISTS cases(
 case_id TEXT PRIMARY KEY, title TEXT NOT NULL, reference_no TEXT, description TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'Open', priority TEXT NOT NULL DEFAULT 'Normal', lead_user_id TEXT,
 created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 FOREIGN KEY(lead_user_id) REFERENCES users(user_id), FOREIGN KEY(created_by) REFERENCES users(user_id));
CREATE TABLE IF NOT EXISTS evidence(
 evidence_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 source_path TEXT NOT NULL, size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL,
 integrity_status TEXT NOT NULL DEFAULT 'Not verified', added_by TEXT NOT NULL,
 created_at TEXT NOT NULL, last_verified_at TEXT,
 FOREIGN KEY(case_id) REFERENCES cases(case_id), FOREIGN KEY(added_by) REFERENCES users(user_id));
CREATE TABLE IF NOT EXISTS audit(
 event_id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, user_id TEXT, username TEXT,
 action TEXT NOT NULL, target_type TEXT, target_id TEXT, outcome TEXT NOT NULL, details TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS operations(
 operation_id TEXT PRIMARY KEY, operation_type TEXT NOT NULL, target TEXT NOT NULL,
 status TEXT NOT NULL, method TEXT NOT NULL, bytes_processed INTEGER NOT NULL DEFAULT 0,
 result_hash TEXT, confidence REAL, initiated_by TEXT NOT NULL, started_at TEXT NOT NULL,
 completed_at TEXT, details TEXT NOT NULL DEFAULT '', FOREIGN KEY(initiated_by) REFERENCES users(user_id));
CREATE TABLE IF NOT EXISTS recovered_files(
 recovery_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL, file_type TEXT NOT NULL,
 output_path TEXT NOT NULL, offset_start INTEGER NOT NULL, offset_end INTEGER NOT NULL,
 sha256 TEXT NOT NULL, confidence REAL NOT NULL, validation TEXT NOT NULL,
 FOREIGN KEY(operation_id) REFERENCES operations(operation_id));
CREATE TABLE IF NOT EXISTS audit_seals(
 event_id INTEGER PRIMARY KEY, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE,
 FOREIGN KEY(event_id) REFERENCES audit(event_id));
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
'''

def utcnow(): return datetime.now(timezone.utc).isoformat(timespec='seconds')

class Database:
 def __init__(self,path=DB_PATH):
  self.path=path; self._lock=threading.RLock(); DATA_DIR.mkdir(parents=True,exist_ok=True); EVIDENCE_DIR.mkdir(parents=True,exist_ok=True); LOG_PATH.parent.mkdir(parents=True,exist_ok=True)
  with self.connect() as c:
   c.execute('PRAGMA journal_mode=WAL'); c.execute('PRAGMA synchronous=NORMAL'); c.execute('PRAGMA temp_store=MEMORY'); c.execute('PRAGMA cache_size=-8192'); c.executescript(SCHEMA)
   seal_count=c.execute('SELECT COUNT(*) FROM audit_seals').fetchone()[0]; audit_count=c.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
   if seal_count==0 and audit_count:
    previous='GENESIS'
    for r in c.execute('SELECT * FROM audit ORDER BY event_id').fetchall():
     payload=json.dumps([r['event_id'],r['timestamp'],r['user_id'],r['username'],r['action'],r['target_type'],r['target_id'],r['outcome'],r['details'],previous],separators=(',',':'),ensure_ascii=False)
     event_hash=hashlib.sha256(payload.encode('utf-8')).hexdigest(); c.execute('INSERT INTO audit_seals(event_id,previous_hash,event_hash) VALUES(?,?,?)',(r['event_id'],previous,event_hash)); previous=event_hash
 @contextmanager
 def connect(self):
  con=sqlite3.connect(self.path,timeout=15); con.row_factory=sqlite3.Row; con.execute('PRAGMA foreign_keys=ON'); con.execute('PRAGMA busy_timeout=15000')
  try: yield con; con.commit()
  except Exception: con.rollback(); raise
  finally: con.close()
 def query(self,sql,params=()):
  with self.connect() as c: return [dict(r) for r in c.execute(sql,params).fetchall()]
 def one(self,sql,params=()):
  with self.connect() as c:
   row=c.execute(sql,params).fetchone(); return dict(row) if row else None
 def execute(self,sql,params=()):
  with self._lock:
   with self.connect() as c: return c.execute(sql,params).rowcount
 def audit(self,user,action,target_type='',target_id='',outcome='Success',details=''):
  uid=user.get('user_id') if user else None; uname=user.get('username') if user else None; timestamp=utcnow(); safe_details=str(details)[:1000]
  with self._lock:
   with self.connect() as c:
    previous=c.execute('SELECT event_hash FROM audit_seals ORDER BY event_id DESC LIMIT 1').fetchone(); previous_hash=previous[0] if previous else 'GENESIS'
    cur=c.execute('INSERT INTO audit(timestamp,user_id,username,action,target_type,target_id,outcome,details) VALUES(?,?,?,?,?,?,?,?)',(timestamp,uid,uname,action,target_type,target_id,outcome,safe_details)); event_id=cur.lastrowid
    payload=json.dumps([event_id,timestamp,uid,uname,action,target_type,target_id,outcome,safe_details,previous_hash],separators=(',',':'),ensure_ascii=False)
    event_hash=hashlib.sha256(payload.encode('utf-8')).hexdigest(); c.execute('INSERT INTO audit_seals(event_id,previous_hash,event_hash) VALUES(?,?,?)',(event_id,previous_hash,event_hash))
  return event_id
 def verify_audit_chain(self):
  rows=self.query('SELECT a.*,s.previous_hash,s.event_hash FROM audit a JOIN audit_seals s ON a.event_id=s.event_id ORDER BY a.event_id')
  previous='GENESIS'
  for r in rows:
   payload=json.dumps([r['event_id'],r['timestamp'],r['user_id'],r['username'],r['action'],r['target_type'],r['target_id'],r['outcome'],r['details'],previous],separators=(',',':'),ensure_ascii=False)
   expected=hashlib.sha256(payload.encode('utf-8')).hexdigest()
   if r['previous_hash']!=previous or r['event_hash']!=expected:return False
   previous=r['event_hash']
  return True
 def has_users(self): return bool(self.one('SELECT user_id FROM users LIMIT 1'))
