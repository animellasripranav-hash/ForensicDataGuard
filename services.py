import hashlib, html, os, shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from database import utcnow
from security import *
from config import LOCKOUT_ATTEMPTS, LOCKOUT_MINUTES

class AppError(Exception): pass
class Service:
 def __init__(self,db): self.db=db
 def create_user(self,display,username,email,password,employee_id='',role='Investigator',status='Pending approval',actor=None):
  display=display.strip(); uid=new_user_id()
  try:
   username=validate_username(username); validate_password(password)
   email=validate_email(email) if email.strip() else f"{uid.casefold()}@local.invalid"
  except ValueError as e:
   raise AppError(str(e)) from e
  if not (2<=len(display)<=100): raise AppError('Display name must contain 2–100 characters.')
  if role not in ('Administrator','Investigator','Auditor'): raise AppError('Invalid role.')
  emp=employee_id.strip() or None
  try:
   self.db.execute('INSERT INTO users(user_id,display_name,username,username_norm,email,email_norm,employee_id,employee_id_norm,password_hash,role,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(uid,display,username,normalize_username(username),email,normalize_email(email),emp,emp.casefold() if emp else None,hash_password(password),role,status,utcnow()))
  except Exception as e:
   if 'UNIQUE' in str(e): raise AppError('Username, email, or employee ID is already registered.')
   raise AppError('The account could not be created safely.') from e
  self.db.audit(actor or {'user_id':uid,'username':username},'Account created','User',uid,'Success',status); return uid
 def authenticate(self,username,password):
  uname=normalize_username(username); user=self.db.one('SELECT * FROM users WHERE username_norm=?',(uname,))
  if not user: self.db.audit(None,'Sign in','User','', 'Failed','Invalid credentials'); raise AppError('Invalid username or password.')
  now=datetime.now(timezone.utc)
  if user['status']=='Locked' and user['locked_until']:
   try:
    if datetime.fromisoformat(user['locked_until'])<=now: self.db.execute("UPDATE users SET status='Active',failed_attempts=0,locked_until=NULL WHERE user_id=?",(user['user_id'],)); user['status']='Active'
   except ValueError: pass
  if user['status']!='Active': raise AppError(f"Account status: {user['status']}.")
  if not verify_password(password,user['password_hash']):
   attempts=user['failed_attempts']+1
   if attempts>=LOCKOUT_ATTEMPTS:
    until=(now+timedelta(minutes=LOCKOUT_MINUTES)).isoformat(timespec='seconds'); self.db.execute("UPDATE users SET status='Locked',failed_attempts=?,locked_until=? WHERE user_id=?",(attempts,until,user['user_id']))
    self.db.audit(user,'Account locked','User',user['user_id'],'Failed','Too many failed sign-ins'); raise AppError('Account locked after repeated failed sign-in attempts.')
   self.db.execute('UPDATE users SET failed_attempts=? WHERE user_id=?',(attempts,user['user_id'])); self.db.audit(user,'Sign in','User',user['user_id'],'Failed','Invalid credentials'); raise AppError('Invalid username or password.')
  self.db.execute('UPDATE users SET failed_attempts=0,locked_until=NULL,last_login=? WHERE user_id=?',(utcnow(),user['user_id'])); self.db.audit(user,'Sign in','User',user['user_id']); return self.db.one('SELECT * FROM users WHERE user_id=?',(user['user_id'],))
 def create_case(self,user,title,reference='',description='',priority='Normal'):
  title=title.strip();
  if not (2<=len(title)<=150): raise AppError('Case title must contain 2–150 characters.')
  cid=new_record_id('CASE'); now=utcnow(); self.db.execute('INSERT INTO cases(case_id,title,reference_no,description,priority,lead_user_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)',(cid,title,reference.strip() or None,description.strip()[:4000],priority,user['user_id'],user['user_id'],now,now)); self.db.audit(user,'Case created','Case',cid); return cid
 def add_evidence(self,user,case_id,path,name='',description=''):
  p=Path(path).expanduser().resolve()
  if not p.is_file(): raise AppError('Select an existing readable file.')
  try:
   size=p.stat().st_size; h=hashlib.sha256()
   with p.open('rb') as f:
    for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
  except OSError as e: raise AppError('The file could not be read.') from e
  eid=new_record_id('EVD'); self.db.execute('INSERT INTO evidence(evidence_id,case_id,name,description,source_path,size_bytes,sha256,added_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(eid,case_id,(name.strip() or p.name)[:200],description.strip()[:4000],str(p),size,h.hexdigest(),user['user_id'],utcnow())); self.db.audit(user,'Evidence registered','Evidence',eid,'Success',f'SHA-256 {h.hexdigest()}'); return eid
 def verify_evidence(self,user,eid):
  row=self.db.one('SELECT * FROM evidence WHERE evidence_id=?',(eid,));
  if not row: raise AppError('Evidence record was not found.')
  p=Path(row['source_path'])
  if not p.is_file(): status='Missing'; self.db.execute('UPDATE evidence SET integrity_status=?,last_verified_at=? WHERE evidence_id=?',(status,utcnow(),eid)); self.db.audit(user,'Evidence verified','Evidence',eid,'Failed',status); return status
  h=hashlib.sha256()
  try:
   with p.open('rb') as f:
    for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
  except OSError as e: raise AppError('Evidence could not be read for verification.') from e
  status='Verified' if h.hexdigest()==row['sha256'] else 'Mismatch'; self.db.execute('UPDATE evidence SET integrity_status=?,last_verified_at=? WHERE evidence_id=?',(status,utcnow(),eid)); self.db.audit(user,'Evidence verified','Evidence',eid,'Success' if status=='Verified' else 'Failed',status); return status
 def approve_user(self,admin,uid,role):
  if admin['role']!='Administrator': raise AppError('Administrator permission is required.')
  if role not in ('Investigator','Auditor'): raise AppError('Registration can only receive Investigator or Auditor role.')
  if not self.db.execute("UPDATE users SET status='Active',role=? WHERE user_id=? AND status='Pending approval'",(role,uid)): raise AppError('This registration is no longer pending.')
  self.db.audit(admin,'Registration approved','User',uid,'Success',role)
 def set_user_status(self,admin,uid,status):
  if admin['role']!='Administrator': raise AppError('Administrator permission is required.')
  if status not in ('Active','Locked','Disabled','Rejected'): raise AppError('Invalid account status.')
  target=self.db.one('SELECT * FROM users WHERE user_id=?',(uid,));
  if not target: raise AppError('User was not found.')
  if target['role']=='Administrator' and status!='Active':
   count=self.db.one("SELECT COUNT(*) n FROM users WHERE role='Administrator' AND status='Active'")['n']
   if count<=1: raise AppError('The final active Administrator cannot be disabled or locked.')
  self.db.execute('UPDATE users SET status=?,failed_attempts=0,locked_until=NULL WHERE user_id=?',(status,uid)); self.db.audit(admin,'Account status changed','User',uid,'Success',status)
 def export_case_html(self,user,case_id,destination):
  case=self.db.one('SELECT * FROM cases WHERE case_id=?',(case_id,)); ev=self.db.query('SELECT * FROM evidence WHERE case_id=? ORDER BY created_at',(case_id,))
  if not case: raise AppError('Case was not found.')
  rows=''.join(f"<tr><td>{html.escape(x['evidence_id'])}</td><td>{html.escape(x['name'])}</td><td><code>{html.escape(x['sha256'])}</code></td><td>{html.escape(x['integrity_status'])}</td></tr>" for x in ev) or '<tr><td colspan=4>No evidence registered.</td></tr>'
  doc=f'''<!doctype html><meta charset=utf-8><title>Case report</title><style>body{{font:15px Segoe UI,Arial;max-width:1100px;margin:48px;color:#18202a}}h1{{color:#12395c}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccd3da;padding:9px;text-align:left}}th{{background:#eaf2f8}}code{{font-size:11px;word-break:break-all}}</style><h1>Forensic Data Guard — Case Report</h1><p><b>Case ID:</b> {html.escape(case_id)}<br><b>Title:</b> {html.escape(case['title'])}<br><b>Status:</b> {html.escape(case['status'])}<br><b>Generated:</b> {html.escape(utcnow())}<br><b>Generated by:</b> {html.escape(user['username'])} ({html.escape(user['user_id'])})</p><h2>Evidence</h2><table><tr><th>ID</th><th>Name</th><th>SHA-256</th><th>Integrity</th></tr>{rows}</table>'''
  try: Path(destination).write_text(doc,encoding='utf-8')
  except OSError as e: raise AppError('The report destination is not writable.') from e
  self.db.audit(user,'Report exported','Case',case_id,'Success',str(destination)); return destination
 def export_operation_html(self,user,operation_id,destination):
  op=self.db.one('SELECT * FROM operations WHERE operation_id=?',(operation_id,)); files=self.db.query('SELECT * FROM recovered_files WHERE operation_id=? ORDER BY offset_start',(operation_id,))
  if not op:raise AppError('Operation was not found.')
  file_rows=''.join(f"<tr><td>{html.escape(x['recovery_id'])}</td><td>{html.escape(x['file_type'])}</td><td>{x['offset_start']}</td><td>{x['offset_end']}</td><td>{x['confidence']:.0%}</td><td><code>{html.escape(x['sha256'])}</code></td></tr>" for x in files) or '<tr><td colspan=6>No recovered-file records for this operation.</td></tr>'
  chain='Valid' if self.db.verify_audit_chain() else 'FAILED'
  doc=f'''<!doctype html><meta charset=utf-8><title>Forensic operation report</title><style>body{{font:15px Segoe UI,Arial;max-width:1200px;margin:48px;color:#18202a}}h1{{color:#12395c}}.ok{{color:#08783e}}.bad{{color:#b42318}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccd3da;padding:9px;text-align:left;vertical-align:top}}th{{background:#eaf2f8}}code{{font-size:10px;word-break:break-all}}</style><h1>Forensic Data Guard — Operation Report</h1><p><b>Operation ID:</b> {html.escape(operation_id)}<br><b>Type:</b> {html.escape(op['operation_type'])}<br><b>Target:</b> {html.escape(op['target'])}<br><b>Status:</b> {html.escape(op['status'])}<br><b>Method:</b> {html.escape(op['method'])}<br><b>Bytes processed:</b> {op['bytes_processed']}<br><b>Started:</b> {html.escape(op['started_at'])}<br><b>Completed:</b> {html.escape(op['completed_at'] or '')}<br><b>Result/source hash:</b> <code>{html.escape(op['result_hash'] or '')}</code><br><b>Details:</b> {html.escape(op['details'])}<br><b>Audit hash chain:</b> <span class="{'ok' if chain=='Valid' else 'bad'}">{chain}</span><br><b>Generated by:</b> {html.escape(user['username'])} ({html.escape(user['user_id'])}) at {html.escape(utcnow())}</p><h2>Recovered files</h2><table><tr><th>ID</th><th>Type</th><th>Start</th><th>End</th><th>Confidence</th><th>SHA-256</th></tr>{file_rows}</table>'''
  try:Path(destination).write_text(doc,encoding='utf-8')
  except OSError as e:raise AppError('The report destination is not writable.') from e
  self.db.audit(user,'Operation report exported','Operation',operation_id,'Success',str(destination)); return destination
