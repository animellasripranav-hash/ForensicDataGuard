import os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from database import Database
from services import Service, AppError
from security import hash_password, verify_password, validate_username

PASSWORD='password1'
class CoreTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.db=Database(Path(self.tmp.name)/'test.db'); self.s=Service(self.db)
  self.admin_id=self.s.create_user('Admin User','admin.user','admin@example.com',PASSWORD,role='Administrator',status='Active'); self.admin=self.db.one('SELECT * FROM users WHERE user_id=?',(self.admin_id,))
 def tearDown(self): self.tmp.cleanup()
 def test_password_hash(self):
  value=hash_password(PASSWORD); self.assertNotIn(PASSWORD,value); self.assertTrue(verify_password(PASSWORD,value)); self.assertFalse(verify_password('wrong',value))
 def test_registration_uniqueness_and_approval(self):
  uid=self.s.create_user('Case Worker','worker.one','worker@example.com',PASSWORD); self.assertEqual(self.db.one('SELECT status FROM users WHERE user_id=?',(uid,))['status'],'Pending approval'); self.s.approve_user(self.admin,uid,'Investigator'); self.assertEqual(self.db.one('SELECT status FROM users WHERE user_id=?',(uid,))['status'],'Active')
  with self.assertRaises(AppError): self.s.create_user('Duplicate','WORKER.ONE','other@example.com',PASSWORD)
 def test_auth_and_case(self):
  user=self.s.authenticate('ADMIN.USER',PASSWORD); cid=self.s.create_case(user,'Test Case','REF-1','Description','High'); self.assertTrue(cid.startswith('CASE-'))
 def test_invalid_registration_is_friendly(self):
  with self.assertRaisesRegex(AppError,'at least 8 characters'):
     self.s.create_user('Bad Password','valid.user','valid@example.com','weak')
  with self.assertRaisesRegex(AppError,'one letter and one number'):
   self.s.create_user('No Number','valid.user2','valid2@example.com','password')
 def test_final_admin_protected(self):
  with self.assertRaises(AppError): self.s.set_user_status(self.admin,self.admin_id,'Disabled')
 def test_evidence_integrity(self):
  cid=self.s.create_case(self.admin,'Evidence Case'); p=Path(self.tmp.name)/'sample.bin'; p.write_bytes(b'forensic sample'); eid=self.s.add_evidence(self.admin,cid,p); self.assertEqual(self.s.verify_evidence(self.admin,eid),'Verified'); p.write_bytes(b'changed'); self.assertEqual(self.s.verify_evidence(self.admin,eid),'Mismatch')
if __name__=='__main__': unittest.main()
