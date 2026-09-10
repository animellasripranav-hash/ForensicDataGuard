import sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from database import Database
from services import Service
from sanitization import erase_paths
from recovery import carve_image

PASSWORD='password1'
class ForensicModuleTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name); self.db=Database(self.root/'test.db'); self.s=Service(self.db)
  uid=self.s.create_user('Admin User','forensic.admin','admin@example.com',PASSWORD,role='Administrator',status='Active'); self.user=self.db.one('SELECT * FROM users WHERE user_id=?',(uid,))
 def tearDown(self):self.tmp.cleanup()
 def test_file_erasure_and_operation_record(self):
  target=self.root/'erase-me.bin'; target.write_bytes(b'sensitive-data'*1000); op=erase_paths(self.db,self.user,[target],'NIST Clear'); self.assertFalse(target.exists()); self.assertEqual(self.db.one('SELECT status FROM operations WHERE operation_id=?',(op,))['status'],'Completed')
 def test_signature_carving_classification_and_hash(self):
  image=self.root/'sample.img'; jpeg=b'\xff\xd8\xff'+b'A'*128+b'\xff\xd9'; pdf=b'%PDF-1.7\nhello\n%%EOF'; image.write_bytes(b'noise'*20+jpeg+b'gap'*20+pdf+b'end'); out=self.root/'recovered'; op,files,manifest=carve_image(self.db,self.user,image,out); self.assertEqual(len(files),2); self.assertEqual({x['type'] for x in files},{'JPEG','PDF'}); self.assertTrue(Path(manifest).exists()); self.assertTrue(all(Path(x['path']).exists() for x in files)); self.assertEqual(self.db.one('SELECT status FROM operations WHERE operation_id=?',(op,))['status'],'Completed')
 def test_audit_hash_chain_detects_change(self):
  self.db.audit(self.user,'Test event','Test','1'); self.assertTrue(self.db.verify_audit_chain()); event=self.db.one('SELECT MAX(event_id) event_id FROM audit')['event_id']; self.db.execute('UPDATE audit SET details=? WHERE event_id=?',('tampered',event)); self.assertFalse(self.db.verify_audit_chain())
 def test_operation_report(self):
  image=self.root/'one.img'; image.write_bytes(b'%PDF-1.4\nvalue\n%%EOF'); op,_,_=carve_image(self.db,self.user,image,self.root/'out'); report=self.root/'operation.html'; self.s.export_operation_html(self.user,op,report); text=report.read_text(encoding='utf-8'); self.assertIn(op,text); self.assertIn('Audit hash chain',text)
if __name__=='__main__':unittest.main()
