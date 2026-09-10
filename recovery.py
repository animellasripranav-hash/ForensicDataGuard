"""Read-only contiguous signature carving for disk images and binary media captures."""
import hashlib, mmap, os
from pathlib import Path
from database import utcnow
from security import new_record_id
from services import AppError

SIGNATURES=[
 ('JPEG',b'\xff\xd8\xff',b'\xff\xd9','jpg',100*1024*1024),
 ('PNG',b'\x89PNG\r\n\x1a\n',b'IEND\xaeB`\x82','png',100*1024*1024),
 ('PDF',b'%PDF-',b'%%EOF','pdf',250*1024*1024),
 ('ZIP/DOCX/XLSX',b'PK\x03\x04',b'PK\x05\x06','zip',500*1024*1024),
 ('GIF',b'GIF8',b'\x00;','gif',100*1024*1024),
]

def sha256_file(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for chunk in iter(lambda:f.read(4*1024*1024),b''):h.update(chunk)
 return h.hexdigest()

def _validate(kind,data):
 if kind=='JPEG':ok=data.startswith(b'\xff\xd8\xff') and data.endswith(b'\xff\xd9')
 elif kind=='PNG':ok=data.startswith(b'\x89PNG') and data.endswith(b'IEND\xaeB`\x82')
 elif kind=='PDF':ok=data.startswith(b'%PDF-') and b'%%EOF' in data[-2048:]
 elif kind=='ZIP/DOCX/XLSX':ok=data.startswith(b'PK\x03\x04') and b'PK\x05\x06' in data[-65558:]
 elif kind=='GIF':ok=data[:6] in (b'GIF87a',b'GIF89a') and data.endswith(b';')
 else:ok=False
 return ('Structure markers validated',0.95) if ok else ('Signature match only',0.60)

def carve_image(db,user,source,destination,progress=None,max_results=500):
 src=Path(source).expanduser().resolve(strict=True); out=Path(destination).expanduser().resolve()
 if not src.is_file():raise AppError('Select a readable disk image or binary media capture.')
 if src==out or src in out.parents:raise AppError('Recovery output must be separate from the source image.')
 out.mkdir(parents=True,exist_ok=True); size=src.stat().st_size; source_mtime=src.stat().st_mtime_ns; source_hash=sha256_file(src)
 op_id=new_record_id('RECOVER'); db.execute('INSERT INTO operations(operation_id,operation_type,target,status,method,initiated_by,started_at,details) VALUES(?,?,?,?,?,?,?,?)',(op_id,'File Carving and Recovery',str(src),'Running','Signature and structure carving',user['user_id'],utcnow(),f'Source SHA-256 {source_hash}'))
 recovered=[]
 try:
  if size==0:raise AppError('The selected source is empty.')
  with src.open('rb') as f, mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mm:
   candidates=[]
   for kind,start,end,ext,limit in SIGNATURES:
    pos=0
    while len(candidates)<max_results:
     pos=mm.find(start,pos)
     if pos<0:break
     end_pos=mm.find(end,pos+len(start),min(size,pos+limit))
     if end_pos>=0:candidates.append((pos,end_pos+len(end),kind,ext))
     pos+=len(start)
   candidates=sorted(set(candidates),key=lambda x:x[0])[:max_results]
   for i,(start,end,kind,ext) in enumerate(candidates,1):
    data=mm[start:end]; validation,confidence=_validate(kind,data); rid=new_record_id('FILE'); path=out/f'{rid}_{start:016X}.{ext}'; path.write_bytes(data); digest=hashlib.sha256(data).hexdigest()
    db.execute('INSERT INTO recovered_files(recovery_id,operation_id,file_type,output_path,offset_start,offset_end,sha256,confidence,validation) VALUES(?,?,?,?,?,?,?,?,?)',(rid,op_id,kind,str(path),start,end,digest,confidence,validation)); recovered.append({'id':rid,'type':kind,'path':str(path),'offset':start,'size':len(data),'sha256':digest,'confidence':confidence,'validation':validation})
    if progress:progress(i,len(candidates),f'Recovered {kind} at offset {start}')
  if src.stat().st_size!=size or src.stat().st_mtime_ns!=source_mtime:raise AppError('The source changed during recovery; results were not finalized.')
  manifest=out/f'{op_id}-manifest.txt'; lines=[f'Operation: {op_id}',f'Source: {src}',f'Source SHA-256: {source_hash}',f'Recovered files: {len(recovered)}','']+[f"{x['id']} | {x['type']} | offset {x['offset']} | size {x['size']} | confidence {x['confidence']:.0%} | {x['sha256']}" for x in recovered]; manifest.write_text('\n'.join(lines),encoding='utf-8')
  db.execute("UPDATE operations SET status='Completed',bytes_processed=?,result_hash=?,confidence=?,completed_at=?,details=? WHERE operation_id=?",(size,source_hash,(sum(x['confidence'] for x in recovered)/len(recovered) if recovered else 0),utcnow(),f'{len(recovered)} files; manifest {manifest}',op_id)); db.audit(user,'File carving completed','Operation',op_id,'Success',f'{len(recovered)} files; source SHA-256 {source_hash}'); return op_id,recovered,str(manifest)
 except Exception as e:
  db.execute("UPDATE operations SET status='Failed',completed_at=?,details=? WHERE operation_id=?",(utcnow(),str(e)[:1000],op_id)); db.audit(user,'File carving failed','Operation',op_id,'Failed',str(e));
  if isinstance(e,AppError):raise
  raise AppError('Recovery stopped safely. Existing recovered outputs remain documented.') from e
