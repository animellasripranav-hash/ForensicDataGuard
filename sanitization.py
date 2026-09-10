"""Guarded sanitization services.

File/folder overwriting is best-effort on flash media and copy-on-write file systems.
Physical-drive erasure is restricted to non-system removable media and requires
an elevated Windows process plus an exact confirmation phrase.
"""
import ctypes, hashlib, json, os, secrets, shutil, subprocess
from pathlib import Path
from config import DATA_DIR
from database import utcnow
from security import new_record_id
from services import AppError

BLOCK_SIZE=1024*1024
NO_WINDOW=0x08000000 if os.name=='nt' else 0
PROTECTED_NAMES={'windows','program files','program files (x86)','programdata','users'}

def _is_admin():
 try:return bool(ctypes.windll.shell32.IsUserAnAdmin())
 except Exception:return False

def _guard_path(path):
 p=Path(path).expanduser().resolve(strict=True)
 if p.is_symlink():raise AppError('Symbolic links and reparse targets cannot be erased.')
 if p.parent==p:raise AppError('A filesystem root cannot be erased with the file and folder module.')
 system_drive=Path(os.environ.get('SystemRoot','C:/Windows')).anchor.casefold()
 if p.anchor.casefold()==system_drive and (len(p.parts)<=2 or p.name.casefold() in PROTECTED_NAMES):raise AppError('Windows and protected system locations cannot be erased.')
 try:
  if p==DATA_DIR.resolve() or DATA_DIR.resolve() in p.parents:raise AppError('Application data and audit records cannot be erased from this module.')
 except OSError:pass
 return p

def _overwrite_file(path,passes,progress=None):
 size=path.stat().st_size; processed=0
 with path.open('r+b',buffering=0) as f:
  for pass_no,kind in enumerate(passes,1):
   f.seek(0); remaining=size
   while remaining:
    n=min(BLOCK_SIZE,remaining); data=(b'\x00'*n) if kind=='zero' else secrets.token_bytes(n); f.write(data); remaining-=n; processed+=n
    if progress:progress(processed,size*len(passes),f'Pass {pass_no}/{len(passes)}: {path.name}')
   f.flush(); os.fsync(f.fileno())
  if size:
   f.seek(0); sample=f.read(min(size,65536))
   if passes[-1]=='zero' and any(sample):raise AppError(f'Overwrite verification failed for {path.name}.')
 return size,hashlib.sha256((str(path)+str(size)+utcnow()).encode()).hexdigest()

def erase_paths(db,user,paths,method='NIST Clear',progress=None):
 if not paths:raise AppError('Select at least one file or folder.')
 if method not in ('NIST Clear','Zero pass','Random pass','Three pass'):raise AppError('Unsupported sanitization method.')
 passes={'NIST Clear':['zero'],'Zero pass':['zero'],'Random pass':['random'],'Three pass':['random','zero','random']}[method]
 targets=[]
 for raw in paths:
  p=_guard_path(raw)
  if p.is_dir():targets.extend(sorted((x for x in p.rglob('*') if x.is_file() and not x.is_symlink()),key=lambda x:len(x.parts),reverse=True))
  else:targets.append(p)
 op_id=new_record_id('ERASE'); total=sum(x.stat().st_size for x in targets)*len(passes)
 db.execute('INSERT INTO operations(operation_id,operation_type,target,status,method,initiated_by,started_at,details) VALUES(?,?,?,?,?,?,?,?)',(op_id,'File/Folder Erasure','; '.join(map(str,paths))[:1000],'Running',method,user['user_id'],utcnow(),f'{len(targets)} files'))
 completed=0
 try:
  for file in targets:
   size,_=_overwrite_file(file,passes,lambda done,all_bytes,msg:progress(completed+done,total,msg) if progress else None)
   completed+=size*len(passes)
   try:
    renamed=file.with_name('.'+secrets.token_hex(8)+'.erased'); file.rename(renamed); renamed.unlink()
   except OSError:file.unlink()
  for raw in sorted((Path(x).resolve() for x in paths if Path(x).is_dir()),key=lambda x:len(x.parts),reverse=True):
   for d in sorted((x for x in raw.rglob('*') if x.is_dir()),key=lambda x:len(x.parts),reverse=True):
    try:d.rmdir()
    except OSError:pass
   try:raw.rmdir()
   except OSError:pass
  if any(Path(x).exists() for x in paths):raise AppError('Some targets still exist after erasure. Review permissions and retry.')
  db.execute("UPDATE operations SET status='Completed',bytes_processed=?,completed_at=?,details=? WHERE operation_id=?",(completed,utcnow(),f'Verified absent; {len(targets)} files',op_id)); db.audit(user,'Secure erasure completed','Operation',op_id,'Success',f'{method}; {len(targets)} files; {completed} bytes written'); return op_id
 except Exception as e:
  db.execute("UPDATE operations SET status='Failed',bytes_processed=?,completed_at=?,details=? WHERE operation_id=?",(completed,utcnow(),str(e)[:1000],op_id)); db.audit(user,'Secure erasure failed','Operation',op_id,'Failed',str(e));
  if isinstance(e,AppError):raise
  raise AppError('Erasure stopped safely because a target could not be processed.') from e

def list_windows_disks():
 if os.name!='nt':return []
 ps="Get-Disk | Select Number,FriendlyName,SerialNumber,BusType,MediaType,Size,IsBoot,IsSystem,IsReadOnly,OperationalStatus | ConvertTo-Json -Compress"
 try:
  r=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',ps],capture_output=True,text=True,timeout=20,check=True,creationflags=NO_WINDOW); data=json.loads(r.stdout or '[]'); return data if isinstance(data,list) else [data]
 except Exception as e:raise AppError('Windows storage devices could not be enumerated.') from e

def erase_removable_drive(db,user,disk_number,serial,confirmation,progress=None):
 if os.name!='nt':raise AppError('Physical drive erasure is available only on Windows.')
 if user.get('role')!='Administrator':raise AppError('Administrator permission is required for drive erasure.')
 disks=list_windows_disks(); disk=next((d for d in disks if int(d.get('Number',-1))==int(disk_number)),None)
 if not disk:raise AppError('The selected disk is no longer available.')
 expected=f"ERASE DISK {disk_number} {str(serial).strip()}".strip()
 if confirmation.strip()!=expected:raise AppError(f'Type the exact confirmation: {expected}')
 if disk.get('IsBoot') or disk.get('IsSystem'):raise AppError('The Windows boot or system disk can never be erased.')
 if str(disk.get('BusType','')).upper() not in {'USB','SD','MMC'}:raise AppError('Only explicitly identified removable USB, SD, or MMC media can be erased.')
 if str(disk.get('SerialNumber','')).strip()!=str(serial).strip():raise AppError('Device identity changed. Refresh and select the device again.')
 if not _is_admin():raise AppError('Restart the application as Administrator to erase removable media.')
 op_id=new_record_id('DRIVE'); target=f"Disk {disk_number} {serial}"; db.execute('INSERT INTO operations(operation_id,operation_type,target,status,method,initiated_by,started_at,details) VALUES(?,?,?,?,?,?,?,?)',(op_id,'Secure Drive Erasure',target,'Running','Windows full zero overwrite',user['user_id'],utcnow(),'Removable media only'))
 script=f"select disk {int(disk_number)}\ndetail disk\nclean all\nexit\n"; script_path=DATA_DIR/f'{op_id}.diskpart.txt'; script_path.write_text(script,encoding='ascii')
 try:
  if progress:progress(0,int(disk.get('Size') or 0),'Windows is securely overwriting the selected removable drive…')
  result=subprocess.run(['diskpart','/s',str(script_path)],capture_output=True,text=True,timeout=24*60*60,creationflags=NO_WINDOW)
  if result.returncode!=0 or 'error' in (result.stdout+result.stderr).casefold():raise AppError('Windows reported that drive erasure failed. Review the operation report.')
  db.execute("UPDATE operations SET status='Completed',bytes_processed=?,completed_at=?,details=? WHERE operation_id=?",(int(disk.get('Size') or 0),utcnow(),'DiskPart clean all completed; device re-enumeration required',op_id)); db.audit(user,'Drive erasure completed','Operation',op_id,'Success',target); return op_id
 except Exception as e:
  db.execute("UPDATE operations SET status='Failed',completed_at=?,details=? WHERE operation_id=?",(utcnow(),str(e)[:1000],op_id)); db.audit(user,'Drive erasure failed','Operation',op_id,'Failed',str(e));
  if isinstance(e,AppError):raise
  raise AppError('Drive erasure failed safely.') from e
 finally:
  try:script_path.unlink()
  except OSError:pass
