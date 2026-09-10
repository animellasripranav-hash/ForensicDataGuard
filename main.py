import logging, queue, shutil, sys, threading
from pathlib import Path
try:
 import tkinter as tk
 from tkinter import ttk, messagebox, filedialog
except ImportError:
 raise SystemExit('Tkinter is required. Install Python 3.12 from python.org with Tcl/Tk support.')
from config import APP_NAME, APP_VERSION, DB_PATH, LOG_PATH
from database import Database, utcnow
from services import Service, AppError
from sanitization import erase_paths, erase_removable_drive, list_windows_disks
from recovery import carve_image

COLORS={'bg':'#111418','side':'#171B21','surface':'#1D222A','raised':'#252B34','text':'#F4F7FA','muted':'#AAB4C0','border':'#36404C','blue':'#4D9DEB','green':'#5CBF88','warning':'#E5A94D','red':'#E56B6F'}

def configure_logging():
 LOG_PATH.parent.mkdir(parents=True,exist_ok=True); logging.basicConfig(filename=LOG_PATH,level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')

def guarded(parent,fn):
 try: return fn()
 except AppError as e: messagebox.showerror('Unable to complete action',str(e),parent=parent)
 except Exception:
  logging.exception('Unexpected error'); messagebox.showerror('Unexpected error','The action could not be completed. No password or sensitive value was written to the log.',parent=parent)

def button(parent, **kwargs):
 kwargs.setdefault('style','Dark.TButton')
 return ttk.Button(parent,**kwargs)

class FormDialog(tk.Toplevel):
 def __init__(self,parent,title,fields,submit_text='Save'):
  super().__init__(parent); self.title(title); self.configure(bg=COLORS['surface']); self.resizable(False,False); self.result=None; self.vars={}
  box=tk.Frame(self,bg=COLORS['surface'],padx=24,pady=20); box.pack(fill='both',expand=True)
  tk.Label(box,text=title,bg=COLORS['surface'],fg=COLORS['text'],font=('Segoe UI',18,'bold')).grid(row=0,column=0,columnspan=2,sticky='w',pady=(0,18))
  r=1
  for key,label,secret in fields:
   tk.Label(box,text=label,bg=COLORS['surface'],fg=COLORS['muted'],font=('Segoe UI',10)).grid(row=r,column=0,sticky='w',pady=7,padx=(0,12))
   v=tk.StringVar(); e=tk.Entry(box,textvariable=v,show='•' if secret else '',width=36,bg=COLORS['raised'],fg=COLORS['text'],insertbackground=COLORS['text'],relief='flat',highlightthickness=1,highlightbackground=COLORS['border'],highlightcolor=COLORS['blue'],font=('Segoe UI',11)); e.grid(row=r,column=1,ipady=7); self.vars[key]=v; r+=1
  actions=tk.Frame(box,bg=COLORS['surface']); actions.grid(row=r,column=0,columnspan=2,sticky='e',pady=(18,0))
  button(actions,text='Cancel',command=self.destroy).pack(side='left',padx=6); button(actions,text=submit_text,style='Accent.TButton',command=self.submit).pack(side='left')
  self.transient(parent); self.grab_set(); self.bind('<Escape>',lambda e:self.destroy()); self.bind('<Return>',lambda e:self.submit()); self.after(50,lambda:self.focus_force())
 def submit(self): self.result={k:v.get() for k,v in self.vars.items()}; self.destroy()

class AuthView(tk.Frame):
 def __init__(self,root,service,on_login):
  super().__init__(root,bg=COLORS['bg']); self.s=service; self.on_login=on_login; self.pack(fill='both',expand=True); self.build()
 def build(self):
  wrap=tk.Frame(self,bg=COLORS['surface'],padx=42,pady=38,highlightthickness=1,highlightbackground=COLORS['border']); wrap.place(relx=.5,rely=.5,anchor='center')
  tk.Label(wrap,text='FORENSIC DATA GUARD',bg=COLORS['surface'],fg=COLORS['blue'],font=('Segoe UI',11,'bold')).pack(anchor='w')
  tk.Label(wrap,text='Secure Sign In',bg=COLORS['surface'],fg=COLORS['text'],font=('Segoe UI',24,'bold')).pack(anchor='w',pady=(8,4))
  tk.Label(wrap,text='Authorized forensic personnel only',bg=COLORS['surface'],fg=COLORS['muted'],font=('Segoe UI',10)).pack(anchor='w',pady=(0,24))
  self.u=tk.StringVar(); self.p=tk.StringVar(); self.show=tk.BooleanVar()
  self.entry(wrap,'Username',self.u); pentry=self.entry(wrap,'Password',self.p,True)
  tk.Checkbutton(wrap,text='Show password',variable=self.show,command=lambda:pentry.configure(show='' if self.show.get() else '•'),bg=COLORS['surface'],fg=COLORS['muted'],selectcolor=COLORS['raised'],activebackground=COLORS['surface'],activeforeground=COLORS['text']).pack(anchor='w',pady=8)
  button(wrap,text='Sign In',style='Accent.TButton',command=self.login).pack(fill='x',ipady=5,pady=(10,8)); button(wrap,text='Create Account',command=self.register).pack(fill='x',ipady=4)
  self.status=tk.Label(wrap,text='',bg=COLORS['surface'],fg=COLORS['red'],wraplength=360,font=('Segoe UI',10)); self.status.pack(pady=(14,0))
  self.bind_all('<Return>',lambda e:self.login())
 def entry(self,parent,label,var,secret=False):
  tk.Label(parent,text=label,bg=COLORS['surface'],fg=COLORS['muted']).pack(anchor='w',pady=(8,5)); e=tk.Entry(parent,textvariable=var,show='•' if secret else '',width=42,bg=COLORS['raised'],fg=COLORS['text'],insertbackground=COLORS['text'],relief='flat',highlightthickness=1,highlightbackground=COLORS['border'],highlightcolor=COLORS['blue'],font=('Segoe UI',12)); e.pack(fill='x',ipady=8); return e
 def login(self):
  self.status.configure(text='Signing in…',fg=COLORS['muted']); self.update_idletasks()
  try: self.on_login(self.s.authenticate(self.u.get(),self.p.get()))
  except AppError as e: self.p.set(''); self.status.configure(text=str(e),fg=COLORS['red'])
 def register(self):
  d=FormDialog(self,'Create Account',[('display','Full/display name',False),('username','Unique username',False),('password','Password (8+ characters: letters and numbers)',True),('confirm','Confirm password',True)],'Submit for Approval'); self.wait_window(d)
  if not d.result:return
  if d.result['password']!=d.result['confirm']: return messagebox.showerror('Validation','Passwords do not match.',parent=self)
  if not messagebox.askyesno('Authorized use','I confirm that I am authorized to use this forensic application. Continue?',parent=self): return
  def run():
   uid=self.s.create_user(d.result['display'],d.result['username'],'',d.result['password'],''); messagebox.showinfo('Registration submitted',f'Account {uid} is pending Administrator approval.',parent=self)
  guarded(self,run)

class MainView(tk.Frame):
 def __init__(self,root,db,service,user,on_logout):
  super().__init__(root,bg=COLORS['bg']); self.root=root; self.db=db; self.s=service; self.user=user; self.on_logout=on_logout; self.pack(fill='both',expand=True); self.pages={}; self.build(); self.show('Dashboard')
 def build(self):
  side=tk.Frame(self,bg=COLORS['side'],width=220); side.pack(side='left',fill='y'); side.pack_propagate(False)
  tk.Label(side,text='FDG',bg=COLORS['side'],fg=COLORS['blue'],font=('Segoe UI',22,'bold')).pack(anchor='w',padx=22,pady=(24,4)); tk.Label(side,text=self.user['role'],bg=COLORS['side'],fg=COLORS['muted']).pack(anchor='w',padx=22,pady=(0,22))
  names=['Dashboard','Cases','Evidence']+(['Drive Eraser'] if self.user['role']=='Administrator' else [])+['File Eraser','Recovery','Operations','Reports','Audit Trail']+(['Users'] if self.user['role']=='Administrator' else [])+['Settings']
  for n in names: tk.Button(side,text=n,command=lambda x=n:self.show(x),anchor='w',bg=COLORS['side'],fg=COLORS['text'],activebackground=COLORS['raised'],activeforeground=COLORS['text'],relief='flat',font=('Segoe UI',11),padx=20,pady=10).pack(fill='x')
  tk.Label(side,text=f"{self.user['username']}\n{self.user['user_id']}",bg=COLORS['side'],fg=COLORS['muted'],justify='left').pack(side='bottom',anchor='w',padx=22,pady=12); button(side,text='Sign Out',command=self.on_logout).pack(side='bottom',fill='x',padx=18,pady=8)
  self.main=tk.Frame(self,bg=COLORS['bg']); self.main.pack(side='left',fill='both',expand=True)
 def show(self,name):
  for p in self.pages.values(): p.destroy()
  self.pages={}; method=getattr(self,'page_'+name.lower().replace(' ','_')); p=method(); self.pages[name]=p
 def shell(self,title,subtitle):
  p=tk.Frame(self.main,bg=COLORS['bg'],padx=30,pady=24); p.pack(fill='both',expand=True); tk.Label(p,text=title,bg=COLORS['bg'],fg=COLORS['text'],font=('Segoe UI',24,'bold')).pack(anchor='w'); tk.Label(p,text=subtitle,bg=COLORS['bg'],fg=COLORS['muted'],font=('Segoe UI',10)).pack(anchor='w',pady=(3,18)); return p
 def run_job(self,title,task,on_success=None):
  dlg=tk.Toplevel(self); dlg.title(title); dlg.configure(bg=COLORS['surface']); dlg.geometry('520x180'); dlg.resizable(False,False); dlg.transient(self.root); dlg.grab_set()
  tk.Label(dlg,text=title,bg=COLORS['surface'],fg=COLORS['text'],font=('Segoe UI',16,'bold')).pack(anchor='w',padx=24,pady=(22,8)); status=tk.StringVar(value='Preparing…'); tk.Label(dlg,textvariable=status,bg=COLORS['surface'],fg=COLORS['muted'],wraplength=470).pack(anchor='w',padx=24,pady=6); bar=ttk.Progressbar(dlg,mode='indeterminate'); bar.pack(fill='x',padx=24,pady=14); bar.start(12); q=queue.Queue()
  def progress(done,total,msg):q.put(('progress',done,total,msg))
  def worker():
   try:q.put(('done',task(progress)))
   except Exception as e:q.put(('error',e))
  def poll():
   try:
    while True:
     item=q.get_nowait()
     if item[0]=='progress':
      _,done,total,msg=item; status.set(msg)
      if total>0:
       bar.stop(); bar.configure(mode='determinate',maximum=total,value=done)
     elif item[0]=='done':
      dlg.destroy();
      if on_success:on_success(item[1])
      return
     else:
      dlg.destroy(); e=item[1]; messagebox.showerror('Operation failed',str(e) if isinstance(e,AppError) else 'The operation failed safely. Review the audit log.',parent=self); return
   except queue.Empty:pass
   dlg.after(120,poll)
  threading.Thread(target=worker,daemon=True).start(); poll()
 def table(self,parent,cols,widths=None):
  f=tk.Frame(parent,bg=COLORS['surface']); f.pack(fill='both',expand=True); t=ttk.Treeview(f,columns=cols,show='headings',selectmode='browse')
  for i,c in enumerate(cols): t.heading(c,text=c); t.column(c,width=(widths[i] if widths else 140),anchor='w')
  y=ttk.Scrollbar(f,orient='vertical',command=t.yview); t.configure(yscrollcommand=y.set); t.pack(side='left',fill='both',expand=True); y.pack(side='right',fill='y'); return t
 def page_dashboard(self):
  p=self.shell('Dashboard','Operational status and recent forensic activity'); stats=tk.Frame(p,bg=COLORS['bg']); stats.pack(fill='x')
  queries=[('OPEN CASES',"SELECT COUNT(*) n FROM cases WHERE status='Open'"),('EVIDENCE','SELECT COUNT(*) n FROM evidence'),('INTEGRITY ALERTS',"SELECT COUNT(*) n FROM evidence WHERE integrity_status IN ('Mismatch','Missing')"),('PENDING USERS',"SELECT COUNT(*) n FROM users WHERE status='Pending approval'")]
  for label,q in queries:
   card=tk.Frame(stats,bg=COLORS['surface'],padx=18,pady=16,highlightthickness=1,highlightbackground=COLORS['border']); card.pack(side='left',fill='x',expand=True,padx=(0,12)); tk.Label(card,text=label,bg=COLORS['surface'],fg=COLORS['muted'],font=('Segoe UI',9,'bold')).pack(anchor='w'); tk.Label(card,text=str(self.db.one(q)['n']),bg=COLORS['surface'],fg=COLORS['text'],font=('Segoe UI',24,'bold')).pack(anchor='w')
  tk.Label(p,text='Recent activity',bg=COLORS['bg'],fg=COLORS['text'],font=('Segoe UI',16,'bold')).pack(anchor='w',pady=(24,10)); t=self.table(p,('Time','User','Action','Target','Outcome'),[190,130,190,170,90])
  for r in self.db.query('SELECT timestamp,username,action,target_id,outcome FROM audit ORDER BY event_id DESC LIMIT 20'): t.insert('', 'end',values=(r['timestamp'],r['username'] or 'System',r['action'],r['target_id'],r['outcome']))
  return p
 def page_cases(self):
  p=self.shell('Cases','Create and manage forensic cases'); bar=tk.Frame(p,bg=COLORS['bg']); bar.pack(fill='x',pady=(0,10)); button(bar,text='New Case',style='Accent.TButton',command=lambda:self.new_case()).pack(side='left'); button(bar,text='Refresh',command=lambda:self.show('Cases')).pack(side='left',padx=8)
  t=self.table(p,('Case ID','Title','Reference','Status','Priority','Updated'),[180,240,130,90,90,180]); self.case_table=t
  for r in self.db.query('SELECT case_id,title,reference_no,status,priority,updated_at FROM cases ORDER BY updated_at DESC'): t.insert('', 'end',values=(r['case_id'],r['title'],r['reference_no'] or '',r['status'],r['priority'],r['updated_at']))
  return p
 def new_case(self):
  d=FormDialog(self,'New Case',[('title','Case title',False),('reference','Reference number',False),('description','Description',False),('priority','Priority (Low/Normal/High/Critical)',False)],'Create Case'); self.wait_window(d)
  if d.result: guarded(self,lambda:(self.s.create_case(self.user,d.result['title'],d.result['reference'],d.result['description'],d.result['priority'] or 'Normal'),self.show('Cases')))
 def page_evidence(self):
  p=self.shell('Evidence','Register files and verify cryptographic integrity'); bar=tk.Frame(p,bg=COLORS['bg']); bar.pack(fill='x',pady=(0,10)); button(bar,text='Add Evidence',style='Accent.TButton',command=self.add_evidence).pack(side='left'); button(bar,text='Verify Selected',command=self.verify_selected).pack(side='left',padx=8); button(bar,text='Refresh',command=lambda:self.show('Evidence')).pack(side='left')
  t=self.table(p,('Evidence ID','Case','Name','Size','SHA-256','Integrity'),[180,160,190,90,310,110]); self.ev_table=t
  for r in self.db.query('SELECT evidence_id,case_id,name,size_bytes,sha256,integrity_status FROM evidence ORDER BY created_at DESC'): t.insert('', 'end',values=(r['evidence_id'],r['case_id'],r['name'],r['size_bytes'],r['sha256'],r['integrity_status']))
  return p
 def add_evidence(self):
  cases=self.db.query("SELECT case_id,title FROM cases WHERE status='Open' ORDER BY created_at DESC")
  if not cases:return messagebox.showwarning('No open case','Create an open case before registering evidence.',parent=self)
  path=filedialog.askopenfilename(title='Select evidence file',parent=self)
  if not path:return
  d=FormDialog(self,'Evidence Details',[('case','Case ID',False),('name','Evidence name',False),('description','Description',False)],'Register Evidence'); d.vars['case'].set(cases[0]['case_id']); d.vars['name'].set(Path(path).name); self.wait_window(d)
  if d.result: guarded(self,lambda:(self.s.add_evidence(self.user,d.result['case'],path,d.result['name'],d.result['description']),self.show('Evidence')))
 def verify_selected(self):
  sel=self.ev_table.selection()
  if not sel:return messagebox.showwarning('Select evidence','Select an evidence record first.',parent=self)
  eid=self.ev_table.item(sel[0])['values'][0]
  def run(): status=self.s.verify_evidence(self.user,eid); messagebox.showinfo('Verification result',f'{eid}: {status}',parent=self); self.show('Evidence')
  guarded(self,run)
 def page_drive_eraser(self):
  p=self.shell('Secure Drive Eraser','Administrator-only sanitization for removable USB, SD, and MMC media')
  warning=tk.Label(p,text='DANGER — Drive erasure is irreversible. Windows system and boot disks are always blocked.',bg='#3A2528',fg='#FFD9D9',padx=14,pady=12,anchor='w'); warning.pack(fill='x',pady=(0,12))
  bar=tk.Frame(p,bg=COLORS['bg']); bar.pack(fill='x',pady=(0,10)); button(bar,text='Refresh Devices',command=self.refresh_disks).pack(side='left'); button(bar,text='Erase Selected Removable Drive',style='Accent.TButton',command=self.start_drive_erase).pack(side='left',padx=8)
  self.drive_table=self.table(p,('Disk','Name','Serial','Bus','Media','Size','System'),[55,220,170,80,90,110,70]); self.refresh_disks(); return p
 def refresh_disks(self):
  if not hasattr(self,'drive_table'):return
  for i in self.drive_table.get_children():self.drive_table.delete(i)
  try:
   for d in list_windows_disks():self.drive_table.insert('','end',values=(d.get('Number'),d.get('FriendlyName',''),str(d.get('SerialNumber','')).strip(),d.get('BusType',''),d.get('MediaType',''),d.get('Size',0),'Yes' if d.get('IsBoot') or d.get('IsSystem') else 'No'))
  except AppError as e:messagebox.showerror('Device scan failed',str(e),parent=self)
 def start_drive_erase(self):
  sel=self.drive_table.selection()
  if not sel:return messagebox.showwarning('Select a device','Select a removable device first.',parent=self)
  v=self.drive_table.item(sel[0])['values']; number=v[0]; serial=str(v[2]); expected=f'ERASE DISK {number} {serial}'.strip()
  d=FormDialog(self,'Confirm Irreversible Drive Erasure',[('confirm',f'Type exactly: {expected}',False)],'Erase Drive'); self.wait_window(d)
  if not d.result:return
  self.run_job('Secure Drive Erasure',lambda progress:erase_removable_drive(self.db,self.user,number,serial,d.result['confirm'],progress),lambda op:messagebox.showinfo('Erasure complete',f'Operation {op} completed. Refresh Windows Disk Management before reuse.',parent=self))
 def page_file_eraser(self):
  p=self.shell('Secure File & Folder Eraser','Batch overwrite, metadata-name removal, deletion verification, and audit reporting')
  notice=tk.Label(p,text='For SSDs and flash storage, file-level overwriting cannot guarantee removal from remapped physical cells. Use device sanitize procedures when required.',bg='#382F20',fg='#FFE3AD',padx=14,pady=10,anchor='w',wraplength=900,justify='left'); notice.pack(fill='x',pady=(0,12))
  bar=tk.Frame(p,bg=COLORS['bg']); bar.pack(fill='x',pady=(0,8)); button(bar,text='Add File',command=self.add_erase_file).pack(side='left'); button(bar,text='Add Folder',command=self.add_erase_folder).pack(side='left',padx=6); button(bar,text='Remove Selected',command=self.remove_erase_target).pack(side='left')
  self.erase_list=tk.Listbox(p,bg=COLORS['surface'],fg=COLORS['text'],selectbackground=COLORS['blue'],selectforeground='#07121c',highlightthickness=1,highlightbackground=COLORS['border'],font=('Segoe UI',10),height=12); self.erase_list.pack(fill='both',expand=True)
  foot=tk.Frame(p,bg=COLORS['bg']); foot.pack(fill='x',pady=12); tk.Label(foot,text='Method',bg=COLORS['bg'],fg=COLORS['muted']).pack(side='left'); self.erase_method=tk.StringVar(value='NIST Clear'); ttk.Combobox(foot,style='Dark.TCombobox',textvariable=self.erase_method,state='readonly',values=('NIST Clear','Zero pass','Random pass','Three pass'),width=18).pack(side='left',padx=8); button(foot,text='Erase Selected Targets',style='Accent.TButton',command=self.start_file_erase).pack(side='right'); return p
 def add_erase_file(self):
  for x in filedialog.askopenfilenames(title='Select files to erase permanently',parent=self):
   if x not in self.erase_list.get(0,'end'):self.erase_list.insert('end',x)
 def add_erase_folder(self):
  x=filedialog.askdirectory(title='Select folder to erase permanently',parent=self)
  if x and x not in self.erase_list.get(0,'end'):self.erase_list.insert('end',x)
 def remove_erase_target(self):
  for i in reversed(self.erase_list.curselection()):self.erase_list.delete(i)
 def start_file_erase(self):
  paths=list(self.erase_list.get(0,'end'))
  if not paths:return messagebox.showwarning('No targets','Add at least one file or folder.',parent=self)
  d=FormDialog(self,'Confirm Irreversible Erasure',[('confirm','Type ERASE SELECTED',False)],'Erase Permanently'); self.wait_window(d)
  if not d.result:return
  if d.result['confirm']!='ERASE SELECTED':return messagebox.showerror('Confirmation failed','Type ERASE SELECTED exactly.',parent=self)
  self.run_job('Secure File and Folder Erasure',lambda progress:erase_paths(self.db,self.user,paths,self.erase_method.get(),progress),lambda op:(messagebox.showinfo('Erasure complete',f'Operation {op} completed and was recorded in the audit trail.',parent=self),self.show('File Eraser')))
 def page_recovery(self):
  p=self.shell('Advanced File Carving & Recovery','Read-only signature and structure carving from disk images or binary media captures')
  tk.Label(p,text='The source is opened read-only. Recover output to a different drive whenever possible to preserve evidence.',bg='#1B3040',fg='#CDEBFF',padx=14,pady=10,anchor='w').pack(fill='x',pady=(0,14)); form=tk.Frame(p,bg=COLORS['surface'],padx=18,pady=18,highlightthickness=1,highlightbackground=COLORS['border']); form.pack(fill='x'); self.recovery_source=tk.StringVar(); self.recovery_dest=tk.StringVar()
  for row,(label,var,cmd) in enumerate((('Source image/media capture',self.recovery_source,self.pick_recovery_source),('Recovery output folder',self.recovery_dest,self.pick_recovery_dest))):
   tk.Label(form,text=label,bg=COLORS['surface'],fg=COLORS['muted']).grid(row=row,column=0,sticky='w',pady=7); tk.Entry(form,textvariable=var,bg=COLORS['raised'],fg=COLORS['text'],insertbackground=COLORS['text'],highlightthickness=1,highlightbackground=COLORS['border'],highlightcolor=COLORS['blue'],relief='flat',width=70).grid(row=row,column=1,sticky='ew',padx=10,ipady=7); button(form,text='Browse',command=cmd).grid(row=row,column=2); form.columnconfigure(1,weight=1)
  button(p,text='Start Read-Only Recovery',style='Accent.TButton',command=self.start_recovery).pack(anchor='e',pady=12); tk.Label(p,text='Supported classification: JPEG, PNG, PDF, ZIP/DOCX/XLSX containers, and GIF. Each output includes offsets, SHA-256, structural validation, and confidence score.',bg=COLORS['bg'],fg=COLORS['muted'],wraplength=900,justify='left').pack(anchor='w'); return p
 def pick_recovery_source(self):
  x=filedialog.askopenfilename(title='Select disk image or media capture',filetypes=[('Disk images','*.img *.dd *.raw *.bin *.iso'),('All files','*.*')],parent=self)
  if x:self.recovery_source.set(x)
 def pick_recovery_dest(self):
  x=filedialog.askdirectory(title='Select recovery output folder',parent=self)
  if x:self.recovery_dest.set(x)
 def start_recovery(self):
  src=self.recovery_source.get(); dest=self.recovery_dest.get()
  if not src or not dest:return messagebox.showwarning('Missing information','Select both a source image and an output folder.',parent=self)
  self.run_job('File Carving and Recovery',lambda progress:carve_image(self.db,self.user,src,dest,progress),lambda result:messagebox.showinfo('Recovery complete',f'Operation {result[0]} recovered {len(result[1])} files.\nManifest: {result[2]}',parent=self))
 def page_operations(self):
  p=self.shell('Operations','Sanitization and recovery operation history'); t=self.table(p,('Operation ID','Type','Target','Status','Method','Bytes','Started','Completed'),[170,180,220,90,180,100,170,170])
  for r in self.db.query('SELECT operation_id,operation_type,target,status,method,bytes_processed,started_at,completed_at FROM operations ORDER BY started_at DESC'):t.insert('','end',values=(r['operation_id'],r['operation_type'],r['target'],r['status'],r['method'],r['bytes_processed'],r['started_at'],r['completed_at'] or ''))
  return p
 def page_reports(self):
  p=self.shell('Reports','Tamper-evident case, sanitization, and recovery reports'); tabs=ttk.Notebook(p); tabs.pack(fill='both',expand=True)
  case_tab=tk.Frame(tabs,bg=COLORS['bg'],padx=10,pady=10); op_tab=tk.Frame(tabs,bg=COLORS['bg'],padx=10,pady=10); tabs.add(case_tab,text='Case Reports'); tabs.add(op_tab,text='Operation Reports')
  cases=self.db.query('SELECT case_id,title,status FROM cases ORDER BY updated_at DESC'); self.report_table=self.table(case_tab,('Case ID','Title','Status'),[190,360,120])
  for r in cases:self.report_table.insert('', 'end',values=(r['case_id'],r['title'],r['status']))
  button(case_tab,text='Export Selected Case Report',style='Report.TButton',command=self.export_report).pack(anchor='e',pady=10)
  self.operation_report_table=self.table(op_tab,('Operation ID','Type','Status','Started'),[190,250,110,190])
  for r in self.db.query('SELECT operation_id,operation_type,status,started_at FROM operations ORDER BY started_at DESC'):self.operation_report_table.insert('','end',values=(r['operation_id'],r['operation_type'],r['status'],r['started_at']))
  button(op_tab,text='Export Selected Operation Report',style='Report.TButton',command=self.export_operation_report).pack(anchor='e',pady=10); return p
 def export_report(self):
  sel=self.report_table.selection()
  if not sel:return messagebox.showwarning('Select case','Select a case first.',parent=self)
  cid=self.report_table.item(sel[0])['values'][0]; dest=filedialog.asksaveasfilename(parent=self,defaultextension='.html',filetypes=[('HTML report','*.html')],initialfile=f'{cid}-report.html')
  if dest: guarded(self,lambda:(self.s.export_case_html(self.user,cid,dest),messagebox.showinfo('Report exported',f'Report saved to:\n{dest}',parent=self)))
 def export_operation_report(self):
  sel=self.operation_report_table.selection()
  if not sel:return messagebox.showwarning('Select operation','Select an operation first.',parent=self)
  op_id=self.operation_report_table.item(sel[0])['values'][0]; dest=filedialog.asksaveasfilename(parent=self,defaultextension='.html',filetypes=[('HTML report','*.html')],initialfile=f'{op_id}-report.html')
  if dest:guarded(self,lambda:(self.s.export_operation_html(self.user,op_id,dest),messagebox.showinfo('Report exported',f'Report saved to:\n{dest}',parent=self)))
 def page_audit_trail(self):
  p=self.shell('Audit Trail','Append-only accountability history'); t=self.table(p,('Time','Event','User ID','Username','Action','Target','Outcome'),[180,70,150,110,170,170,80])
  for r in self.db.query('SELECT timestamp,event_id,user_id,username,action,target_id,outcome FROM audit ORDER BY event_id DESC LIMIT 1000'):t.insert('', 'end',values=(r['timestamp'],r['event_id'],r['user_id'] or '',r['username'] or '',r['action'],r['target_id'] or '',r['outcome']))
  return p
 def page_users(self):
  p=self.shell('Users','Approve registrations and manage account status'); bar=tk.Frame(p,bg=COLORS['bg']); bar.pack(fill='x',pady=(0,10)); button(bar,text='Approve as Investigator',style='Accent.TButton',command=lambda:self.user_action('approve','Investigator')).pack(side='left'); button(bar,text='Approve as Auditor',command=lambda:self.user_action('approve','Auditor')).pack(side='left',padx=6); button(bar,text='Unlock/Activate',command=lambda:self.user_action('status','Active')).pack(side='left'); button(bar,text='Disable',command=lambda:self.user_action('status','Disabled')).pack(side='left',padx=6)
  t=self.table(p,('User ID','Name','Username','Role','Status','Last Sign-in'),[170,170,140,120,140,190]); self.user_table=t
  for r in self.db.query('SELECT user_id,display_name,username,role,status,last_login FROM users ORDER BY created_at DESC'):t.insert('', 'end',values=(r['user_id'],r['display_name'],r['username'],r['role'],r['status'],r['last_login'] or 'Never'))
  return p
 def user_action(self,kind,value):
  sel=self.user_table.selection()
  if not sel:return messagebox.showwarning('Select user','Select a user first.',parent=self)
  uid=self.user_table.item(sel[0])['values'][0]
  if not messagebox.askyesno('Confirm action',f'{kind.title()} account {uid}?',parent=self):return
  fn=(lambda:self.s.approve_user(self.user,uid,value)) if kind=='approve' else (lambda:self.s.set_user_status(self.user,uid,value)); guarded(self,lambda:(fn(),self.show('Users')))
 def page_settings(self):
  p=self.shell('Settings & Maintenance','Database health, backup, and application information'); card=tk.Frame(p,bg=COLORS['surface'],padx=20,pady=20,highlightthickness=1,highlightbackground=COLORS['border']); card.pack(fill='x');
  for text in (f'Application version: {APP_VERSION}',f'Database: {DB_PATH}',f'Database integrity: {self.db.one("PRAGMA integrity_check")["integrity_check"]}',f'Audit hash chain: {"Valid" if self.db.verify_audit_chain() else "FAILED"}'):
   tk.Label(card,text=text,bg=COLORS['surface'],fg=COLORS['text'],anchor='w').pack(fill='x',pady=5)
  button(card,text='Back Up Database',style='Accent.TButton',command=self.backup).pack(anchor='w',pady=(14,0)); return p
 def backup(self):
  dest=filedialog.asksaveasfilename(parent=self,defaultextension='.db',filetypes=[('SQLite backup','*.db')],initialfile=f'forensic-guard-backup-{utcnow()[:10]}.db')
  if not dest:return
  def run(): shutil.copy2(DB_PATH,dest); self.db.audit(self.user,'Database backup','Database','primary','Success',dest); messagebox.showinfo('Backup complete',f'Backup saved to:\n{dest}',parent=self)
  guarded(self,run)

class Application(tk.Tk):
 def __init__(self):
  super().__init__(); self.title(f'{APP_NAME} {APP_VERSION}'); self.geometry('1280x800'); self.minsize(1024,700); self.configure(bg=COLORS['bg']); self.style(); self.db=Database(); self.s=Service(self.db); self.view=None
  if not self.db.has_users(): self.setup_admin()
  else:self.auth()
 def style(self):
  s=ttk.Style(self); s.theme_use('clam'); s.configure('.',background=COLORS['surface'],foreground=COLORS['text'],font=('Segoe UI',10)); s.configure('TButton',background=COLORS['raised'],foreground=COLORS['text'],padding=(14,8),borderwidth=0,relief='flat'); s.configure('Dark.TButton',background=COLORS['raised'],foreground=COLORS['text'],padding=(14,8),borderwidth=0,relief='flat'); s.map('TButton',background=[('disabled','#20252C'),('pressed','#465362'),('active',COLORS['border'])],foreground=[('disabled','#7D8791'),('pressed',COLORS['text']),('active',COLORS['text'])]); s.map('Dark.TButton',background=[('disabled','#20252C'),('pressed','#465362'),('active',COLORS['border'])],foreground=[('disabled','#7D8791'),('pressed',COLORS['text']),('active',COLORS['text'])]); s.configure('Accent.TButton',background=COLORS['blue'],foreground='#07121c'); s.map('Accent.TButton',background=[('active','#6BAFF0')]); s.configure('Treeview',background=COLORS['surface'],fieldbackground=COLORS['surface'],foreground=COLORS['text'],rowheight=32,borderwidth=0); s.configure('Treeview.Heading',background=COLORS['raised'],foreground=COLORS['text'],padding=8,borderwidth=0); s.map('Treeview',background=[('selected',COLORS['blue'])],foreground=[('selected','#07121c')]); s.configure('TNotebook',background=COLORS['bg'],borderwidth=0,tabmargins=(0,0,0,0)); s.configure('TNotebook.Tab',background=COLORS['raised'],foreground=COLORS['text'],padding=(16,9),borderwidth=0); s.map('TNotebook.Tab',background=[('selected',COLORS['blue']),('active',COLORS['border'])],foreground=[('selected','#07121c'),('active',COLORS['text'])]); s.configure('Report.TButton',background=COLORS['blue'],foreground='#07121c',padding=(14,8),borderwidth=0); s.map('Report.TButton',background=[('active','#6BAFF0'),('pressed','#3B8AD4')],foreground=[('active','#07121c'),('pressed','#07121c')]); s.configure('Dark.TCombobox',fieldbackground=COLORS['raised'],background=COLORS['raised'],foreground=COLORS['text'],arrowcolor=COLORS['text'],bordercolor=COLORS['border'],lightcolor=COLORS['border'],darkcolor=COLORS['border'],padding=6); s.map('Dark.TCombobox',fieldbackground=[('readonly',COLORS['raised'])],background=[('readonly',COLORS['raised'])],foreground=[('readonly',COLORS['text'])]); s.configure('Vertical.TScrollbar',background=COLORS['raised'],troughcolor=COLORS['bg'],arrowcolor=COLORS['text'],bordercolor=COLORS['bg']); s.configure('Horizontal.TScrollbar',background=COLORS['raised'],troughcolor=COLORS['bg'],arrowcolor=COLORS['text'],bordercolor=COLORS['bg']); s.configure('TProgressbar',background=COLORS['blue'],troughcolor=COLORS['raised'],bordercolor=COLORS['raised'])
 def clear(self):
  for w in self.winfo_children():w.destroy()
 def setup_admin(self):
  self.update_idletasks(); self.deiconify()
  while True:
   d=FormDialog(self,'First Administrator Setup',[('display','Full/display name',False),('username','Username',False),('password','Password (8+ characters: letters and numbers)',True),('confirm','Confirm password',True)],'Create Administrator'); self.wait_window(d)
   if not d.result:self.destroy();return
   if d.result['password']!=d.result['confirm']:
    messagebox.showerror('Validation','Passwords do not match.',parent=self); continue
   result=guarded(self,lambda:self.s.create_user(d.result['display'],d.result['username'],'',d.result['password'],'','Administrator','Active'))
   if result: break
  self.auth()
 def auth(self): self.clear(); AuthView(self,self.s,self.logged_in)
 def logged_in(self,user): self.clear(); MainView(self,self.db,self.s,user,self.auth)

if __name__=='__main__':
 configure_logging()
 try: Application().mainloop()
 except Exception:
  logging.exception('Fatal startup error');
  try: messagebox.showerror('Startup error','Forensic Data Guard could not start. Review the sanitized application log.')
  except Exception: pass
  sys.exit(1)
