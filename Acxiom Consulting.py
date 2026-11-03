"""AcxiomCRM Enterprise Edition - single-file Flask + SQLite CRM.
Educational implementation baseline. Install Flask, then run: python AcxiomCRM_Enterprise.py
"""
from __future__ import annotations
import os, re, csv, io, json, secrets, sqlite3
from datetime import datetime, date, timedelta
from functools import wraps
from flask import Flask, request, jsonify, session, render_template_string, g, make_response
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('ACXIOMCRM_DB', os.path.join(BASE_DIR, 'acxiomcrm.db'))
app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_hex(32),
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                  SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE') == '1',
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=4), MAX_CONTENT_LENGTH=3*1024*1024)
ROLES = ('Admin','Manager','Sales Executive')
STATUSES = {'customers':('Active','Inactive','Prospect'), 'leads':('New','Contacted','Qualified','Unqualified','Converted','Lost'),
            'opportunities':('Qualification','Proposal','Negotiation','Won','Lost'),
            'followups':('Planned','Completed','Missed','Cancelled'), 'activities':('Open','In Progress','Completed','Cancelled')}
ACTIVITY_TYPES=('Call','Meeting','Email','Task')

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('Admin','Manager','Sales Executive')),active INTEGER NOT NULL DEFAULT 1,failed_count INTEGER NOT NULL DEFAULT 0,lockout_until TEXT,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS customers(id INTEGER PRIMARY KEY AUTOINCREMENT,code TEXT UNIQUE NOT NULL,name TEXT NOT NULL,email TEXT NOT NULL COLLATE NOCASE UNIQUE,phone TEXT NOT NULL UNIQUE,company TEXT,address TEXT,city TEXT,state TEXT,status TEXT NOT NULL DEFAULT 'Active',owner_id INTEGER,notes TEXT,created_at TEXT NOT NULL,updated_at TEXT,FOREIGN KEY(owner_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS leads(id INTEGER PRIMARY KEY AUTOINCREMENT,code TEXT UNIQUE NOT NULL,name TEXT NOT NULL,email TEXT,phone TEXT,company TEXT,source TEXT,status TEXT NOT NULL DEFAULT 'New',priority TEXT NOT NULL DEFAULT 'Medium',expected_value REAL NOT NULL DEFAULT 0,owner_id INTEGER,notes TEXT,converted_customer_id INTEGER,created_at TEXT NOT NULL,updated_at TEXT,FOREIGN KEY(owner_id) REFERENCES users(id),FOREIGN KEY(converted_customer_id) REFERENCES customers(id));
CREATE TABLE IF NOT EXISTS opportunities(id INTEGER PRIMARY KEY AUTOINCREMENT,code TEXT UNIQUE NOT NULL,name TEXT NOT NULL,customer_id INTEGER,lead_id INTEGER,amount REAL NOT NULL,stage TEXT NOT NULL,probability INTEGER NOT NULL,expected_close_date TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Open',source TEXT,owner_id INTEGER,notes TEXT,created_at TEXT NOT NULL,updated_at TEXT,FOREIGN KEY(customer_id) REFERENCES customers(id),FOREIGN KEY(lead_id) REFERENCES leads(id),FOREIGN KEY(owner_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS followups(id INTEGER PRIMARY KEY AUTOINCREMENT,code TEXT UNIQUE NOT NULL,customer_id INTEGER,lead_id INTEGER,opportunity_id INTEGER,followup_date TEXT NOT NULL,followup_type TEXT NOT NULL,subject TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Planned',assigned_to INTEGER,notes TEXT,created_at TEXT NOT NULL,updated_at TEXT,FOREIGN KEY(customer_id) REFERENCES customers(id),FOREIGN KEY(lead_id) REFERENCES leads(id),FOREIGN KEY(opportunity_id) REFERENCES opportunities(id),FOREIGN KEY(assigned_to) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS activities(id INTEGER PRIMARY KEY AUTOINCREMENT,code TEXT UNIQUE NOT NULL,activity_type TEXT NOT NULL,subject TEXT NOT NULL,description TEXT,activity_date TEXT NOT NULL,customer_id INTEGER,lead_id INTEGER,opportunity_id INTEGER,assigned_to INTEGER,status TEXT NOT NULL DEFAULT 'Open',created_at TEXT NOT NULL,FOREIGN KEY(customer_id) REFERENCES customers(id),FOREIGN KEY(lead_id) REFERENCES leads(id),FOREIGN KEY(opportunity_id) REFERENCES opportunities(id),FOREIGN KEY(assigned_to) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,action TEXT NOT NULL,entity_name TEXT NOT NULL,record_id TEXT,old_value TEXT,new_value TEXT,result TEXT NOT NULL DEFAULT 'Success',ip_address TEXT,created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));
CREATE INDEX IF NOT EXISTS ix_customers_owner ON customers(owner_id); CREATE INDEX IF NOT EXISTS ix_leads_owner ON leads(owner_id); CREATE INDEX IF NOT EXISTS ix_opps_owner ON opportunities(owner_id); CREATE INDEX IF NOT EXISTS ix_followups_date ON followups(followup_date,status);
'''

def now(): return datetime.now().isoformat(timespec='seconds')
def get_db():
    if 'db' not in g:
        g.db=sqlite3.connect(DB_PATH); g.db.row_factory=sqlite3.Row; g.db.execute('PRAGMA foreign_keys=ON'); g.db.execute('PRAGMA busy_timeout=5000')
    return g.db
@app.teardown_appcontext
def close_db(_):
    conn=g.pop('db',None)
    if conn: conn.close()
def init_db():
    conn=sqlite3.connect(DB_PATH); conn.execute('PRAGMA foreign_keys=ON'); conn.executescript(SCHEMA)
    # Safe forward migrations: older demo databases may lack fields used by the current forms.
    migrations = {
        'customers': {'code':'TEXT', 'address':'TEXT', 'city':'TEXT', 'state':'TEXT', 'updated_at':'TEXT', 'owner_id':'INTEGER', 'notes':'TEXT', 'company':'TEXT'},
        'leads': {'code':'TEXT', 'priority':"TEXT NOT NULL DEFAULT 'Medium'", 'expected_value':'REAL NOT NULL DEFAULT 0', 'owner_id':'INTEGER', 'notes':'TEXT', 'converted_customer_id':'INTEGER', 'updated_at':'TEXT'},
        'opportunities': {'code':'TEXT', 'customer_id':'INTEGER', 'lead_id':'INTEGER', 'status':"TEXT NOT NULL DEFAULT 'Open'", 'source':'TEXT', 'owner_id':'INTEGER', 'notes':'TEXT', 'updated_at':'TEXT'},
        'followups': {'code':'TEXT', 'customer_id':'INTEGER', 'lead_id':'INTEGER', 'opportunity_id':'INTEGER', 'followup_type':"TEXT NOT NULL DEFAULT 'Call'", 'status':"TEXT NOT NULL DEFAULT 'Planned'", 'assigned_to':'INTEGER', 'notes':'TEXT', 'updated_at':'TEXT'},
        'activities': {'code':'TEXT', 'description':'TEXT', 'customer_id':'INTEGER', 'lead_id':'INTEGER', 'opportunity_id':'INTEGER', 'assigned_to':'INTEGER', 'status':"TEXT NOT NULL DEFAULT 'Open'"},
        'users': {'active':'INTEGER NOT NULL DEFAULT 1', 'failed_count':'INTEGER NOT NULL DEFAULT 0', 'lockout_until':'TEXT'},
    }
    for table, columns in migrations.items():
        existing={row[1] for row in conn.execute(f'PRAGMA table_info({table})').fetchall()}
        for column, declaration in columns.items():
            if column not in existing:
                conn.execute(f'ALTER TABLE {table} ADD COLUMN {column} {declaration}')
    # Backfill record codes for databases created by earlier versions.
    # Older versions did not always create the `code` column, so add it above
    # and assign stable identifiers before any seeded inserts run.
    code_prefixes = {'customers':'CUS', 'leads':'LED', 'opportunities':'OPP', 'followups':'FUP', 'activities':'ACT'}
    for table, prefix in code_prefixes.items():
        cols = {row[1] for row in conn.execute(f'PRAGMA table_info({table})').fetchall()}
        if 'code' in cols:
            for rec in conn.execute(f'SELECT id FROM {table} WHERE code IS NULL OR TRIM(code)=\'\'').fetchall():
                conn.execute(f'UPDATE {table} SET code=? WHERE id=?', (f'{prefix}-MIG-{rec[0]:04d}', rec[0]))
            conn.execute(f'CREATE UNIQUE INDEX IF NOT EXISTS ux_{table}_code ON {table}(code)')

    demo=[('System Administrator','admin@acxiomcrm.local','2468','Admin'),('Sales Manager','manager@acxiomcrm.local','1357','Manager'),('Sales Executive','sales@acxiomcrm.local','2026','Sales Executive')]
    for n,e,pin,r in demo:
        conn.execute('INSERT OR IGNORE INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)',(n,e,generate_password_hash(pin),r,now()))
        conn.execute('UPDATE users SET password_hash=?,active=1 WHERE email=?',(generate_password_hash(pin),e))

    # Seed a complete, fictional demonstration workspace only when the CRM is empty.
    # Existing customer/business data is never overwritten or duplicated by this seed.
    if conn.execute('SELECT COUNT(*) FROM customers').fetchone()[0] == 0 and conn.execute('SELECT COUNT(*) FROM leads').fetchone()[0] == 0:
        admin_id=conn.execute("SELECT id FROM users WHERE email='admin@acxiomcrm.local'").fetchone()[0]
        manager_id=conn.execute("SELECT id FROM users WHERE email='manager@acxiomcrm.local'").fetchone()[0]
        sales_id=conn.execute("SELECT id FROM users WHERE email='sales@acxiomcrm.local'").fetchone()[0]
        demo_customers=[
          ('CUS-1001','Aarav Sharma','aarav.sharma@example.com','9876543210','BrightTech Solutions','MG Road','Bengaluru','Karnataka','Active',sales_id,'Annual CRM subscription; decision maker is operations head.'),
          ('CUS-1002','Priya Reddy','priya.reddy@example.com','9876543211','GreenLeaf Retail','Banjara Hills','Hyderabad','Telangana','Active',manager_id,'Interested in enterprise package; requested pricing.'),
          ('CUS-1003','Rahul Verma','rahul.verma@example.com','9876543212','Vertex Manufacturing','Anna Salai','Chennai','Tamil Nadu','Prospect',sales_id,'Requested a product demonstration.'),
          ('CUS-1004','Sneha Nair','sneha.nair@example.com','9876543213','BluePeak Services','Marine Drive','Kochi','Kerala','Active',manager_id,'Existing customer; interested in support renewal.'),
          ('CUS-1005','Ananya Das','ananya.das@example.com','9876543215','Aster Digital','Salt Lake','Kolkata','West Bengal','Active',sales_id,'Needs CRM for a 20-member sales team.'),
          ('CUS-1006','Vikram Patel','vikram.patel@example.com','9876543216','Orbit Logistics','SG Highway','Ahmedabad','Gujarat','Active',manager_id,'Interested in pipeline and reporting features.')]
        for row in demo_customers:
            conn.execute('INSERT INTO customers(code,name,email,phone,company,address,city,state,status,owner_id,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(*row,now()))
        customer_ids={r[1]:r[0] for r in conn.execute('SELECT id,name FROM customers').fetchall()}
        demo_leads=[
          ('LED-2001','Kiran Mehta','kiran.mehta@example.com','9876500001','Mehta Traders','Website','Qualified','High',85000,sales_id,'Requested a formal sales proposal.'),
          ('LED-2002','Divya Rao','divya.rao@example.com','9876500002','Rao Distributors','Referral','Contacted','Medium',45000,manager_id,'Schedule a discovery call.'),
          ('LED-2003','Arjun Das','arjun.das@example.com','9876500003','Das Retail','Campaign','New','Low',25000,sales_id,'New enquiry from email campaign.'),
          ('LED-2004','Meera Joshi','meera.joshi@example.com','9876500004','Joshi Technologies','LinkedIn','Qualified','High',120000,manager_id,'Interested in enterprise plan.'),
          ('LED-2005','Fatima Khan','fatima.khan@example.com','9876500006','Khan Healthcare','Website','New','High',150000,sales_id,'Needs a CRM demonstration.')]
        for row in demo_leads:
            conn.execute('INSERT INTO leads(code,name,email,phone,company,source,status,priority,expected_value,owner_id,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(*row,now()))
        lead_ids={r[1]:r[0] for r in conn.execute('SELECT id,name FROM leads').fetchall()}
        demo_opps=[
          ('OPP-3001','BrightTech Annual Contract',customer_ids['Aarav Sharma'],None,150000,'Proposal',70,'2026-12-15','Website',sales_id,'Annual CRM rollout and onboarding.'),
          ('OPP-3002','GreenLeaf CRM Rollout',customer_ids['Priya Reddy'],None,90000,'Negotiation',85,'2026-12-05','Referral',manager_id,'Commercial terms under discussion.'),
          ('OPP-3003','Vertex Support Package',customer_ids['Rahul Verma'],None,60000,'Qualification',30,'2027-01-20','Event',sales_id,'Confirm scope and support requirements.'),
          ('OPP-3004','Joshi Enterprise License',None,lead_ids['Meera Joshi'],200000,'Proposal',60,'2027-01-15','LinkedIn',manager_id,'Enterprise license proposal submitted.'),
          ('OPP-3005','Orbit Logistics CRM',customer_ids['Vikram Patel'],None,125000,'Negotiation',75,'2026-12-20','Referral',manager_id,'Final pricing review pending.')]
        for row in demo_opps:
            conn.execute('INSERT INTO opportunities(code,name,customer_id,lead_id,amount,stage,probability,expected_close_date,source,owner_id,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(*row,now()))
        opp_ids={r[1]:r[0] for r in conn.execute('SELECT id,name FROM opportunities').fetchall()}
        demo_followups=[
          ('FUP-4001',customer_ids['Aarav Sharma'],None,opp_ids['BrightTech Annual Contract'],'2026-11-06','Call','Discuss annual subscription','Planned',sales_id,'Share pricing and confirm user count.'),
          ('FUP-4002',customer_ids['Rahul Verma'],None,opp_ids['Vertex Support Package'],'2026-11-07','Meeting','Product demonstration','Planned',sales_id,'Prepare demo environment.'),
          ('FUP-4003',customer_ids['Priya Reddy'],None,opp_ids['GreenLeaf CRM Rollout'],'2026-11-10','Email','Send enterprise proposal','Planned',manager_id,'Attach quotation and implementation timeline.'),
          ('FUP-4004',None,lead_ids['Fatima Khan'],None,'2026-11-12','Call','Qualify healthcare enquiry','Planned',sales_id,'Confirm clinic count and user requirements.')]
        for row in demo_followups:
            conn.execute('INSERT INTO followups(code,customer_id,lead_id,opportunity_id,followup_date,followup_type,subject,status,assigned_to,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(*row,now()))
        demo_activities=[
          ('ACT-5001','Call','Initial customer discussion','Discussed CRM requirements and current sales process.','2026-11-03',customer_ids['Aarav Sharma'],None,None,sales_id,'Completed'),
          ('ACT-5002','Task','Send commercial proposal','Prepare and email the commercial proposal.','2026-11-06',customer_ids['Priya Reddy'],None,None,manager_id,'Open'),
          ('ACT-5003','Meeting','Product walkthrough','Demonstrate customer, lead and reporting modules.','2026-11-07',customer_ids['Rahul Verma'],None,None,sales_id,'Planned'),
          ('ACT-5004','Email','Share pricing details','Send pricing and subscription details.','2026-11-08',None,lead_ids['Kiran Mehta'],None,sales_id,'Planned')]
        for row in demo_activities:
            conn.execute('INSERT INTO activities(code,activity_type,subject,description,activity_date,customer_id,lead_id,opportunity_id,assigned_to,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(*row,now()))
    conn.commit(); conn.close()
def audit(action,entity,record_id=None,old=None,new=None,result='Success'):
    get_db().execute('INSERT INTO audit_logs(user_id,action,entity_name,record_id,old_value,new_value,result,ip_address,created_at) VALUES(?,?,?,?,?,?,?,?,?)',
      (session.get('uid'),action,entity,str(record_id) if record_id is not None else None,json.dumps(old,default=str) if old is not None else None,json.dumps(new,default=str) if new is not None else None,result,request.remote_addr,now()))
    get_db().commit()
def user():
    if not session.get('uid'): return None
    return get_db().execute('SELECT id,name,email,role,active FROM users WHERE id=? AND active=1',(session['uid'],)).fetchone()
def auth(fn):
    @wraps(fn)
    def w(*a,**kw):
        if not user(): return jsonify(error='Authentication required.'),401
        return fn(*a,**kw)
    return w
def roles(*allowed):
    def deco(fn):
        @wraps(fn)
        @auth
        def w(*a,**kw):
            if user()['role'] not in allowed: return jsonify(error='You do not have permission to perform this action.'),403
            return fn(*a,**kw)
        return w
    return deco
def scope(kind,alias=''):
    u=user(); prefix=(alias+'.') if alias else ''
    if not u or u['role'] in ('Admin','Manager'): return '',[]
    col='assigned_to' if kind in ('followups','activities') else 'owner_id'
    return f' AND {prefix}{col}=?',[u['id']]
def body(): return request.get_json(silent=True) or request.form.to_dict()
def txt(v,label,required=False,maxlen=180):
    v=(v or '').strip()
    if required and not v: raise ValueError(f'{label} is required.')
    if len(v)>maxlen: raise ValueError(f'{label} must be {maxlen} characters or fewer.')
    return v
def email(v,required=False):
    v=(v or '').strip().lower()
    if required and not v: raise ValueError('Email is required.')
    if v and (len(v)>254 or not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',v)): raise ValueError('Enter a valid email address.')
    return v
def phone(v,required=False):
    v=re.sub(r'[\s+()-]','',(v or '').strip())
    if required and not v: raise ValueError('Phone is required.')
    if v and not re.fullmatch(r'\d{10,13}',v): raise ValueError('Enter a valid phone number (10–13 digits).')
    return v
def date_value(v,label,required=True):
    v=(v or '').strip()
    if required and not v: raise ValueError(f'{label} is required.')
    if v:
        try: date.fromisoformat(v)
        except ValueError: raise ValueError(f'{label} must be a valid date.')
    return v
def integer(v,label,lo=None,hi=None,default=0):
    try: n=int(v if v not in (None,'') else default)
    except (ValueError,TypeError): raise ValueError(f'{label} must be a whole number.')
    if lo is not None and n<lo or hi is not None and n>hi: raise ValueError(f'{label} must be between {lo} and {hi}.')
    return n
def number(v,label,lo=None):
    try: n=float(v if v not in (None,'') else 0)
    except (ValueError,TypeError): raise ValueError(f'{label} must be numeric.')
    if n!=n or n in (float('inf'),float('-inf')) or (lo is not None and n<lo): raise ValueError(f'{label} must be at least {lo}.')
    return n

def owner_id(d):
    u=user()
    if u['role']=='Sales Executive': return u['id']
    try: oid=int(d.get('owner_id') or u['id'])
    except (ValueError,TypeError): raise ValueError('Select a valid record owner.')
    if not get_db().execute('SELECT id FROM users WHERE id=? AND active=1',(oid,)).fetchone():
        raise ValueError('Selected owner is not an active application user.')
    return oid

@app.after_request
def headers(resp):
    resp.headers['X-Content-Type-Options']='nosniff'; resp.headers['X-Frame-Options']='DENY'; resp.headers['Referrer-Policy']='same-origin'; resp.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
    return resp
@app.before_request
def csrf_check():
    if request.method in ('POST','PUT','PATCH','DELETE') and request.path.startswith('/api/') and request.path not in ('/api/login','/api/register'):
        if session.get('uid') and request.headers.get('X-CSRF-Token')!=session.get('csrf'): return jsonify(error='Security token expired. Refresh the page and try again.'),400

@app.get('/')
def home(): return render_template_string(HTML)
@app.get('/api/me')
def me(): return jsonify(user=dict(user()) if user() else None,csrf=session.get('csrf'))
@app.post('/api/register')
def register():
    d=body()
    try:
        n=txt(d.get('name'),'Name',True,100); e=email(d.get('email'),True); p=d.get('password') or ''
        if not re.fullmatch(r'\d{4}',p): raise ValueError('PIN must contain exactly 4 digits.')
        cur=get_db().execute('INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)',(n,e,generate_password_hash(p),'Sales Executive',now())); get_db().commit(); audit('REGISTER','User',cur.lastrowid,new={'email':e})
        return jsonify(message='Account created. An administrator can assign additional access.'),201
    except (ValueError,sqlite3.IntegrityError) as ex: return jsonify(error=str(ex) if isinstance(ex,ValueError) else 'That email address is already registered.'),400
@app.post('/api/login')
def login():
    d=body(); e=(d.get('email') or d.get('username') or '').strip().lower(); p=d.get('password') or ''; aliases={'admin':'admin@acxiomcrm.local','manager':'manager@acxiomcrm.local','sales':'sales@acxiomcrm.local','sales executive':'sales@acxiomcrm.local'}; e=aliases.get(e,e); row=get_db().execute('SELECT * FROM users WHERE email=?',(e,)).fetchone(); current=datetime.now()
    if not row: audit('LOGIN_FAILED','Authentication',e,result='Failed'); return jsonify(error='Invalid email or password.'),401
    if not row['active']: return jsonify(error='This account is inactive. Contact an administrator.'),403
    if row['lockout_until'] and datetime.fromisoformat(row['lockout_until'])>current: return jsonify(error='Account temporarily locked after repeated attempts. Try again later.'),423
    if not check_password_hash(row['password_hash'],p):
        count=row['failed_count']+1; lock=(current+timedelta(minutes=15)).isoformat(timespec='seconds') if count>=5 else None
        get_db().execute('UPDATE users SET failed_count=?,lockout_until=? WHERE id=?',(count,lock,row['id'])); get_db().commit(); audit('LOGIN_FAILED','Authentication',row['id'],result='Failed')
        return jsonify(error='Invalid email or password.'),401
    get_db().execute('UPDATE users SET failed_count=0,lockout_until=NULL WHERE id=?',(row['id'],)); get_db().commit(); session.clear(); session['uid']=row['id']; session['csrf']=secrets.token_urlsafe(32); session.permanent=True; audit('LOGIN','Authentication',row['id'])
    return jsonify(message='Welcome back.',user=dict(user()),csrf=session['csrf'])
@app.post('/api/logout')
@auth
def logout(): audit('LOGOUT','Authentication',session.get('uid')); session.clear(); return jsonify(message='Signed out.')

CONFIG={
'customers':{'table':'customers','fields':['name','email','phone','company','address','city','state','status','notes'],'title':'Customers'},
'leads':{'table':'leads','fields':['name','email','phone','company','source','status','priority','expected_value','notes'],'title':'Leads'},
'opportunities':{'table':'opportunities','fields':['name','customer_id','lead_id','amount','stage','probability','expected_close_date','source','notes'],'title':'Opportunities'},
'followups':{'table':'followups','fields':['customer_id','lead_id','opportunity_id','followup_date','followup_type','subject','status','notes'],'title':'Follow-ups'},
'activities':{'table':'activities','fields':['activity_type','subject','description','activity_date','customer_id','lead_id','opportunity_id','status'],'title':'Activities'}}
def validate(kind,d):
    if kind=='customers':
        d.update(name=txt(d.get('name'),'Customer name',True,120),email=email(d.get('email'),True),phone=phone(d.get('phone'),True),company=txt(d.get('company'),'Company',False,120),address=txt(d.get('address'),'Address',False,250),city=txt(d.get('city'),'City',False,80),state=txt(d.get('state'),'State',False,80),status=d.get('status') or 'Active',notes=txt(d.get('notes'),'Notes',False,1500))
        if d['status'] not in STATUSES[kind]: raise ValueError('Choose a valid customer status.')
    elif kind=='leads':
        d.update(name=txt(d.get('name'),'Lead name',True,120),email=email(d.get('email')),phone=phone(d.get('phone')),company=txt(d.get('company'),'Company',False,120),source=txt(d.get('source'),'Source',False,100),status=d.get('status') or 'New',priority=d.get('priority') or 'Medium',expected_value=number(d.get('expected_value'),'Expected value',0),notes=txt(d.get('notes'),'Notes',False,1500))
        if d['status'] not in STATUSES[kind]: raise ValueError('Choose a valid lead status.')
        if d['priority'] not in ('Low','Medium','High'): raise ValueError('Choose a valid priority.')
    elif kind=='opportunities':
        d.update(name=txt(d.get('name'),'Opportunity name',True,150),amount=number(d.get('amount'),'Amount',0.01),probability=integer(d.get('probability'),'Probability',0,100),stage=d.get('stage') or 'Qualification',expected_close_date=date_value(d.get('expected_close_date'),'Expected close date'),source=txt(d.get('source'),'Source',False,100),notes=txt(d.get('notes'),'Notes',False,1500))
        if d['stage'] not in STATUSES[kind]: raise ValueError('Choose a valid opportunity stage.')
        if d['stage'] not in ('Won','Lost') and d['expected_close_date']<date.today().isoformat(): raise ValueError('Expected close date cannot be in the past for an active opportunity.')
        d['status']='Closed' if d['stage'] in ('Won','Lost') else 'Open'
    elif kind=='followups':
        d.update(subject=txt(d.get('subject'),'Subject',True,150),followup_date=date_value(d.get('followup_date'),'Follow-up date'),followup_type=d.get('followup_type') or 'Call',status=d.get('status') or 'Planned',notes=txt(d.get('notes'),'Notes',False,1500))
        if d['status'] not in STATUSES[kind]: raise ValueError('Choose a valid follow-up status.')
        if d['followup_type'] not in ACTIVITY_TYPES: raise ValueError('Choose a valid follow-up type.')
        if d['status']=='Planned' and d['followup_date']<date.today().isoformat(): raise ValueError('A planned follow-up cannot be dated in the past.')
    elif kind=='activities':
        d.update(activity_type=d.get('activity_type') or 'Task',subject=txt(d.get('subject'),'Subject',True,150),description=txt(d.get('description'),'Description',False,1500),activity_date=date_value(d.get('activity_date'),'Activity date'),status=d.get('status') or 'Open')
        if d['activity_type'] not in ACTIVITY_TYPES: raise ValueError('Choose a valid activity type.')
        if d['status'] not in STATUSES[kind]: raise ValueError('Choose a valid activity status.')
    for f in ('customer_id','lead_id','opportunity_id'):
        if f in CONFIG[kind]['fields']:
            val=d.get(f); d[f]=int(val) if val not in (None,'') else None
            if d[f] is not None:
                table=f.replace('_id','')+'s'
                if table=='opportunitys': table='opportunities'
                related_kind={'customers':'customers','leads':'leads','opportunities':'opportunities'}[table]
                if not visible_record(related_kind,d[f]): raise ValueError(f'Selected {f.replace("_id", "")} does not exist or is outside your access scope.')
    return d

def visible_record(kind,rid):
    table=CONFIG[kind]['table']; w,p=scope(kind)
    return get_db().execute(f'SELECT * FROM {table} WHERE id=?{w}',[rid]+p).fetchone()
@app.route('/api/<kind>',methods=['GET','POST'])
@auth
def collection(kind):
    if kind not in CONFIG: return jsonify(error='Unknown CRM module.'),404
    table=CONFIG[kind]['table']; w,p=scope(kind)
    if request.method=='GET':
        q=(request.args.get('q') or '').strip()[:100]; limit=min(max(int(request.args.get('limit',100)),1),500); offset=max(int(request.args.get('offset',0)),0)
        search=''
        if q: search=' AND ('+' OR '.join(f"CAST({c} AS TEXT) LIKE ?" for c in CONFIG[kind]['fields'] if c not in ('notes','description'))+')'; p += [f'%{q}%']*sum(c not in ('notes','description') for c in CONFIG[kind]['fields'])
        rows=get_db().execute(f'SELECT * FROM {table} WHERE 1=1{w}{search} ORDER BY id DESC LIMIT ? OFFSET ?',p+[limit,offset]).fetchall()
        return jsonify(items=[dict(x) for x in rows],limit=limit,offset=offset)
    d=body()
    try:
        d=validate(kind,d); fields=CONFIG[kind]['fields']; vals=[d.get(f) for f in fields]; cols=list(fields)
        if kind in ('customers','leads','opportunities'): cols.append('owner_id'); vals.append(owner_id(d))
        else: cols.append('assigned_to'); vals.append(owner_id(d))
        cols += ['code','created_at']; vals += [kind[:3].upper()+'-'+secrets.token_hex(3).upper(),now()]
        if kind=='customers' and get_db().execute('SELECT id FROM customers WHERE email=? OR phone=?',(d['email'],d['phone'])).fetchone(): raise ValueError('A customer with this email or phone already exists.')
        cur=get_db().execute(f"INSERT INTO {table}({','.join(cols)}) VALUES({','.join('?' for _ in cols)})",vals); get_db().commit(); audit('CREATE',kind,cur.lastrowid,new=d)
        return jsonify(message=f'{CONFIG[kind]["title"][:-1]} created.',id=cur.lastrowid),201
    except (ValueError,sqlite3.IntegrityError) as ex: return jsonify(error=str(ex) if isinstance(ex,ValueError) else 'A duplicate or invalid relationship was detected.'),400
@app.route('/api/<kind>/<int:rid>',methods=['GET','PUT','DELETE'])
@auth
def item(kind,rid):
    if kind not in CONFIG: return jsonify(error='Unknown CRM module.'),404
    old=visible_record(kind,rid)
    if not old: return jsonify(error='Record not found or access denied.'),404
    if request.method=='GET': return jsonify(item=dict(old))
    if request.method=='DELETE':
        if kind=='customers' and get_db().execute('SELECT 1 FROM opportunities WHERE customer_id=?',(rid,)).fetchone(): return jsonify(error='This customer has linked opportunities. Deactivate the customer instead.'),409
        get_db().execute(f"DELETE FROM {CONFIG[kind]['table']} WHERE id=?",(rid,)); get_db().commit(); audit('DELETE',kind,rid,old=dict(old)); return jsonify(message='Record deleted.')
    d=body()
    try:
        d=validate(kind,d); fields=CONFIG[kind]['fields']; sets=[f'{f}=?' for f in fields]; vals=[d.get(f) for f in fields]
        if kind in ('customers','leads','opportunities') and user()['role']!='Sales Executive': sets.append('owner_id=?'); vals.append(owner_id(d))
        if kind in ('followups','activities'): sets.append('assigned_to=?'); vals.append(owner_id(d))
        if kind=='customers' and get_db().execute('SELECT id FROM customers WHERE (email=? OR phone=?) AND id<>?',(d['email'],d['phone'],rid)).fetchone(): raise ValueError('Another customer already uses this email or phone.')
        sets.append('updated_at=?'); vals.extend([now(),rid]); get_db().execute(f"UPDATE {CONFIG[kind]['table']} SET {','.join(sets)} WHERE id=?",vals); get_db().commit(); audit('UPDATE',kind,rid,old=dict(old),new=d)
        return jsonify(message='Record updated.')
    except (ValueError,sqlite3.IntegrityError) as ex: return jsonify(error=str(ex) if isinstance(ex,ValueError) else 'Duplicate or invalid relationship.'),400

@app.post('/api/leads/<int:rid>/convert')
@auth
def convert_lead(rid):
    lead=visible_record('leads',rid)
    if not lead: return jsonify(error='Lead not found or access denied.'),404
    if lead['status']=='Converted' or lead['converted_customer_id']: return jsonify(error='This lead has already been converted.'),409
    try:
        if not lead['email'] or not lead['phone']: return jsonify(error='Lead must have an email and phone before conversion.'),400
        cur=get_db().execute('INSERT INTO customers(code,name,email,phone,company,status,owner_id,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?)',('CUS-'+secrets.token_hex(3).upper(),lead['name'],lead['email'],lead['phone'],lead['company'],'Active',lead['owner_id'],f'Converted from lead {lead["code"]}',now()))
        cid=cur.lastrowid; get_db().execute("UPDATE leads SET status='Converted',converted_customer_id=?,updated_at=? WHERE id=?",(cid,now(),rid)); get_db().commit(); audit('CONVERT','Lead',rid,old={'status':lead['status']},new={'customer_id':cid,'status':'Converted'})
        return jsonify(message='Lead converted to customer.',customer_id=cid),201
    except sqlite3.IntegrityError: return jsonify(error='A customer with this lead email or phone already exists.'),409

@app.get('/api/dashboard')
@auth
def dashboard():
    def count(table,extra=''):
        w,p=scope(table); return get_db().execute(f'SELECT COUNT(*) n FROM {table} WHERE 1=1{w} {extra}',p).fetchone()['n']
    w,p=scope('opportunities'); pipe=get_db().execute(f"SELECT COALESCE(SUM(amount),0) v,COALESCE(SUM(amount*probability/100.0),0) weighted FROM opportunities WHERE stage NOT IN ('Won','Lost'){w}",p).fetchone()
    fw,fp=scope('followups'); upcoming=get_db().execute(f"SELECT COUNT(*) n FROM followups WHERE status='Planned' AND followup_date>=?{fw}",[date.today().isoformat()]+fp).fetchone()['n']
    overdue=get_db().execute(f"SELECT COUNT(*) n FROM followups WHERE status='Planned' AND followup_date<?{fw}",[date.today().isoformat()]+fp).fetchone()['n']
    stages=get_db().execute(f'SELECT stage,COUNT(*) count,COALESCE(SUM(amount),0) amount FROM opportunities WHERE 1=1{w} GROUP BY stage',p).fetchall()
    leads=get_db().execute(f'SELECT status,COUNT(*) count FROM leads WHERE 1=1{scope("leads")[0]} GROUP BY status',scope('leads')[1]).fetchall()
    recent=get_db().execute(f"SELECT 'Customer' type,name title,created_at FROM customers WHERE 1=1{scope('customers')[0]} UNION ALL SELECT 'Lead',name,created_at FROM leads WHERE 1=1{scope('leads')[0]} ORDER BY created_at DESC LIMIT 7",scope('customers')[1]+scope('leads')[1]).fetchall()
    return jsonify(kpis={'customers':count('customers'),'leads':count('leads'), 'open_opportunities':count('opportunities',"AND stage NOT IN ('Won','Lost')"),'won':count('opportunities',"AND stage='Won'"),'upcoming_followups':upcoming,'overdue_followups':overdue,'pipeline':pipe['v'],'weighted_pipeline':pipe['weighted']},stages=[dict(x) for x in stages],lead_status=[dict(x) for x in leads],recent=[dict(x) for x in recent],role=user()['role'])

@app.get('/api/lookups')
@auth
def lookups():
    result={}
    for table in ('customers','leads','opportunities'):
        w,p=scope(table); result[table]=[dict(x) for x in get_db().execute(f'SELECT id,code,name FROM {table} WHERE 1=1{w} ORDER BY name LIMIT 500',p).fetchall()]
    result['users']=[dict(x) for x in get_db().execute('SELECT id,name,role FROM users WHERE active=1 ORDER BY name').fetchall()] if user()['role'] in ('Admin','Manager') else [{'id':user()['id'],'name':user()['name'],'role':user()['role']}]
    return jsonify(result)

@app.get('/api/users')
@roles('Admin')
def users_list(): return jsonify(items=[dict(x) for x in get_db().execute('SELECT id,name,email,role,active,failed_count,lockout_until,created_at FROM users ORDER BY id DESC').fetchall()])
@app.post('/api/users')
@roles('Admin')
def user_create():
    d=body()
    try:
        n=txt(d.get('name'),'Name',True,100); e=email(d.get('email'),True); p=d.get('password') or ''; r=d.get('role')
        if r not in ROLES: raise ValueError('Choose a valid role.')
        if not re.fullmatch(r'\d{4}',p): raise ValueError('PIN must contain exactly 4 digits.')
        cur=get_db().execute('INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)',(n,e,generate_password_hash(p),r,now())); get_db().commit(); audit('CREATE','User',cur.lastrowid,new={'email':e,'role':r}); return jsonify(message='User created.'),201
    except (ValueError,sqlite3.IntegrityError) as ex: return jsonify(error=str(ex) if isinstance(ex,ValueError) else 'Email already exists.'),400
@app.patch('/api/users/<int:uid>')
@roles('Admin')
def user_update(uid):
    d=body(); row=get_db().execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
    if not row: return jsonify(error='User not found.'),404
    role=d.get('role',row['role']); active=1 if str(d.get('active',row['active'])).lower() in ('1','true','yes') else 0
    if role not in ROLES: return jsonify(error='Invalid role.'),400
    if uid==user()['id'] and (not active or role!='Admin'): return jsonify(error='You cannot deactivate or remove your own administrator access.'),400
    get_db().execute('UPDATE users SET role=?,active=? WHERE id=?',(role,active,uid)); get_db().commit(); audit('USER_UPDATE','User',uid,old={'role':row['role'],'active':row['active']},new={'role':role,'active':active}); return jsonify(message='User updated.')
@app.post('/api/users/<int:uid>/reset-password')
@roles('Admin')
def user_reset(uid):
    p=body().get('password') or ''
    if not re.fullmatch(r'\d{4}',p): return jsonify(error='PIN must contain exactly 4 digits.'),400
    if not get_db().execute('SELECT id FROM users WHERE id=?',(uid,)).fetchone(): return jsonify(error='User not found.'),404
    get_db().execute('UPDATE users SET password_hash=?,failed_count=0,lockout_until=NULL WHERE id=?',(generate_password_hash(p),uid)); get_db().commit(); audit('PASSWORD_RESET','User',uid); return jsonify(message='Password reset successfully.')
@app.get('/api/audit')
@roles('Admin')
def audit_list():
    q=(request.args.get('q') or '')[:80]; rows=get_db().execute('SELECT a.*,u.name user_name FROM audit_logs a LEFT JOIN users u ON a.user_id=u.id WHERE a.action LIKE ? OR a.entity_name LIKE ? OR COALESCE(u.name,\'\') LIKE ? ORDER BY a.id DESC LIMIT 500',(f'%{q}%',f'%{q}%',f'%{q}%')).fetchall(); return jsonify(items=[dict(x) for x in rows])
@app.get('/api/reports/<report>')
@auth
def reports(report):
    if report=='pipeline':
        w,p=scope('opportunities'); rows=get_db().execute(f'SELECT stage,COUNT(*) count,SUM(amount) amount,SUM(amount*probability/100.0) weighted FROM opportunities WHERE 1=1{w} GROUP BY stage ORDER BY stage',p).fetchall(); return jsonify(items=[dict(x) for x in rows])
    if report=='conversion':
        w,p=scope('leads'); rows=get_db().execute(f"SELECT status,COUNT(*) count,COALESCE(SUM(expected_value),0) value FROM leads WHERE 1=1{w} GROUP BY status",p).fetchall(); return jsonify(items=[dict(x) for x in rows])
    if report=='user-activity':
        if user()['role'] not in ('Admin','Manager'): return jsonify(error='Manager or Admin access required.'),403
        rows=get_db().execute('SELECT u.name,COUNT(a.id) activity_count FROM users u LEFT JOIN audit_logs a ON a.user_id=u.id GROUP BY u.id ORDER BY activity_count DESC').fetchall(); return jsonify(items=[dict(x) for x in rows])
    if report not in CONFIG: return jsonify(error='Unknown report.'),404
    table=CONFIG[report]['table']; w,p=scope(report); rows=get_db().execute(f'SELECT * FROM {table} WHERE 1=1{w} ORDER BY id DESC LIMIT 1000',p).fetchall(); return jsonify(items=[dict(x) for x in rows])
@app.get('/api/export/<report>.csv')
@auth
def export_csv(report):
    if report not in CONFIG and report not in ('pipeline','conversion'): return jsonify(error='Unknown report.'),404
    data=reports_data(report)
    if isinstance(data,tuple): return data
    output=io.StringIO(); fields=list(data[0].keys()) if data else ['No records']; writer=csv.DictWriter(output,fieldnames=fields); writer.writeheader(); writer.writerows(data)
    resp=make_response(output.getvalue()); resp.headers['Content-Type']='text/csv; charset=utf-8'; resp.headers['Content-Disposition']=f'attachment; filename=acxiomcrm-{report}-{date.today()}.csv'; return resp
def reports_data(report):
    if report=='pipeline':
        w,p=scope('opportunities'); return [dict(x) for x in get_db().execute(f'SELECT stage,COUNT(*) count,SUM(amount) amount,SUM(amount*probability/100.0) weighted FROM opportunities WHERE 1=1{w} GROUP BY stage',p).fetchall()]
    if report=='conversion':
        w,p=scope('leads'); return [dict(x) for x in get_db().execute(f'SELECT status,COUNT(*) count,COALESCE(SUM(expected_value),0) value FROM leads WHERE 1=1{w} GROUP BY status',p).fetchall()]
    w,p=scope(report); return [dict(x) for x in get_db().execute(f'SELECT * FROM {CONFIG[report]["table"]} WHERE 1=1{w} ORDER BY id DESC LIMIT 5000',p).fetchall()]
@app.post('/api/import/<kind>')
@auth
def import_csv(kind):
    """Import CSV rows into a CRM module. Required column names match the Add form."""
    if kind not in CONFIG: return jsonify(error='Unknown CRM module.'),404
    upload=request.files.get('file')
    if not upload or not upload.filename: return jsonify(error='Choose a CSV file first.'),400
    if not upload.filename.lower().endswith('.csv'): return jsonify(error='Please upload a .csv file. Excel files should be saved as CSV first.'),400
    try:
        raw=upload.stream.read(2*1024*1024+1)
        if len(raw)>2*1024*1024: return jsonify(error='CSV file must be 2 MB or smaller.'),413
        text_data=raw.decode('utf-8-sig')
        reader=csv.DictReader(io.StringIO(text_data))
        if not reader.fieldnames: return jsonify(error='CSV file must contain a header row.'),400
        allowed=set(CONFIG[kind]['fields'])
        missing=[]
        if kind=='customers': missing=[x for x in ('name','email','phone') if x not in reader.fieldnames]
        elif kind=='leads': missing=['name'] if 'name' not in reader.fieldnames else []
        elif kind=='opportunities': missing=[x for x in ('name','amount','stage','probability','expected_close_date') if x not in reader.fieldnames]
        elif kind=='followups': missing=[x for x in ('subject','followup_date','followup_type') if x not in reader.fieldnames]
        elif kind=='activities': missing=[x for x in ('subject','activity_type','activity_date') if x not in reader.fieldnames]
        if missing: return jsonify(error='Missing required CSV columns: '+', '.join(missing)),400
        imported=0; skipped=[]
        for line,row in enumerate(reader, start=2):
            if imported+len(skipped)>=1000: skipped.append({'row':line,'error':'Import limit is 1,000 rows.'}); break
            d={k:(row.get(k) or '').strip() for k in allowed if k in row}
            try:
                d=validate(kind,d)
                cols=list(CONFIG[kind]['fields']); vals=[d.get(f) for f in cols]
                if kind in ('customers','leads','opportunities'): cols.append('owner_id'); vals.append(owner_id(d))
                else: cols.append('assigned_to'); vals.append(owner_id(d))
                cols += ['code','created_at']; vals += [kind[:3].upper()+'-'+secrets.token_hex(3).upper(),now()]
                if kind=='customers' and get_db().execute('SELECT id FROM customers WHERE email=? OR phone=?',(d['email'],d['phone'])).fetchone():
                    raise ValueError('Duplicate customer email or phone.')
                get_db().execute(f"INSERT INTO {CONFIG[kind]['table']}({','.join(cols)}) VALUES({','.join('?' for _ in cols)})",vals)
                imported+=1
            except (ValueError,sqlite3.IntegrityError) as ex:
                skipped.append({'row':line,'error':str(ex) if isinstance(ex,ValueError) else 'Duplicate or invalid linked record.'})
        get_db().commit(); audit('IMPORT',kind,None,new={'imported':imported,'skipped':len(skipped),'filename':upload.filename})
        return jsonify(message=f'Imported {imported} {kind} record(s).',imported=imported,skipped=skipped,skipped_count=len(skipped)),200
    except UnicodeDecodeError: return jsonify(error='CSV encoding not supported. Save the file as UTF-8 CSV and try again.'),400
    except Exception as ex:
        get_db().rollback(); app.logger.exception('CSV import failed')
        return jsonify(error=f'Import failed: {type(ex).__name__}: {ex}'),500

@app.get('/api/template/<kind>.csv')
@auth
def csv_template(kind):
    if kind not in CONFIG: return jsonify(error='Unknown CRM module.'),404
    fields=CONFIG[kind]['fields']; output=io.StringIO(); csv.writer(output).writerow(fields)
    resp=make_response(output.getvalue()); resp.headers['Content-Type']='text/csv; charset=utf-8'; resp.headers['Content-Disposition']=f'attachment; filename=acxiomcrm-{kind}-template.csv'; return resp

@app.get('/api/health')
def health(): return jsonify(status='ok',application='AcxiomCRM',version='2.1')

HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AcxiomCRM | Enterprise Sales Workspace</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@500;600;700;800&display=swap" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root{--navy:#101c34;--navy2:#192b4a;--blue:#4169e1;--blue2:#3155c8;--teal:#12a88a;--ink:#17243b;--muted:#7b879b;--bg:#f4f6fb;--line:#e7ebf3;--white:#fff;--shadow:0 8px 26px rgba(22,39,69,.055)}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px 'DM Sans',sans-serif}h1,h2,h3,h4,h5,.brand{font-family:Manrope,sans-serif;letter-spacing:-.45px}.login-wrap{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 18% 20%,#294b83 0,transparent 35%),linear-gradient(135deg,#0d1930,#1d355d 70%,#2d4774)}.login-box{width:min(440px,96vw);border:0;border-radius:22px;padding:38px;box-shadow:0 30px 80px #07132966}.logo-mark{display:inline-grid;place-items:center;width:42px;height:42px;border-radius:13px;background:linear-gradient(135deg,#5b7df0,#284bbd);color:white;font-weight:800;font-size:20px;margin-right:10px}.login-title{font-size:25px;font-weight:800;display:flex;align-items:center;justify-content:center}.muted{color:var(--muted)}.form-label{font-size:12px;font-weight:700;color:#46546c}.form-control,.form-select{border:1px solid #dfe5ef;border-radius:9px;min-height:43px;font-size:13px}.form-control:focus,.form-select:focus{border-color:#8198f5;box-shadow:0 0 0 .2rem #4169e11c}.btn{border-radius:9px;font-weight:650;padding:9px 14px;font-size:13px}.btn-primary{background:var(--blue);border-color:var(--blue);box-shadow:0 5px 14px #4169e126}.btn-primary:hover{background:var(--blue2);border-color:var(--blue2)}.app{display:none;min-height:100vh}.sidebar{width:250px;position:fixed;inset:0 auto 0 0;background:linear-gradient(180deg,var(--navy),#172947);color:#fff;padding:25px 16px;z-index:20;overflow-y:auto}.side-brand{display:flex;align-items:center;padding:0 8px 28px}.side-brand .logo-mark{background:linear-gradient(135deg,#6f8cff,#3d5ed0)}.brand{font-weight:800;font-size:19px;letter-spacing:-.8px}.brand-sub{color:#8fa1bf;font-size:10px;letter-spacing:1.7px;text-transform:uppercase;margin-left:60px;margin-top:-25px;margin-bottom:28px}.nav-label{font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:#7588a8;padding:12px 12px 6px}.nav-link-crm{display:flex;align-items:center;gap:12px;color:#aebbd0;padding:11px 13px;border-radius:9px;margin:3px 0;text-decoration:none;font-weight:600;font-size:13px;cursor:pointer;transition:.18s}.nav-link-crm:hover,.nav-link-crm.active{background:#ffffff15;color:#fff}.nav-link-crm.active{box-shadow:inset 3px 0 #7190ff}.nav-ico{width:20px;text-align:center;font-size:16px}.side-user{position:absolute;bottom:18px;left:16px;right:16px;border-top:1px solid #ffffff1b;padding:16px 5px 0}.avatar{width:34px;height:34px;border-radius:11px;background:#3d5d9b;display:grid;place-items:center;font-weight:800;color:white}.main{margin-left:250px;min-height:100vh}.topbar{height:76px;background:white;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 34px;position:sticky;top:0;z-index:10}.crumb{font-size:11px;color:#96a0b1;letter-spacing:1.3px;text-transform:uppercase}.page-title{font-size:22px;font-weight:800;margin:2px 0 0}.top-actions{display:flex;align-items:center;gap:12px}.role-pill{background:#eef1ff;color:#435ec6;padding:7px 12px;border-radius:30px;font-size:11px;font-weight:800}.workspace{padding:28px 34px 44px;max-width:1600px;margin:auto}.welcome{display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:23px}.welcome h2{font-size:21px;font-weight:800;margin:0 0 5px}.welcome p{margin:0;color:var(--muted);font-size:13px}.cardx{background:white;border:1px solid var(--line);border-radius:15px;box-shadow:var(--shadow)}.kpi{padding:19px 20px;min-height:128px;position:relative;overflow:hidden}.kpi:after{content:'';position:absolute;width:85px;height:85px;border-radius:50%;background:#4169e10c;right:-24px;top:-25px}.kpi-top{display:flex;align-items:center;justify-content:space-between;color:#7e8ba0;font-size:12px;font-weight:650}.kpi-icon{width:33px;height:33px;border-radius:10px;display:grid;place-items:center;background:#eef2ff;color:#4169e1;font-size:16px}.kpi-value{font:800 27px Manrope,sans-serif;margin-top:12px;letter-spacing:-.8px}.kpi-note{font-size:11px;color:#8994a6;margin-top:2px}.panel{padding:20px 21px}.panel-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:17px}.panel-title{font:750 14px Manrope,sans-serif;margin:0}.panel-sub{font-size:11px;color:#95a0b0;margin-top:4px}.table{font-size:12px;color:#38465e;margin:0}.table thead th{background:#f7f8fc;color:#8792a4;font-size:10px;text-transform:uppercase;letter-spacing:.75px;border-bottom:1px solid var(--line);padding:13px 12px;white-space:nowrap}.table tbody td{padding:13px 12px;border-color:#edf0f5;vertical-align:middle}.table-hover tbody tr:hover{background:#fafbff}.searchbox{max-width:280px}.tag{display:inline-block;border-radius:30px;padding:5px 9px;font-size:10px;font-weight:750;background:#edf1f7;color:#647188}.tag.green{background:#e5f7f1;color:#168568}.tag.blue{background:#edf1ff;color:#4b63cf}.tag.orange{background:#fff3e3;color:#b77a1d}.tag.red{background:#ffebee;color:#c24b5d}.toolbar{display:flex;gap:9px;align-items:center;justify-content:space-between;margin-bottom:15px;flex-wrap:wrap}.empty{padding:38px;text-align:center;color:#98a2b2}.modal-content{border:0;border-radius:16px;box-shadow:0 25px 70px #15244033}.modal-header,.modal-footer{border-color:var(--line);padding:17px 21px}.modal-body{padding:22px}.field-help{font-size:10px;color:#929cad;margin-top:4px}.toast-area{position:fixed;top:88px;right:24px;z-index:1000}.toast-msg{background:#172b4b;color:white;padding:12px 17px;border-radius:10px;box-shadow:var(--shadow);margin-bottom:8px;min-width:250px}.mobile-menu{display:none}@media(max-width:900px){.sidebar{width:220px}.main{margin-left:220px}.workspace{padding:22px}.topbar{padding:0 22px}}@media(max-width:700px){.sidebar{transform:translateX(-100%);transition:.2s}.sidebar.open{transform:translateX(0)}.main{margin-left:0}.mobile-menu{display:inline-block}.topbar{height:66px;padding:0 15px}.workspace{padding:18px 14px}.welcome{align-items:flex-start;gap:12px;flex-direction:column}.login-box{padding:27px}}
.login-wrap{background:#0b1730;padding:30px}.login-shell{width:min(1120px,100%);min-height:690px;display:grid;grid-template-columns:1.04fr .96fr;background:#fff;border-radius:26px;overflow:hidden;box-shadow:0 35px 100px #020b1c80}.login-art{position:relative;overflow:hidden;padding:42px 48px 25px;background:radial-gradient(circle at 75% 68%,#294b86 0,transparent 38%),linear-gradient(145deg,#102343,#1c3968 65%,#284b7d);color:white;display:flex;flex-direction:column}.art-brand{display:flex;align-items:center;gap:11px;font:800 19px Manrope,sans-serif;letter-spacing:.2px}.art-copy{position:relative;z-index:2;margin-top:60px;max-width:450px}.eyebrow,.form-kicker{font-size:10px;font-weight:800;letter-spacing:2px}.eyebrow{color:#a9bcff}.art-copy h1{font-size:39px;line-height:1.16;font-weight:800;margin:17px 0}.art-copy h1 span{color:#9bb0ff}.art-copy p{color:#c2cee2;font-size:13px;line-height:1.8;max-width:385px}.art-visual{margin:auto -20px -3px 0}.art-visual svg{width:100%;max-height:300px;filter:drop-shadow(0 18px 28px #07152c55)}.art-foot{display:flex;justify-content:space-between;color:#a9bad4;font-size:10px;letter-spacing:.4px}.login-form-side{display:grid;place-items:center;padding:45px 54px}.login-box{width:100%;max-width:390px;border:0;border-radius:0;padding:0;box-shadow:none}.login-mobile-brand{display:none}.form-kicker{color:#5474d9;margin-bottom:10px}.login-box h2{font-size:25px;font-weight:800;margin:0}.pin-input{letter-spacing:12px;font-size:20px;font-weight:800;text-align:center;padding-left:20px}.demo-heading{display:flex;align-items:center;gap:12px;color:#98a3b4;font-size:9px;font-weight:800;letter-spacing:1.3px;margin:27px 0 12px}.demo-line{height:1px;background:#e9edf4;flex:1}.demo-accounts{display:grid;gap:8px}.demo-account{display:flex;align-items:center;gap:12px;width:100%;text-align:left;border:1px solid #e9edf4;background:#fff;border-radius:11px;padding:10px 12px;transition:.18s}.demo-account:hover{border-color:#aebdf4;background:#f8f9ff;transform:translateY(-1px)}.demo-icon{width:34px;height:34px;display:grid;place-items:center;border-radius:10px;font-size:16px}.admin-icon{background:#edf1ff;color:#4968d4}.manager-icon{background:#e7f7f2;color:#1b9a7b}.sales-icon{background:#fff2e5;color:#c38434}.demo-account b{display:block;font-size:11px;color:#273650}.demo-account small{display:block;font-size:10px;color:#8490a3;margin-top:2px}.demo-arrow{margin-left:auto;color:#9aa7bd}.login-security{font-size:9px;color:#9aa4b3;margin-top:18px;text-align:center}@media(max-width:850px){.login-shell{grid-template-columns:1fr;max-width:520px;min-height:0}.login-art{display:none}.login-form-side{padding:42px 32px}.login-mobile-brand{display:flex;align-items:center;justify-content:center;font:800 19px Manrope,sans-serif;margin-bottom:35px}.login-box{max-width:390px}}@media(max-width:480px){.login-wrap{padding:12px}.login-form-side{padding:30px 20px}.login-box h2{font-size:22px}}
</style></head><body>
<div id="loginScreen" class="login-wrap"><div class="login-shell"><section class="login-art"><div class="art-brand"><span class="logo-mark">A</span><span>ACXIOM<span style="color:#91aaff">CRM</span></span></div><div class="art-copy"><div class="eyebrow">CUSTOMER RELATIONSHIP PLATFORM</div><h1>Build stronger<br><span>customer</span> relationships.</h1><p>One intelligent workspace to manage customers, grow your pipeline and turn every interaction into opportunity.</p></div><div class="art-visual"><svg viewBox="0 0 620 360" role="img" aria-label="Illustration of a CRM analytics dashboard with customer cards and sales chart"><defs><linearGradient id="cardGrad" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#fff"/><stop offset="1" stop-color="#e9efff"/></linearGradient><linearGradient id="chartGrad" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#7895ff" stop-opacity=".5"/><stop offset="1" stop-color="#7895ff" stop-opacity="0"/></linearGradient></defs><circle cx="485" cy="76" r="58" fill="#ffffff" opacity=".07"/><circle cx="90" cy="278" r="85" fill="#ffffff" opacity=".05"/><rect x="95" y="34" width="430" height="270" rx="20" fill="#07162f" opacity=".22"/><rect x="80" y="20" width="430" height="270" rx="20" fill="url(#cardGrad)"/><rect x="80" y="20" width="430" height="39" rx="20" fill="#f6f8ff"/><circle cx="103" cy="39" r="5" fill="#ff8c91"/><circle cx="120" cy="39" r="5" fill="#ffc66b"/><circle cx="137" cy="39" r="5" fill="#5bc9a6"/><rect x="101" y="75" width="117" height="69" rx="10" fill="#edf2ff"/><rect x="231" y="75" width="117" height="69" rx="10" fill="#e9f8f4"/><rect x="361" y="75" width="126" height="69" rx="10" fill="#fff3e8"/><rect x="115" y="91" width="48" height="6" rx="3" fill="#a6b5d8"/><rect x="115" y="108" width="75" height="15" rx="5" fill="#4267d5"/><rect x="245" y="91" width="50" height="6" rx="3" fill="#9bc9bb"/><rect x="245" y="108" width="70" height="15" rx="5" fill="#25a98a"/><rect x="375" y="91" width="50" height="6" rx="3" fill="#d9b78e"/><rect x="375" y="108" width="76" height="15" rx="5" fill="#eea64e"/><rect x="101" y="159" width="386" height="108" rx="11" fill="#fff" stroke="#e5eaf5"/><path d="M121 242 L165 222 L207 230 L250 194 L292 205 L335 174 L378 187 L422 151 L465 164 L465 250 L121 250Z" fill="url(#chartGrad)"/><path d="M121 242 L165 222 L207 230 L250 194 L292 205 L335 174 L378 187 L422 151 L465 164" fill="none" stroke="#5275e7" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><g fill="#5275e7"><circle cx="165" cy="222" r="4"/><circle cx="250" cy="194" r="4"/><circle cx="335" cy="174" r="4"/><circle cx="422" cy="151" r="4"/></g><rect x="390" y="235" width="135" height="74" rx="14" fill="#fff"/><circle cx="414" cy="259" r="13" fill="#e5efff"/><path d="M408 260l4 4 8-9" stroke="#4267d5" stroke-width="2.5" fill="none"/><rect x="437" y="251" width="65" height="6" rx="3" fill="#a5b0c4"/><rect x="437" y="265" width="47" height="5" rx="2.5" fill="#d3dbea"/></svg></div><div class="art-foot"><span>✦ Insightful. Connected. Productive.</span><span>ACXIOMCRM · 2026</span></div></section><section class="login-form-side"><div class="login-box"><div class="login-mobile-brand"><span class="logo-mark">A</span> ACXIOM<span style="color:#4169e1">CRM</span></div><div class="form-kicker">WELCOME BACK</div><h2>Sign in to your workspace</h2><p class="muted mb-4">Enter your account details to continue.</p><div id="loginError" class="alert alert-danger d-none small"></div><form id="loginForm"><label class="form-label">Username or business email</label><input class="form-control mb-3" name="email" type="text" autocomplete="username" placeholder="Enter username" required><div class="d-flex justify-content-between"><label class="form-label">4-digit PIN</label><span class="small muted">Numeric access code</span></div><input class="form-control pin-input mb-4" name="password" type="password" inputmode="numeric" pattern="[0-9]{4}" maxlength="4" minlength="4" autocomplete="current-password" placeholder="● ● ● ●" required><button class="btn btn-primary w-100 py-3">Sign in securely <span class="ms-2">→</span></button></form><div class="demo-heading"><span>DEMO ACCESS ACCOUNTS</span><span class="demo-line"></span></div><div class="demo-accounts"><button type="button" class="demo-account" onclick="fillDemo('admin','2468')"><span class="demo-icon admin-icon">♙</span><span><b>Administrator</b><small>admin · PIN 2468</small></span><span class="demo-arrow">↗</span></button><button type="button" class="demo-account" onclick="fillDemo('manager','1357')"><span class="demo-icon manager-icon">▥</span><span><b>Manager</b><small>manager · PIN 1357</small></span><span class="demo-arrow">↗</span></button><button type="button" class="demo-account" onclick="fillDemo('sales','2026')"><span class="demo-icon sales-icon">◎</span><span><b>Sales Executive</b><small>sales · PIN 2026</small></span><span class="demo-arrow">↗</span></button></div><div class="login-security">🔒 Demo credentials for academic evaluation · Change before production use</div></div></section></div></div>
<div id="app" class="app"><aside class="sidebar" id="sidebar"><div class="side-brand"><span class="logo-mark">A</span><span class="brand">ACXIOMCRM</span></div><div class="brand-sub">Sales workspace</div><div class="nav-label">Workspace</div><a class="nav-link-crm active" data-page="dashboard"><span class="nav-ico">▦</span>Dashboard</a><div class="nav-label">Relationship management</div><a class="nav-link-crm" data-page="customers"><span class="nav-ico">♙</span>Customers</a><a class="nav-link-crm" data-page="leads"><span class="nav-ico">◎</span>Leads</a><a class="nav-link-crm" data-page="opportunities"><span class="nav-ico">◈</span>Opportunities</a><a class="nav-link-crm" data-page="followups"><span class="nav-ico">◷</span>Follow-ups</a><a class="nav-link-crm" data-page="activities"><span class="nav-ico">☷</span>Activities</a><div class="nav-label">Insights & administration</div><a class="nav-link-crm" data-page="reports"><span class="nav-ico">▤</span>Reports</a><a class="nav-link-crm" data-page="users" data-roles="Admin"><span class="nav-ico">♧</span>User management</a><a class="nav-link-crm" data-page="audit" data-roles="Admin"><span class="nav-ico">⌁</span>Audit trail</a><div class="side-user"><div class="d-flex align-items-center gap-2"><div class="avatar" id="avatar">A</div><div class="flex-grow-1"><div id="sideName" class="fw-bold small">Administrator</div><div id="sideEmail" class="text-white-50" style="font-size:10px">admin@company.com</div></div><button class="btn btn-sm btn-outline-light" onclick="logout()">↗</button></div></div></aside>
<main class="main"><header class="topbar"><div class="d-flex align-items-center gap-3"><button class="btn btn-light mobile-menu" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button><div><div class="crumb">AcxiomCRM / <span id="crumb">Overview</span></div><h1 class="page-title" id="pageTitle">Dashboard</h1></div></div><div class="top-actions"><span class="role-pill" id="rolePill">ADMIN</span><span class="small muted" id="today"></span></div></header><div class="workspace"><div id="page"></div></div></main></div><div class="toast-area" id="toastArea"></div>
<div class="modal fade" id="recordModal" tabindex="-1"><div class="modal-dialog modal-lg modal-dialog-scrollable"><div class="modal-content"><form id="recordForm"><div class="modal-header"><div><h5 class="modal-title fw-bold" id="modalTitle">New record</h5><div class="small muted">Complete the information below and save your changes.</div></div><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="formError" class="alert alert-danger d-none"></div><div class="row g-3" id="formFields"></div></div><div class="modal-footer"><button type="button" class="btn btn-light" data-bs-dismiss="modal">Cancel</button><button class="btn btn-primary">Save record</button></div></form></div></div></div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script><script>
const $=s=>document.querySelector(s);let me=null,csrf='',kindNow='',editNow=null,chartRefs=[];const today=new Date().toISOString().slice(0,10);$('#today').textContent=new Date().toLocaleDateString('en-IN',{day:'2-digit',month:'short',year:'numeric'});
const defs={customers:{title:'Customers',fields:[['name','Customer name','text',1],['email','Email address','email',1],['phone','Phone number','tel',1],['company','Company','text'],['address','Address','text'],['city','City','text'],['state','State','text'],['status','Status','select',1,['Active','Inactive','Prospect']],['notes','Notes','textarea']]},leads:{title:'Leads',fields:[['name','Lead name','text',1],['email','Email address','email'],['phone','Phone number','tel'],['company','Company','text'],['source','Lead source','select',0,['Website','Referral','Campaign','Social media','Event','Cold call','Other']],['status','Lead status','select',1,['New','Contacted','Qualified','Unqualified','Converted','Lost']],['priority','Priority','select',1,['Low','Medium','High']],['expected_value','Expected value (₹)','number'],['notes','Notes','textarea']]},opportunities:{title:'Opportunities',fields:[['name','Opportunity name','text',1],['customer_id','Linked customer','lookup',0,'customers'],['lead_id','Linked lead','lookup',0,'leads'],['amount','Opportunity amount (₹)','number',1],['stage','Pipeline stage','select',1,['Qualification','Proposal','Negotiation','Won','Lost']],['probability','Probability (%)','number',1],['expected_close_date','Expected close date','date',1],['source','Source','text'],['notes','Notes','textarea']]},followups:{title:'Follow-ups',fields:[['subject','Subject','text',1],['customer_id','Customer','lookup',0,'customers'],['lead_id','Lead','lookup',0,'leads'],['opportunity_id','Opportunity','lookup',0,'opportunities'],['followup_date','Follow-up date','date',1],['followup_type','Follow-up type','select',1,['Call','Meeting','Email','Task']],['status','Status','select',1,['Planned','Completed','Missed','Cancelled']],['notes','Notes','textarea']]},activities:{title:'Activities',fields:[['subject','Subject','text',1],['activity_type','Activity type','select',1,['Call','Meeting','Email','Task']],['activity_date','Activity date','date',1],['customer_id','Customer','lookup',0,'customers'],['lead_id','Lead','lookup',0,'leads'],['opportunity_id','Opportunity','lookup',0,'opportunities'],['status','Status','select',1,['Open','In Progress','Completed','Cancelled']],['description','Description','textarea']]}};
async function api(url,opt={}){opt.headers={...(opt.headers||{}),'X-CSRF-Token':csrf};if(!(opt.body instanceof FormData))opt.headers['Content-Type']='application/json';let r=await fetch(url,opt),d=await r.json().catch(()=>({error:'Unexpected server response.'}));if(!r.ok)throw Error(d.error||'Request failed.');return d}function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}function money(v){return '₹'+Number(v||0).toLocaleString('en-IN',{maximumFractionDigits:0})}function toast(msg){let n=document.createElement('div');n.className='toast-msg';n.textContent=msg;$('#toastArea').append(n);setTimeout(()=>n.remove(),3200)}function fail(msg){toast(msg)}function tag(v){let c=['Active','Completed','Won','Qualified'].includes(v)?'green':['Lost','Missed','Inactive','Unqualified'].includes(v)?'red':['Proposal','Negotiation','Contacted','In Progress'].includes(v)?'blue':['Planned','New','Qualification','Prospect'].includes(v)?'orange':'';return `<span class="tag ${c}">${esc(v||'—')}</span>`}function setPage(name){document.querySelectorAll('.nav-link-crm').forEach(a=>a.classList.toggle('active',a.dataset.page===name));$('#sidebar').classList.remove('open');$('#crumb').textContent=name==='dashboard'?'Overview':name[0].toUpperCase()+name.slice(1);$('#pageTitle').textContent=name==='audit'?'Audit trail':name==='users'?'User management':name[0].toUpperCase()+name.slice(1);if(name==='dashboard')dashboard();else if(name in defs)list(name);else if(name==='users')users();else if(name==='audit')auditPage();else if(name==='reports')reportsPage()}
document.querySelectorAll('.nav-link-crm').forEach(a=>a.addEventListener('click',()=>setPage(a.dataset.page)));
function fillDemo(username,pin){const f=document.getElementById('loginForm');f.elements.email.value=username;f.elements.password.value=pin;f.elements.password.focus()}
$('#loginForm').addEventListener('submit',async e=>{e.preventDefault();let d=Object.fromEntries(new FormData(e.target));try{let r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)}),x=await r.json();if(!r.ok)throw Error(x.error);me=x.user;csrf=x.csrf;boot()}catch(x){$('#loginError').textContent=x.message;$('#loginError').classList.remove('d-none')}});
function toggleRegister(){$('#registerForm').classList.toggle('d-none')}$('#registerForm').addEventListener('submit',async e=>{e.preventDefault();try{let d=Object.fromEntries(new FormData(e.target)),r=await fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)}),x=await r.json();if(!r.ok)throw Error(x.error);toast(x.message);e.target.reset();e.target.classList.add('d-none')}catch(x){fail(x.message)}});
function boot(){$('#loginScreen').style.display='none';$('#app').style.display='block';$('#sideName').textContent=me.name;$('#sideEmail').textContent=me.email;$('#avatar').textContent=me.name.slice(0,1).toUpperCase();$('#rolePill').textContent=me.role.toUpperCase();document.querySelectorAll('[data-roles]').forEach(a=>a.style.display=a.dataset.roles.split(',').includes(me.role)?'flex':'none');setPage('dashboard')}
async function dashboard(){try{let d=await api('/api/dashboard'),k=d.kpis;$('#page').innerHTML=`<div class="welcome"><div><h2>Good ${new Date().getHours()<12?'morning':new Date().getHours()<17?'afternoon':'evening'}, ${esc(me.name.split(' ')[0])}</h2><p>Here is what is happening across your sales workspace today.</p></div><button class="btn btn-primary" onclick="setPage('opportunities')">View sales pipeline&nbsp; →</button></div><div class="row g-3 mb-3">${[['Total customers',k.customers,'♙','Customer records'],['Active leads',k.leads,'◎','Prospects in your funnel'],['Open opportunities',k.open_opportunities,'◈','Deals in progress'],['Sales pipeline',money(k.pipeline),'↗','Weighted: '+money(k.weighted_pipeline)],['Upcoming follow-ups',k.upcoming_followups,'◷','Scheduled from today'],['Overdue follow-ups',k.overdue_followups,'!','Require attention']].map((x,i)=>`<div class="col-6 col-xl-2"><div class="cardx kpi"><div class="kpi-top">${x[0]}<span class="kpi-icon">${x[2]}</span></div><div class="kpi-value">${x[1]}</div><div class="kpi-note">${x[3]}</div></div></div>`).join('')}</div><div class="row g-3"><div class="col-xl-7"><div class="cardx panel"><div class="panel-head"><div><h3 class="panel-title">Opportunity pipeline</h3><div class="panel-sub">Deal count by sales stage</div></div><button class="btn btn-sm btn-light" onclick="setPage('reports')">View report</button></div><div style="height:270px"><canvas id="stageChart"></canvas></div></div></div><div class="col-xl-5"><div class="cardx panel"><div class="panel-head"><div><h3 class="panel-title">Lead distribution</h3><div class="panel-sub">Current lead status breakdown</div></div></div><div style="height:270px"><canvas id="leadChart"></canvas></div></div></div><div class="col-12"><div class="cardx panel"><div class="panel-head"><div><h3 class="panel-title">Recent records</h3><div class="panel-sub">Latest customer and lead activity</div></div></div><div class="table-responsive"><table class="table"><thead><tr><th>Record type</th><th>Name</th><th>Created</th></tr></thead><tbody>${d.recent.map(x=>`<tr><td>${tag(x.type)}</td><td class="fw-semibold">${esc(x.title)}</td><td>${esc(x.created_at)}</td></tr>`).join('')||'<tr><td colspan="3" class="empty">No records created yet.</td></tr>'}</tbody></table></div></div></div></div>`;
chartRefs.forEach(c=>c.destroy());chartRefs=[];chartRefs.push(new Chart($('#stageChart'),{type:'bar',data:{labels:d.stages.map(x=>x.stage),datasets:[{label:'Opportunity value',data:d.stages.map(x=>x.amount),backgroundColor:'#5578e8',borderRadius:7,maxBarThickness:48}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{y:{grid:{color:'#edf0f5'},ticks:{callback:v=>'₹'+Number(v).toLocaleString('en-IN')}},x:{grid:{display:false}}}}}));chartRefs.push(new Chart($('#leadChart'),{type:'doughnut',data:{labels:d.lead_status.map(x=>x.status),datasets:[{data:d.lead_status.map(x=>x.count),backgroundColor:['#5578e8','#22a88b','#f0ad4e','#8a78d6','#3ba6c8','#dc7182'],borderWidth:0,hoverOffset:5}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{usePointStyle:true,boxWidth:8,padding:16}}}}}));}catch(e){fail(e.message)}}
const cols={customers:['code','name','company','email','phone','status'],leads:['code','name','company','source','status','priority','expected_value'],opportunities:['code','name','amount','stage','probability','expected_close_date'],followups:['code','subject','followup_date','followup_type','status'],activities:['code','subject','activity_type','activity_date','status']};
async function list(k){try{let d=await api('/api/'+k),items=d.items;$('#page').innerHTML=`<div class="welcome"><div><h2>${defs[k].title}</h2><p>Manage and maintain your ${defs[k].title.toLowerCase()} records.</p></div><button class="btn btn-primary" onclick="openForm('${k}')">＋ Add ${defs[k].title.slice(0,-1)}</button></div><div class="cardx panel"><div class="toolbar"><div class="d-flex gap-2 align-items-center"><input id="tableSearch" class="form-control searchbox" placeholder="Search ${defs[k].title.toLowerCase()}..." oninput="filterTable()"><span class="small muted">${items.length} records</span></div><div class="d-flex gap-2 flex-wrap"><button class="btn btn-outline-primary btn-sm" onclick="downloadTemplate('${k}')">↓ Template</button><button class="btn btn-outline-success btn-sm" onclick="chooseImport('${k}')">↑ Import CSV</button><input id="importFile" type="file" accept=".csv,text/csv" hidden onchange="importRecords('${k}',this)"><button class="btn btn-outline-secondary btn-sm" onclick="downloadReport('${k}')">↓ Export CSV</button></div></div><div class="table-responsive"><table class="table table-hover"><thead><tr>${cols[k].map(c=>`<th>${c.replaceAll('_',' ')}</th>`).join('')}<th>Actions</th></tr></thead><tbody id="tableRows">${items.map(x=>row(k,x)).join('')||`<tr><td colspan="${cols[k].length+1}" class="empty">No ${defs[k].title.toLowerCase()} found. Add your first record to get started.</td></tr>`}</tbody></table></div></div>`}catch(e){fail(e.message)}}
function chooseImport(k){const f=$('#importFile');f.value='';f.click()}
async function importRecords(k,input){if(!input.files||!input.files[0])return;const fd=new FormData();fd.append('file',input.files[0]);try{const r=await fetch('/api/import/'+k,{method:'POST',headers:{'X-CSRF-Token':csrf},body:fd});const d=await r.json().catch(()=>({error:'Unexpected server response.'}));if(!r.ok)throw Error(d.error||'Import failed.');let msg=d.message;if(d.skipped_count)msg+=` ${d.skipped_count} row(s) skipped; open browser console not required, details: `+d.skipped.slice(0,3).map(x=>'row '+x.row+': '+x.error).join('; ');toast(msg);list(k)}catch(e){fail(e.message)}}
async function downloadTemplate(k){try{const r=await fetch('/api/template/'+k+'.csv',{headers:{'X-CSRF-Token':csrf}});if(!r.ok)throw Error('Could not download template.');const b=await r.blob(),u=URL.createObjectURL(b),a=document.createElement('a');a.href=u;a.download=`acxiomcrm-${k}-template.csv`;a.click();URL.revokeObjectURL(u)}catch(e){fail(e.message)}}
function row(k,x){return `<tr data-search="${esc(JSON.stringify(x).toLowerCase())}">${cols[k].map(c=>`<td>${c==='amount'||c==='expected_value'?money(x[c]):c==='probability'?esc(x[c])+'%':c==='status'||c==='stage'?tag(x[c]):c==='priority'?tag(x[c]):esc(x[c]||'—')}</td>`).join('')}<td class="text-nowrap"><button class="btn btn-sm btn-light" onclick="editItem('${k}',${x.id})">Edit</button> ${k==='leads'&&x.status!=='Converted'?`<button class="btn btn-sm btn-outline-success" onclick="convertLead(${x.id})">Convert</button>`:''}<button class="btn btn-sm btn-outline-danger" onclick="deleteItem('${k}',${x.id})">Delete</button></td></tr>`}function filterTable(){let q=$('#tableSearch').value.toLowerCase();document.querySelectorAll('#tableRows tr').forEach(r=>r.style.display=(r.dataset.search||'').includes(q)?'':'none')}
async function lookups(){return await api('/api/lookups')}async function openForm(k,item={}){kindNow=k;editNow=item.id||null;let lk=await lookups();$('#modalTitle').textContent=(editNow?'Edit ':'Create ')+defs[k].title.slice(0,-1);$('#formError').classList.add('d-none');$('#formFields').innerHTML=defs[k].fields.map(([n,label,type,req,opts])=>{let v=item[n]??'';let control='';if(type==='textarea')control=`<textarea class="form-control" rows="3" name="${n}">${esc(v)}</textarea>`;else if(type==='select')control=`<select class="form-select" name="${n}">${opts.map(o=>`<option ${v===o?'selected':''}>${o}</option>`).join('')}</select>`;else if(type==='lookup'){let arr=lk[opts]||[];control=`<select class="form-select" name="${n}"><option value="">Not linked</option>${arr.map(o=>`<option value="${o.id}" ${String(v)===String(o.id)?'selected':''}>${esc(o.code)} · ${esc(o.name)}</option>`).join('')}</select>`}else control=`<input class="form-control" name="${n}" type="${type}" value="${esc(v)}" ${req?'required':''} ${type==='number'?(n==='probability'?'min="0" max="100"':'min="0" step="0.01"'):''} ${type==='date'?'min="'+(n==='followup_date'?today:'')+'"':''}>`;return `<div class="col-md-6"><label class="form-label">${label}${req?' *':''}</label>${control}</div>`}).join('');bootstrap.Modal.getOrCreateInstance($('#recordModal')).show()}
async function editItem(k,id){try{let d=await api(`/api/${k}/${id}`);openForm(k,d.item)}catch(e){fail(e.message)}}$('#recordForm').addEventListener('submit',async e=>{e.preventDefault();let d=Object.fromEntries(new FormData(e.target));try{await api(`/api/${kindNow}${editNow?'/'+editNow:''}`,{method:editNow?'PUT':'POST',body:JSON.stringify(d)});bootstrap.Modal.getInstance($('#recordModal')).hide();toast('Record saved successfully.');list(kindNow)}catch(x){$('#formError').textContent=x.message;$('#formError').classList.remove('d-none')}});
async function deleteItem(k,id){if(!confirm('Are you sure you want to delete this record? This action is recorded in the audit trail.'))return;try{await api(`/api/${k}/${id}`,{method:'DELETE'});toast('Record deleted.');list(k)}catch(e){fail(e.message)}}async function convertLead(id){if(!confirm('Convert this lead into a customer?'))return;try{let d=await api(`/api/leads/${id}/convert`,{method:'POST'});toast(d.message);list('leads')}catch(e){fail(e.message)}}
async function reportsPage(){try{let [p,c]=await Promise.all([api('/api/reports/pipeline'),api('/api/reports/conversion')]);$('#page').innerHTML=`<div class="welcome"><div><h2>Business reports</h2><p>Monitor pipeline performance, lead conversion and operational activity.</p></div></div><div class="cardx panel mb-3"><h3 class="panel-title">Import data and generate reports</h3><p class="panel-sub">Download a module template, fill it in Excel, save as CSV, then import it from the relevant module. Use Export CSV to generate your updated report.</p><div class="d-flex flex-wrap gap-2 mt-3">${['customers','leads','opportunities','followups','activities'].map(k=>`<button class="btn btn-sm btn-outline-primary" onclick="downloadTemplate('${k}')">${defs[k].title} template ↓</button>`).join('')}</div></div><div class="row g-3"><div class="col-xl-6"><div class="cardx panel"><div class="panel-head"><div><h3 class="panel-title">Sales pipeline report</h3><div class="panel-sub">Stage-wise deal value and weighted value</div></div><button class="btn btn-sm btn-light" onclick="downloadReport('pipeline')">Export CSV</button></div><div class="table-responsive"><table class="table"><thead><tr><th>Stage</th><th>Deals</th><th>Amount</th><th>Weighted</th></tr></thead><tbody>${p.items.map(x=>`<tr><td>${tag(x.stage)}</td><td>${x.count}</td><td>${money(x.amount)}</td><td>${money(x.weighted)}</td></tr>`).join('')||'<tr><td colspan="4" class="empty">No pipeline data.</td></tr>'}</tbody></table></div></div></div><div class="col-xl-6"><div class="cardx panel"><div class="panel-head"><div><h3 class="panel-title">Lead conversion report</h3><div class="panel-sub">Lead count and expected value by status</div></div><button class="btn btn-sm btn-light" onclick="downloadReport('conversion')">Export CSV</button></div><div class="table-responsive"><table class="table"><thead><tr><th>Status</th><th>Leads</th><th>Expected value</th></tr></thead><tbody>${c.items.map(x=>`<tr><td>${tag(x.status)}</td><td>${x.count}</td><td>${money(x.value)}</td></tr>`).join('')||'<tr><td colspan="3" class="empty">No lead data.</td></tr>'}</tbody></table></div></div></div>${['customers','leads','opportunities','followups','activities'].map(k=>`<div class="col-md-4"><div class="cardx panel d-flex justify-content-between align-items-center"><div><div class="panel-title">${defs[k].title} report</div><div class="panel-sub">Download filtered records</div></div><button class="btn btn-outline-primary btn-sm" onclick="downloadReport('${k}')">Export ↓</button></div></div>`).join('')}</div>`}catch(e){fail(e.message)}}
async function downloadReport(k){try{let r=await fetch('/api/export/'+k+'.csv',{headers:{'X-CSRF-Token':csrf}});if(!r.ok){let d=await r.json();throw Error(d.error)}let blob=await r.blob(),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=`acxiomcrm-${k}.csv`;a.click();URL.revokeObjectURL(url)}catch(e){fail(e.message)}}
async function users(){try{let d=await api('/api/users');$('#page').innerHTML=`<div class="welcome"><div><h2>User management</h2><p>Manage workspace accounts, roles and account status.</p></div><button class="btn btn-primary" onclick="createUser()">＋ Add user</button></div><div class="cardx panel"><div class="table-responsive"><table class="table"><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Failed logins</th><th>Created</th><th>Actions</th></tr></thead><tbody>${d.items.map(u=>`<tr><td class="fw-semibold">${esc(u.name)}</td><td>${esc(u.email)}</td><td>${tag(u.role)}</td><td>${tag(u.active?'Active':'Inactive')}</td><td>${u.failed_count}</td><td>${esc(u.created_at)}</td><td><button class="btn btn-sm btn-light" onclick="editUser(${u.id},'${esc(u.role)}',${u.active})">Edit</button> <button class="btn btn-sm btn-outline-secondary" onclick="resetPassword(${u.id})">Reset password</button></td></tr>`).join('')}</tbody></table></div></div>`}catch(e){fail(e.message)}}
async function createUser(){let name=prompt('Full name');if(!name)return;let email=prompt('Business email');if(!email)return;let password=prompt('4-digit PIN');if(!password)return;let role=prompt('Role: Admin, Manager, Sales Executive','Sales Executive');try{await api('/api/users',{method:'POST',body:JSON.stringify({name,email,password,role})});toast('User created.');users()}catch(e){fail(e.message)}}async function editUser(id,role,active){let r=prompt('Role: Admin, Manager, Sales Executive',role);if(!r)return;let a=confirm('Keep this account active? Select Cancel to deactivate.');try{await api('/api/users/'+id,{method:'PATCH',body:JSON.stringify({role:r,active:a})});toast('User updated.');users()}catch(e){fail(e.message)}}async function resetPassword(id){let p=prompt('Enter a new 4-digit PIN');if(!p)return;try{let d=await api('/api/users/'+id+'/reset-password',{method:'POST',body:JSON.stringify({password:p})});toast(d.message)}catch(e){fail(e.message)}}
async function auditPage(){try{let d=await api('/api/audit');$('#page').innerHTML=`<div class="welcome"><div><h2>Audit trail</h2><p>Security and business events recorded by the application. Audit entries are append-only through the application.</p></div></div><div class="cardx panel"><div class="toolbar"><input class="form-control searchbox" id="auditSearch" placeholder="Search user, action or module..." oninput="filterAudit()"><span class="small muted">Latest ${d.items.length} events</span></div><div class="table-responsive"><table class="table"><thead><tr><th>Timestamp</th><th>User</th><th>Action</th><th>Module</th><th>Record ID</th><th>Result</th><th>IP address</th></tr></thead><tbody id="auditRows">${d.items.map(x=>`<tr data-search="${esc(JSON.stringify(x).toLowerCase())}"><td>${esc(x.created_at)}</td><td>${esc(x.user_name||'System')}</td><td>${esc(x.action)}</td><td>${esc(x.entity_name)}</td><td>${esc(x.record_id||'—')}</td><td>${tag(x.result)}</td><td>${esc(x.ip_address||'—')}</td></tr>`).join('')||'<tr><td colspan="7" class="empty">No audit events yet.</td></tr>'}</tbody></table></div></div>`}catch(e){fail(e.message)}}function filterAudit(){let q=$('#auditSearch').value.toLowerCase();document.querySelectorAll('#auditRows tr').forEach(r=>r.style.display=(r.dataset.search||'').includes(q)?'':'none')}
async function logout(){try{await api('/api/logout',{method:'POST'})}catch(e){}location.reload()}
(async()=>{try{let d=await fetch('/api/me').then(r=>r.json());if(d.user){me=d.user;csrf=d.csrf;boot()}}catch(e){}})();
</script></body></html>'''

@app.errorhandler(413)
def too_large(_): return jsonify(error='Request is too large.'),413
@app.errorhandler(500)
def server_error(err):
    app.logger.exception('Unhandled AcxiomCRM error: %s', err)
    return jsonify(error='Server could not save this record. Check the terminal for the detailed error; database compatibility migrations run automatically on startup.'),500
if __name__=='__main__':
    init_db()
    print('\n'+'='*58+'\n AcxiomCRM Enterprise Edition\n URL: http://127.0.0.1:5000\n Demo Admin: admin / PIN 2468\n Demo Manager: manager / PIN 1357\n Demo Sales: sales / PIN 2026\n Stop server: CTRL+C\n'+'='*58+'\n')
    app.run(host='127.0.0.1',port=int(os.environ.get('PORT',5000)),debug=False)
