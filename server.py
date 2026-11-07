"""Local role-based authentication API. Run: python server.py."""
import hashlib
import hmac
import json
import os
import math
import calendar
import secrets
import sys
import sqlite3
import time
from contextlib import contextmanager
from datetime import date
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

ROOT = Path(__file__).resolve().parent
DB = Path(os.environ.get('DATABASE_PATH', ROOT / 'users.sqlite3'))
FRONTEND = ROOT.parent / 'fe' / 'dist'
ROLES = ('superuser', 'manager', 'employee')
DEMO_ENABLED = os.environ.get('ENABLE_DEMO_LOGIN', '1') == '1'
ALLOWED_ORIGIN = os.environ.get('FRONTEND_ORIGIN', '').rstrip('/')
COOKIE_SECURE = os.environ.get('COOKIE_SECURE', '0') == '1'
DEMO_PASSWORD = 'Demo@12345'

@contextmanager
def database():
    DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB, timeout=10)
    con.execute('PRAGMA foreign_keys=ON')
    con.row_factory = sqlite3.Row
    try:
        with con:
            yield con
    finally:
        con.close()

def initialize():
    with database() as con:
        con.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('superuser','manager','employee'))
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attempts (
                client TEXT PRIMARY KEY, count INTEGER NOT NULL, reset REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS teams (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE
            );
            CREATE TABLE IF NOT EXISTS team_members (
                team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
                employee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                PRIMARY KEY (team_id, employee_id)
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
                assignee_id INTEGER NOT NULL REFERENCES users(id),
                created_by INTEGER NOT NULL REFERENCES users(id),
                assigned_by INTEGER NOT NULL REFERENCES users(id),
                status TEXT NOT NULL DEFAULT 'To do' CHECK(status IN ('To do','In progress','Done')),
                due_date TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attendance (
                user_id INTEGER NOT NULL REFERENCES users(id), day TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('Present','Absent','Leave')),
                marked_by INTEGER NOT NULL REFERENCES users(id), updated_at REAL NOT NULL,
                PRIMARY KEY(user_id, day)
            );
            CREATE TABLE IF NOT EXISTS visit_locations (
                task_id INTEGER PRIMARY KEY REFERENCES tasks(id),
                employee_id INTEGER NOT NULL REFERENCES users(id), active INTEGER NOT NULL DEFAULT 0,
                latitude REAL, longitude REAL, accuracy REAL, captured_at REAL, received_at REAL
            );
            CREATE TABLE IF NOT EXISTS salaries (
                user_id INTEGER PRIMARY KEY REFERENCES users(id), base INTEGER NOT NULL,
                allowances INTEGER NOT NULL, deductions INTEGER NOT NULL,
                updated_by INTEGER NOT NULL REFERENCES users(id), updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS payroll (
                id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
                month TEXT NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL, role TEXT NOT NULL,
                base INTEGER NOT NULL, allowances INTEGER NOT NULL, deductions INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'Draft' CHECK(status IN ('Draft','Approved','Paid')),
                created_by INTEGER NOT NULL REFERENCES users(id), created_at REAL NOT NULL,
                approved_by INTEGER REFERENCES users(id), approved_at REAL,
                paid_by INTEGER REFERENCES users(id), paid_at REAL, payment_reference TEXT NOT NULL DEFAULT '',
                UNIQUE(user_id,month)
            );
            CREATE TABLE IF NOT EXISTS payroll_month_settings (
                month TEXT PRIMARY KEY, working_days INTEGER NOT NULL,
                paid_leave_days INTEGER NOT NULL, notes TEXT NOT NULL DEFAULT '',
                updated_by INTEGER NOT NULL REFERENCES users(id), updated_at REAL NOT NULL
            );
        ''')
        if 'created_by' not in [row['name'] for row in con.execute('PRAGMA table_info(users)')]:
            con.execute('ALTER TABLE users ADD COLUMN created_by INTEGER REFERENCES users(id)')
        if 'manager_id' not in [row['name'] for row in con.execute('PRAGMA table_info(teams)')]:
            con.execute('ALTER TABLE teams ADD COLUMN manager_id INTEGER REFERENCES users(id)')
        if 'task_type' not in [row['name'] for row in con.execute('PRAGMA table_info(tasks)')]:
            con.execute("ALTER TABLE tasks ADD COLUMN task_type TEXT NOT NULL DEFAULT 'standard'")
        if 'site_address' not in [row['name'] for row in con.execute('PRAGMA table_info(tasks)')]:
            con.execute("ALTER TABLE tasks ADD COLUMN site_address TEXT NOT NULL DEFAULT ''")
        payroll_columns = {row['name'] for row in con.execute('PRAGMA table_info(payroll)')}
        for column, definition in [('attendance_deduction', 'INTEGER NOT NULL DEFAULT 0'), ('absent_days', 'INTEGER NOT NULL DEFAULT 0'), ('basis_days', 'INTEGER NOT NULL DEFAULT 0'), ('attendance_policy', "TEXT NOT NULL DEFAULT 'calendar'"), ('attendance_at', 'REAL'), ('leave_days', 'INTEGER NOT NULL DEFAULT 0'), ('paid_leave_allowance', 'INTEGER NOT NULL DEFAULT 0'), ('unpaid_days', 'INTEGER NOT NULL DEFAULT 0')]:
            if column not in payroll_columns:
                con.execute(f'ALTER TABLE payroll ADD COLUMN {column} {definition}')
        for column, definition in [('leave_opening', 'INTEGER NOT NULL DEFAULT 0'), ('paid_leave_used', 'INTEGER NOT NULL DEFAULT 0'), ('leave_balance_after', 'INTEGER'), ('night_shifts', 'INTEGER NOT NULL DEFAULT 0'), ('night_shift_rate', 'INTEGER NOT NULL DEFAULT 0'), ('night_shift_pay', 'INTEGER NOT NULL DEFAULT 0'), ('night_hours_hundredths', 'INTEGER NOT NULL DEFAULT 0')]:
            if column not in payroll_columns:
                con.execute(f'ALTER TABLE payroll ADD COLUMN {column} {definition}')
        if 'night_shift_rate' not in {row['name'] for row in con.execute('PRAGMA table_info(payroll_month_settings)')}:
            con.execute('ALTER TABLE payroll_month_settings ADD COLUMN night_shift_rate INTEGER NOT NULL DEFAULT 0')
        if 'night_shift' not in {row['name'] for row in con.execute('PRAGMA table_info(attendance)')}:
            con.execute('ALTER TABLE attendance ADD COLUMN night_shift INTEGER NOT NULL DEFAULT 0')
        if 'night_hours_hundredths' not in {row['name'] for row in con.execute('PRAGMA table_info(attendance)')}:
            con.execute('ALTER TABLE attendance ADD COLUMN night_hours_hundredths INTEGER NOT NULL DEFAULT 0')

def visible_employees(con, manager_id):
    return {row[0] for row in con.execute("SELECT id FROM users WHERE role='employee' AND (created_by=? OR id IN (SELECT employee_id FROM team_members JOIN teams ON teams.id=team_members.team_id WHERE manager_id=?))", (manager_id, manager_id))}

def task_assignees(con, actor):
    if actor['role'] == 'superuser':
        return [public_user(row) for row in con.execute("SELECT * FROM users WHERE role IN ('manager','employee') ORDER BY name")]
    if actor['role'] == 'manager':
        return [public_user(row) for row in con.execute("SELECT DISTINCT users.* FROM users JOIN team_members ON users.id=team_members.employee_id JOIN teams ON teams.id=team_members.team_id WHERE teams.manager_id=? AND users.role='employee' ORDER BY users.name", (actor['id'],))]
    return []

def task_visible(actor, task):
    return actor['role'] == 'superuser' or task['assignee_id'] == actor['id'] or (actor['role'] == 'manager' and actor['id'] in (task['created_by'], task['assigned_by']))

def attendance_people(con, actor):
    if actor['role'] == 'superuser':
        return [public_user(row) for row in con.execute("SELECT * FROM users WHERE role IN ('manager','employee') ORDER BY name")]
    if actor['role'] == 'manager':
        return [public_user(actor)] + task_assignees(con, actor)
    return [public_user(actor)]

def valid_month(value):
    try:
        return isinstance(value, str) and len(value) == 7 and date.fromisoformat(value + '-01').isoformat()[:7] == value
    except ValueError:
        return False

def payroll_amounts(data):
    values = []
    for key in ('base', 'allowances', 'deductions'):
        value = data.get(key, '0')
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            raise ValueError('Amounts must be decimal strings.')
        try:
            amount = Decimal(str(value))
            if not amount.is_finite() or amount < 0 or amount > 100000000 or amount.as_tuple().exponent < -2:
                raise ValueError('Invalid amount.')
            values.append(int(amount * 100))
        except InvalidOperation:
            raise ValueError('Invalid amount.')
    if values[0] <= 0 or values[2] > values[0] + values[1]:
        raise ValueError('Base must be positive and deductions cannot exceed earnings.')
    return values

def leave_opening(con, user_id, month):
    balance = 0
    # Only configured months earn credits. Each January starts a new leave year.
    for settings in con.execute('SELECT * FROM payroll_month_settings WHERE month>=? AND month<? ORDER BY month', (month[:4] + '-01', month)).fetchall():
        closed = con.execute("SELECT * FROM payroll WHERE user_id=? AND month=? AND status IN ('Approved','Paid')", (user_id, settings['month'])).fetchone()
        if closed and closed['leave_balance_after'] is not None:
            balance = closed['leave_balance_after']
        else:
            used = closed['leave_days'] if closed else con.execute("SELECT COUNT(*) FROM attendance WHERE user_id=? AND day LIKE ? AND status='Leave'", (user_id, settings['month'] + '-%')).fetchone()[0]
            balance = max(0, balance + settings['paid_leave_days'] - used)
    return balance

def payroll_attendance(con, row):
    result = dict(row)
    if row['status'] == 'Draft':
        absent_days = con.execute("SELECT COUNT(*) FROM attendance WHERE user_id=? AND day LIKE ? AND status='Absent'", (row['user_id'], row['month'] + '-%')).fetchone()[0]
        year, month = map(int, row['month'].split('-'))
        settings = con.execute('SELECT * FROM payroll_month_settings WHERE month=?', (row['month'],)).fetchone()
        leave_days = con.execute("SELECT COUNT(*) FROM attendance WHERE user_id=? AND day LIKE ? AND status='Leave'", (row['user_id'], row['month'] + '-%')).fetchone()[0]
        if settings:
            basis, allowance = calendar.monthrange(year, month)[1], settings['paid_leave_days']
            opening = leave_opening(con, row['user_id'], row['month'])
            used = min(leave_days, opening + allowance)
            unpaid_days = absent_days + leave_days - used
            result.update(leave_opening=opening, paid_leave_used=used, leave_balance_after=opening + allowance - used)
            result['attendance_policy'] = 'calendar'
        else:
            basis = calendar.monthrange(year, month)[1]
            result['attendance_policy'] = 'calendar'
            allowance, unpaid_days = leave_days, absent_days
            result.update(leave_opening=0, paid_leave_used=leave_days, leave_balance_after=0)
        night_shifts = con.execute("SELECT COUNT(*) FROM attendance WHERE user_id=? AND day LIKE ? AND status='Present' AND night_shift=1", (row['user_id'], row['month'] + '-%')).fetchone()[0]
        night_hours = con.execute("SELECT COALESCE(SUM(night_hours_hundredths),0) FROM attendance WHERE user_id=? AND day LIKE ? AND status='Present' AND night_shift=1", (row['user_id'], row['month'] + '-%')).fetchone()[0]
        rate = settings['night_shift_rate'] if settings else 0
        extra = int((Decimal(rate) * night_hours / 100).quantize(Decimal('1'), rounding=ROUND_HALF_UP))
        result.update(night_shifts=night_shifts, night_shift_rate=rate, night_shift_pay=extra, night_hours_hundredths=night_hours)
        deduction = min(row['base'], int((Decimal(row['base']) * unpaid_days / basis).quantize(Decimal('1'), rounding=ROUND_HALF_UP)))
        result.update(absent_days=absent_days, basis_days=basis, attendance_deduction=deduction, leave_days=leave_days, paid_leave_allowance=allowance, unpaid_days=unpaid_days)
    result['total_deductions'] = result['deductions'] + result['attendance_deduction']
    result['net_pay'] = result['base'] + result['allowances'] + result.get('night_shift_pay', 0) - result['total_deductions']
    return result

def password_hash(password):
    salt = secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
    return salt + ':' + digest

def seed_demo_accounts():
    if not DEMO_ENABLED:
        return
    with database() as con:
        for role, name in [('superuser', 'Demo Super User'), ('manager', 'Demo Manager'), ('employee', 'Demo Employee')]:
            con.execute('INSERT OR IGNORE INTO users(name,email,password,role) VALUES(?,?,?,?)',
                        (name, role + '@demo.local', password_hash(DEMO_PASSWORD), role))

def password_valid(password, stored):
    salt, digest = stored.split(':')
    actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
    return hmac.compare_digest(actual, digest)

def public_user(row):
    return {key: row[key] for key in ('id', 'name', 'email', 'role')}

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND), **kwargs)

    def respond(self, code, data, cookie=None):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        origin = self.headers.get('Origin', '').rstrip('/')
        if ALLOWED_ORIGIN and origin == ALLOWED_ORIGIN:
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Access-Control-Allow-Credentials', 'true')
            self.send_header('Vary', 'Origin')
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def token(self):
        authorization = self.headers.get('Authorization', '')
        if authorization.startswith('Bearer '):
            return hashlib.sha256(authorization[7:].encode()).hexdigest()
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get('Cookie', ''))
            token = cookie['session'].value if 'session' in cookie else ''
            return hashlib.sha256(token.encode()).hexdigest()
        except Exception:
            return ''

    def do_OPTIONS(self):
        origin = self.headers.get('Origin', '').rstrip('/')
        if not ALLOWED_ORIGIN or origin != ALLOWED_ORIGIN:
            return self.respond(403, {'error': 'Origin not allowed.'})
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', origin)
        self.send_header('Access-Control-Allow-Credentials', 'true')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With, Authorization')
        self.send_header('Access-Control-Max-Age', '86400')
        self.send_header('Vary', 'Origin')
        self.end_headers()

    def current_user(self, con):
        return con.execute('SELECT users.* FROM sessions JOIN users ON users.id=sessions.user_id WHERE token=? AND expires>?', (self.token(), time.time())).fetchone()

    def do_GET(self):
        if not self.path.startswith('/api/'):
            clean_path = urlsplit(self.path).path.lstrip('/')
            target = FRONTEND / clean_path
            if clean_path and not target.is_file():
                self.path = '/index.html'
            return super().do_GET()
        with database() as con:
            if urlsplit(self.path).path == '/api/payroll':
                actor = self.current_user(con)
                if not actor:
                    return self.respond(401, {'error': 'Please sign in.'})
                month = parse_qs(urlsplit(self.path).query).get('month', [''])[0]
                if not valid_month(month):
                    return self.respond(400, {'error': 'Choose a valid payroll month.'})
                ids = {person['id'] for person in attendance_people(con, actor)}
                rows = [payroll_attendance(con, row) for row in con.execute('SELECT * FROM payroll WHERE month=? ORDER BY name', (month,)) if row['user_id'] in ids and (actor['role'] != 'employee' or row['status'] != 'Draft')]
                salaries = []
                if actor['role'] == 'superuser':
                    for person in attendance_people(con, actor):
                        salary = con.execute('SELECT base,allowances,deductions FROM salaries WHERE user_id=?', (person['id'],)).fetchone()
                        salaries.append({**person, 'salary': dict(salary) if salary else None})
                settings = con.execute('SELECT month,working_days,paid_leave_days,notes,night_shift_rate FROM payroll_month_settings WHERE month=?', (month,)).fetchone()
                return self.respond(200, {'rows': rows, 'people': salaries, 'currency': 'INR', 'month_settings': dict(settings) if settings else None})
            if urlsplit(self.path).path == '/api/attendance':
                actor = self.current_user(con)
                if not actor:
                    return self.respond(401, {'error': 'Please sign in.'})
                month = parse_qs(urlsplit(self.path).query).get('month', [''])[0]
                try:
                    if date.fromisoformat(month + '-01').strftime('%Y-%m') != month:
                        raise ValueError()
                except ValueError:
                    return self.respond(400, {'error': 'Choose a valid month (YYYY-MM).'})
                people = attendance_people(con, actor)
                ids = {person['id'] for person in people}
                teams = [dict(row) for row in con.execute('SELECT * FROM teams ORDER BY name' if actor['role'] == 'superuser' else 'SELECT * FROM teams WHERE manager_id=? ORDER BY name', () if actor['role'] == 'superuser' else (actor['id'],))] if actor['role'] != 'employee' else []
                for team in teams:
                    team['employee_ids'] = [row[0] for row in con.execute('SELECT employee_id FROM team_members WHERE team_id=?', (team['id'],)) if row[0] in ids]
                records = [dict(row) for row in con.execute('SELECT user_id,day,status,night_shift,night_hours_hundredths FROM attendance WHERE day LIKE ? ORDER BY day', (month + '-%',)) if row['user_id'] in ids]
                return self.respond(200, {'people': people, 'teams': teams, 'records': records})
            if self.path == '/api/auth/status':
                user = self.current_user(con)
                return self.respond(200, {'needs_setup': not con.execute('SELECT 1 FROM users LIMIT 1').fetchone(), 'user': public_user(user) if user else None, 'demo_enabled': DEMO_ENABLED})
            if self.path == '/api/tasks':
                actor = self.current_user(con)
                if not actor:
                    return self.respond(401, {'error': 'Please sign in.'})
                rows = con.execute('SELECT tasks.*, assignee.name AS assignee_name, assignee.role AS assignee_role, creator.name AS creator_name, assigner.name AS assigner_name FROM tasks JOIN users assignee ON assignee.id=tasks.assignee_id JOIN users creator ON creator.id=tasks.created_by JOIN users assigner ON assigner.id=tasks.assigned_by ORDER BY tasks.id DESC')
                tasks = [dict(row) for row in rows if task_visible(actor, row)]
                allowed = {person['id'] for person in task_assignees(con, actor)}
                for task in tasks:
                    task['location'] = None
                    if actor['role'] == 'superuser' or task['assignee_id'] == actor['id'] or (actor['role'] == 'manager' and task['assignee_id'] in allowed):
                        point = con.execute('SELECT * FROM visit_locations WHERE task_id=? AND employee_id=?', (task['id'], task['assignee_id'])).fetchone()
                        if point:
                            location = dict(point)
                            location['is_recent'] = bool(location['active'] and location['received_at'] and time.time() - location['received_at'] < 180 and location['captured_at'] and time.time() - location['captured_at'] < 180)
                            task['location'] = location
                return self.respond(200, {'tasks': tasks, 'assignees': task_assignees(con, actor)})
            if self.path in ('/api/users', '/api/teams'):
                user = self.current_user(con)
                if not user:
                    return self.respond(401, {'error': 'Please sign in.'})
                if user['role'] not in ('superuser', 'manager'):
                    return self.respond(403, {'error': 'Manager or Super User access required.'})
                if self.path == '/api/teams':
                    teams = [dict(row) for row in con.execute('SELECT * FROM teams ORDER BY name' if user['role'] == 'superuser' else 'SELECT * FROM teams WHERE manager_id=? ORDER BY name', () if user['role'] == 'superuser' else (user['id'],))]
                    for team in teams:
                        team['employee_ids'] = [row[0] for row in con.execute('SELECT employee_id FROM team_members WHERE team_id=? ORDER BY employee_id', (team['id'],))]
                    return self.respond(200, {'teams': teams})
                allowed = visible_employees(con, user['id']) if user['role'] == 'manager' else None
                return self.respond(200, {'users': [public_user(row) for row in con.execute('SELECT * FROM users ORDER BY id') if allowed is None or row['id'] in allowed]})
            return self.respond(404, {'error': 'Not found.'})

    def do_POST(self):
        # Non-simple requests cannot be submitted cross-origin without a preflight.
        if self.headers.get('X-Requested-With') != 'app':
            return self.respond(403, {'error': 'Invalid request origin.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 16000:
                raise ValueError()
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError()
            self.handle_post(data)
        except (ValueError, TypeError, KeyError):
            self.respond(400, {'error': 'Invalid request.'})
        except sqlite3.IntegrityError:
            self.respond(409, {'error': 'A team with that name already exists.' if self.path.startswith('/api/teams') else 'An account with that email already exists.'})

    def handle_post(self, data):
        with database() as con:
            if self.path in ('/api/payroll/settings', '/api/payroll/salary', '/api/payroll/generate', '/api/payroll/update', '/api/payroll/approve', '/api/payroll/paid'):
                con.execute('BEGIN IMMEDIATE')
                actor = self.current_user(con)
                if not actor:
                    return self.respond(401, {'error': 'Please sign in.'})
                if actor['role'] != 'superuser':
                    return self.respond(403, {'error': 'Only Super Users can change payroll.'})
                if self.path == '/api/payroll/settings':
                    month, leave, notes = data.get('month'), data.get('paid_leave_days'), data.get('notes', '')
                    if not valid_month(month) or type(leave) is not int or not isinstance(notes, str) or len(notes) > 1000:
                        return self.respond(400, {'error': 'Enter a valid month, whole paid-leave days, and notes up to 1000 characters.'})
                    year, month_number = map(int, month.split('-'))
                    working = calendar.monthrange(year, month_number)[1]
                    if not 0 <= leave <= working:
                        return self.respond(400, {'error': 'Paid leave must be between zero and the calendar days in the month.'})
                    try:
                        rate = payroll_amounts({'base': '1', 'allowances': data.get('night_shift_rate', '0')})[1]
                    except ValueError:
                        return self.respond(400, {'error': 'Enter a nonnegative night-shift rate with at most two decimals.'})
                    con.execute('INSERT INTO payroll_month_settings(month,working_days,paid_leave_days,notes,updated_by,updated_at,night_shift_rate) VALUES(?,?,?,?,?,?,?) ON CONFLICT(month) DO UPDATE SET working_days=excluded.working_days,paid_leave_days=excluded.paid_leave_days,notes=excluded.notes,updated_by=excluded.updated_by,updated_at=excluded.updated_at,night_shift_rate=excluded.night_shift_rate', (month, working, leave, notes.strip(), actor['id'], time.time(), rate))
                    return self.respond(200, {'ok': True})
                if self.path == '/api/payroll/salary':
                    user_id = data.get('user_id')
                    if type(user_id) is not int or not con.execute("SELECT id FROM users WHERE id=? AND role IN ('employee','manager')", (user_id,)).fetchone():
                        return self.respond(400, {'error': 'Choose an Employee or Manager account.'})
                    try:
                        base, allowances, deductions = payroll_amounts(data)
                    except ValueError:
                        return self.respond(400, {'error': 'Use nonnegative amounts with at most two decimals. Base salary must be positive; deductions cannot exceed earnings.'})
                    con.execute('INSERT INTO salaries VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET base=excluded.base,allowances=excluded.allowances,deductions=excluded.deductions,updated_by=excluded.updated_by,updated_at=excluded.updated_at', (user_id, base, allowances, deductions, actor['id'], time.time()))
                    return self.respond(200, {'ok': True})
                if self.path == '/api/payroll/generate':
                    month = data.get('month')
                    policy = data.get('attendance_policy', 'calendar')
                    if policy not in ('calendar', 'fixed30', 'working'):
                        return self.respond(400, {'error': 'Choose a valid attendance deduction basis.'})
                    if not valid_month(month):
                        return self.respond(400, {'error': 'Choose a valid payroll month.'})
                    if policy == 'working' and not con.execute('SELECT month FROM payroll_month_settings WHERE month=?', (month,)).fetchone():
                        return self.respond(400, {'error': 'Set the working days and paid-leave allowance for this month first.'})
                    people = con.execute("SELECT users.*,salaries.base,salaries.allowances,salaries.deductions FROM salaries JOIN users ON users.id=salaries.user_id WHERE users.role IN ('employee','manager')").fetchall()
                    if not people:
                        return self.respond(400, {'error': 'Set up at least one monthly salary first.'})
                    created = 0
                    for person in people:
                        cursor = con.execute('INSERT OR IGNORE INTO payroll(user_id,month,name,email,role,base,allowances,deductions,created_by,created_at,attendance_policy) VALUES(?,?,?,?,?,?,?,?,?,?,?)', (person['id'], month, person['name'], person['email'], person['role'], person['base'], person['allowances'], person['deductions'], actor['id'], time.time(), policy))
                        created += cursor.rowcount
                    return self.respond(200, {'created': created})
                if type(data.get('id')) is not int:
                    return self.respond(400, {'error': 'Choose a payroll record.'})
                row = con.execute('SELECT * FROM payroll WHERE id=?', (data['id'],)).fetchone()
                if not row:
                    return self.respond(404, {'error': 'Payroll record not found.'})
                if self.path in ('/api/payroll/update', '/api/payroll/approve') and row['status'] != 'Draft':
                    return self.respond(409, {'error': 'Approved and paid payroll records are locked.'})
                if self.path == '/api/payroll/update':
                    try:
                        base, allowances, deductions = payroll_amounts(data)
                    except ValueError:
                        return self.respond(400, {'error': 'Enter valid amounts. Deductions cannot exceed earnings.'})
                    policy = data.get('attendance_policy', row['attendance_policy'])
                    if policy not in ('calendar', 'fixed30', 'working'):
                        return self.respond(400, {'error': 'Choose a valid attendance deduction basis.'})
                    candidate = payroll_attendance(con, {**dict(row), 'base': base, 'allowances': allowances, 'deductions': deductions, 'attendance_policy': policy})
                    if candidate['net_pay'] < 0:
                        return self.respond(400, {'error': 'Attendance and manual deductions together exceed earnings. Reduce manual deductions.'})
                    con.execute('UPDATE payroll SET base=?,allowances=?,deductions=?,attendance_policy=? WHERE id=?', (base, allowances, deductions, policy, row['id']))
                elif self.path == '/api/payroll/approve':
                    if con.execute("SELECT id FROM payroll WHERE user_id=? AND month>=? AND month<? AND status='Draft' LIMIT 1", (row['user_id'], row['month'][:4] + '-01', row['month'])).fetchone():
                        return self.respond(409, {'error': 'Approve this person’s earlier draft months first so leave carry-forward is finalized.'})
                    if con.execute("SELECT id FROM payroll WHERE user_id=? AND month>? AND month<=? AND status IN ('Approved','Paid') LIMIT 1", (row['user_id'], row['month'], row['month'][:4] + '-12')).fetchone():
                        return self.respond(409, {'error': 'A later month is already approved. Payroll must be approved in month order to preserve leave balances.'})
                    calculated = payroll_attendance(con, row)
                    if calculated['net_pay'] < 0:
                        return self.respond(409, {'error': 'Combined deductions exceed earnings. Edit the draft before approval.'})
                    if 'expected_net_pay' in data and (data['expected_net_pay'] != calculated['net_pay'] or data.get('expected_absent_days') != calculated['absent_days']):
                        return self.respond(409, {'error': 'Attendance or amounts changed. Close this dialog, refresh payroll, and review before approving.'})
                    if any(key in data and data[key] != calculated[field] for key, field in [('expected_basis_days', 'basis_days'), ('expected_leave_days', 'leave_days'), ('expected_paid_leave_allowance', 'paid_leave_allowance'), ('expected_leave_opening', 'leave_opening'), ('expected_night_shifts', 'night_shifts'), ('expected_night_shift_rate', 'night_shift_rate'), ('expected_night_hours_hundredths', 'night_hours_hundredths')]):
                        return self.respond(409, {'error': 'Monthly settings or leave changed. Refresh and review before approving.'})
                    con.execute("UPDATE payroll SET status='Approved',approved_by=?,approved_at=?,attendance_deduction=?,absent_days=?,basis_days=?,attendance_at=?,leave_days=?,paid_leave_allowance=?,unpaid_days=?,attendance_policy=? WHERE id=?", (actor['id'], time.time(), calculated['attendance_deduction'], calculated['absent_days'], calculated['basis_days'], time.time(), calculated['leave_days'], calculated['paid_leave_allowance'], calculated['unpaid_days'], calculated['attendance_policy'], row['id']))
                    con.execute('UPDATE payroll SET leave_opening=?,paid_leave_used=?,leave_balance_after=?,night_shifts=?,night_shift_rate=?,night_shift_pay=?,night_hours_hundredths=? WHERE id=?', (calculated['leave_opening'], calculated['paid_leave_used'], calculated['leave_balance_after'], calculated['night_shifts'], calculated['night_shift_rate'], calculated['night_shift_pay'], calculated['night_hours_hundredths'], row['id']))
                else:
                    if row['status'] != 'Approved':
                        return self.respond(409, {'error': 'Only an approved record can be marked paid.'})
                    reference = data.get('payment_reference', '')
                    if not isinstance(reference, str) or len(reference) > 200:
                        return self.respond(400, {'error': 'Payment reference must be at most 200 characters.'})
                    con.execute("UPDATE payroll SET status='Paid',paid_by=?,paid_at=?,payment_reference=? WHERE id=?", (actor['id'], time.time(), reference.strip(), row['id']))
                return self.respond(200, {'ok': True})
            if self.path in ('/api/visits/start', '/api/visits/location', '/api/visits/stop'):
                con.execute('BEGIN IMMEDIATE')
                actor = self.current_user(con)
                if not actor:
                    return self.respond(401, {'error': 'Please sign in.'})
                if type(data.get('task_id')) is not int:
                    return self.respond(400, {'error': 'Choose a valid site-visit task.'})
                task = con.execute('SELECT * FROM tasks WHERE id=?', (data['task_id'],)).fetchone()
                if not task or actor['role'] != 'employee' or task['assignee_id'] != actor['id'] or task['task_type'] != 'site_visit':
                    return self.respond(403, {'error': 'Only the assigned employee can share this site-visit location.'})
                if self.path == '/api/visits/stop':
                    con.execute('UPDATE visit_locations SET active=0 WHERE task_id=?', (task['id'],))
                    return self.respond(200, {'ok': True})
                if task['status'] == 'Done':
                    return self.respond(400, {'error': 'This task is complete. Location sharing is stopped.'})
                if self.path == '/api/visits/start':
                    # One active visit per employee. Each new start discards the previous point.
                    con.execute('UPDATE visit_locations SET active=0 WHERE employee_id=?', (actor['id'],))
                    con.execute('INSERT INTO visit_locations(task_id,employee_id,active) VALUES(?,?,1) ON CONFLICT(task_id) DO UPDATE SET employee_id=excluded.employee_id,active=1,latitude=NULL,longitude=NULL,accuracy=NULL,captured_at=NULL,received_at=NULL', (task['id'], actor['id']))
                    return self.respond(200, {'ok': True})
                point = con.execute('SELECT * FROM visit_locations WHERE task_id=? AND employee_id=? AND active=1', (task['id'], actor['id'])).fetchone()
                if not point:
                    return self.respond(409, {'error': 'Start location sharing for this visit first.'})
                lat, lng, accuracy, captured = (data.get(key) for key in ('latitude', 'longitude', 'accuracy', 'captured_at'))
                if any(type(value) not in (int, float) or not math.isfinite(value) for value in (lat, lng, accuracy, captured)) or not -90 <= lat <= 90 or not -180 <= lng <= 180 or accuracy < 0 or captured > time.time() + 300 or captured < time.time() - 86400:
                    return self.respond(400, {'error': 'Invalid location coordinates or timestamp.'})
                if point['captured_at'] is None or captured > point['captured_at']:
                    con.execute('UPDATE visit_locations SET latitude=?,longitude=?,accuracy=?,captured_at=?,received_at=? WHERE task_id=?', (lat, lng, accuracy, captured, time.time(), task['id']))
                return self.respond(200, {'ok': True})
            if self.path == '/api/profile':
                con.execute('BEGIN IMMEDIATE')
                actor = self.current_user(con)
                if not actor:
                    return self.respond(401, {'error': 'Please sign in.'})
                name, email = data.get('name'), data.get('email')
                current_password, new_password = data.get('current_password', ''), data.get('new_password', '')
                if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100 or not isinstance(email, str) or not 3 <= len(email.strip()) <= 254 or '@' not in email:
                    return self.respond(400, {'error': 'Enter a name and valid email address.'})
                if not isinstance(current_password, str) or not isinstance(new_password, str) or len(current_password) > 256:
                    return self.respond(400, {'error': 'Invalid password.'})
                email = email.strip().lower()
                if email != actor['email'] or new_password:
                    if not current_password or not password_valid(current_password, actor['password']):
                        return self.respond(400, {'error': 'Enter your current password to change email or password.'})
                if new_password and not 10 <= len(new_password) <= 256:
                    return self.respond(400, {'error': 'Use a new password with 10–256 characters.'})
                con.execute('UPDATE users SET name=?, email=? WHERE id=?', (name.strip(), email, actor['id']))
                if new_password:
                    con.execute('UPDATE users SET password=? WHERE id=?', (password_hash(new_password), actor['id']))
                    con.execute('DELETE FROM sessions WHERE user_id=? AND token<>?', (actor['id'], self.token()))
                updated = con.execute('SELECT * FROM users WHERE id=?', (actor['id'],)).fetchone()
                return self.respond(200, {'user': public_user(updated)})
            if self.path == '/api/attendance':
                con.execute('BEGIN IMMEDIATE')
                actor = self.current_user(con)
                if not actor:
                    return self.respond(401, {'error': 'Please sign in.'})
                if actor['role'] not in ('superuser', 'manager'):
                    return self.respond(403, {'error': 'Only Managers and Super Users can mark attendance.'})
                user_id, day, status = data.get('user_id'), data.get('day'), data.get('status')
                night_shift = data.get('night_shift', False)
                if type(night_shift) is not bool or (night_shift and status != 'Present'):
                    return self.respond(400, {'error': 'Night shift can only be marked for a Present day.'})
                try:
                    value = data.get('night_hours', '0')
                    if not isinstance(value, (str, int)) or isinstance(value, bool):
                        raise ValueError()
                    hours = Decimal(str(value))
                    if not hours.is_finite() or not 0 <= hours <= 24 or hours.as_tuple().exponent < -2 or (night_shift and hours == 0) or (not night_shift and hours != 0):
                        raise ValueError()
                    night_hours = int(hours * 100)
                except (ValueError, InvalidOperation):
                    return self.respond(400, {'error': 'Enter night hours between 0.01 and 24 with at most two decimals, or clear the night-shift selection.'})
                if type(user_id) is not int or not isinstance(day, str) or status not in ('Present', 'Absent', 'Leave', 'Unmarked'):
                    return self.respond(400, {'error': 'Choose a person, date, and valid attendance status.'})
                try:
                    if date.fromisoformat(day).isoformat() != day:
                        raise ValueError()
                except ValueError:
                    return self.respond(400, {'error': 'Choose a valid date.'})
                # Managers mark team employees; only Super Users mark Manager attendance.
                permitted = {person['id'] for person in (attendance_people(con, actor) if actor['role'] == 'superuser' else task_assignees(con, actor))}
                if user_id not in permitted:
                    return self.respond(403, {'error': 'You cannot mark attendance for this person.'})
                if status == 'Unmarked':
                    con.execute('DELETE FROM attendance WHERE user_id=? AND day=?', (user_id, day))
                else:
                    con.execute('INSERT INTO attendance(user_id,day,status,marked_by,updated_at,night_shift,night_hours_hundredths) VALUES(?,?,?,?,?,?,?) ON CONFLICT(user_id,day) DO UPDATE SET status=excluded.status,marked_by=excluded.marked_by,updated_at=excluded.updated_at,night_shift=excluded.night_shift,night_hours_hundredths=excluded.night_hours_hundredths', (user_id, day, status, actor['id'], time.time(), int(night_shift), night_hours))
                return self.respond(200, {'ok': True})
            if self.path in ('/api/tasks', '/api/tasks/update', '/api/tasks/status'):
                con.execute('BEGIN IMMEDIATE')
                actor = self.current_user(con)
                if not actor:
                    return self.respond(401, {'error': 'Please sign in.'})
                task = None
                if self.path != '/api/tasks':
                    if type(data.get('id')) is not int:
                        return self.respond(400, {'error': 'Choose a valid task.'})
                    task = con.execute('SELECT * FROM tasks WHERE id=?', (data['id'],)).fetchone()
                    if not task or not task_visible(actor, task):
                        return self.respond(404, {'error': 'Task not found.'})
                    if actor['role'] == 'manager' and task['assignee_id'] != actor['id'] and task['assignee_id'] not in {item['id'] for item in task_assignees(con, actor)}:
                        return self.respond(403, {'error': 'This task is no longer assigned within your teams.'})
                if self.path == '/api/tasks/status':
                    if actor['role'] != 'superuser' and task['assignee_id'] != actor['id'] and not (actor['role'] == 'manager' and actor['id'] in (task['created_by'], task['assigned_by'])):
                        return self.respond(403, {'error': 'You cannot update this task.'})
                    status = data.get('status')
                    if status not in ('To do', 'In progress', 'Done'):
                        return self.respond(400, {'error': 'Choose a valid task status.'})
                    con.execute('UPDATE tasks SET status=? WHERE id=?', (status, task['id']))
                    if status == 'Done':
                        con.execute('UPDATE visit_locations SET active=0 WHERE task_id=?', (task['id'],))
                    return self.respond(200, {'ok': True})
                if actor['role'] not in ('superuser', 'manager'):
                    return self.respond(403, {'error': 'Only Super Users and Managers can assign tasks.'})
                title, description, due = data.get('title'), data.get('description', ''), data.get('due_date', '')
                assignee_id = data.get('assignee_id')
                task_type, site_address = data.get('task_type', task['task_type'] if task else 'standard'), data.get('site_address', task['site_address'] if task else '')
                if task_type not in ('standard', 'site_visit') or not isinstance(site_address, str) or len(site_address) > 500 or (task_type == 'site_visit' and not site_address.strip()):
                    return self.respond(400, {'error': 'Site visits need a site address (up to 500 characters).'})
                if not isinstance(title, str) or not 1 <= len(title.strip()) <= 200 or not isinstance(description, str) or len(description) > 4000 or not isinstance(due, str):
                    return self.respond(400, {'error': 'Enter a task title (up to 200 characters) and description (up to 4000 characters).'})
                if due:
                    try:
                        if date.fromisoformat(due).isoformat() != due:
                            raise ValueError()
                    except ValueError:
                        return self.respond(400, {'error': 'Choose a valid due date.'})
                # Existing manager assignments may be retained when editing an assigned task.
                allowed = {item['id'] for item in task_assignees(con, actor)}
                if task and task['assignee_id'] == actor['id']:
                    allowed.add(actor['id'])
                if type(assignee_id) is not int or assignee_id not in allowed:
                    return self.respond(403, {'error': 'Choose a permitted assignee. Managers can assign only employees in their teams.'})
                if task:
                    con.execute('UPDATE tasks SET title=?,description=?,due_date=?,assignee_id=?,assigned_by=? WHERE id=?', (title.strip(), description.strip(), due, assignee_id, actor['id'], task['id']))
                    con.execute('UPDATE tasks SET task_type=?,site_address=? WHERE id=?', (task_type, site_address.strip() if task_type == 'site_visit' else '', task['id']))
                    if assignee_id != task['assignee_id'] or task_type != task['task_type']:
                        con.execute('DELETE FROM visit_locations WHERE task_id=?', (task['id'],))
                    return self.respond(200, {'ok': True})
                cursor = con.execute('INSERT INTO tasks(title,description,assignee_id,created_by,assigned_by,due_date,created_at) VALUES(?,?,?,?,?,?,?)', (title.strip(), description.strip(), assignee_id, actor['id'], actor['id'], due, time.time()))
                con.execute('UPDATE tasks SET task_type=?,site_address=? WHERE id=?', (task_type, site_address.strip() if task_type == 'site_visit' else '', cursor.lastrowid))
                return self.respond(201, {'id': cursor.lastrowid})
            if self.path in ('/api/teams', '/api/teams/manager', '/api/teams/members', '/api/employees/teams'):
                con.execute('BEGIN IMMEDIATE')
                actor = self.current_user(con)
                if not actor:
                    return self.respond(401, {'error': 'Please sign in.'})
                if actor['role'] not in ('superuser', 'manager') or (self.path in ('/api/teams', '/api/teams/manager') and actor['role'] != 'superuser'):
                    return self.respond(403, {'error': 'Super User access required.'})
                if self.path == '/api/teams/manager':
                    team_id, manager_id = data.get('team_id'), data.get('manager_id')
                    if type(team_id) is not int or (manager_id is not None and type(manager_id) is not int):
                        return self.respond(400, {'error': 'Choose a valid team and manager.'})
                    if not con.execute('SELECT id FROM teams WHERE id=?', (team_id,)).fetchone():
                        return self.respond(404, {'error': 'Team not found.'})
                    if manager_id is not None and not con.execute("SELECT id FROM users WHERE id=? AND role='manager'", (manager_id,)).fetchone():
                        return self.respond(400, {'error': 'Choose a Manager account.'})
                    con.execute('UPDATE teams SET manager_id=? WHERE id=?', (manager_id, team_id))
                    return self.respond(200, {'ok': True})
                if self.path == '/api/teams':
                    name = data.get('name')
                    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
                        return self.respond(400, {'error': 'Enter a team name with 1–100 characters.'})
                    cursor = con.execute('INSERT INTO teams(name) VALUES(?)', (name.strip(),))
                    return self.respond(201, {'team': {'id': cursor.lastrowid, 'name': name.strip(), 'employee_ids': []}})
                from_team = self.path == '/api/teams/members'
                parent_id = data.get('team_id' if from_team else 'employee_id')
                ids = data.get('employee_ids' if from_team else 'team_ids')
                if type(parent_id) is not int or not isinstance(ids, list) or len(ids) > 1000 or any(type(value) is not int for value in ids):
                    return self.respond(400, {'error': 'Choose valid employees and teams.'})
                parent = con.execute('SELECT id FROM teams WHERE id=?' if from_team else "SELECT id FROM users WHERE id=? AND role='employee'", (parent_id,)).fetchone()
                if not parent:
                    return self.respond(404, {'error': 'Team or employee not found.'})
                ids = sorted(set(ids))
                if actor['role'] == 'manager':
                    owned = {row[0] for row in con.execute('SELECT id FROM teams WHERE manager_id=?', (actor['id'],))}
                    allowed = visible_employees(con, actor['id'])
                    if (from_team and (parent_id not in owned or not set(ids) <= allowed)) or (not from_team and (parent_id not in allowed or not set(ids) <= owned)):
                        return self.respond(403, {'error': 'You can only assign your employees to teams you manage.'})
                for value in ids:
                    valid = con.execute("SELECT id FROM users WHERE id=? AND role='employee'" if from_team else 'SELECT id FROM teams WHERE id=?', (value,)).fetchone()
                    if not valid:
                        return self.respond(400, {'error': 'One or more selected employees or teams no longer exist.'})
                if not from_team and actor['role'] == 'manager':
                    con.execute('DELETE FROM team_members WHERE employee_id=? AND team_id IN (SELECT id FROM teams WHERE manager_id=?)', (parent_id, actor['id']))
                else:
                    con.execute('DELETE FROM team_members WHERE team_id=?' if from_team else 'DELETE FROM team_members WHERE employee_id=?', (parent_id,))
                con.executemany('INSERT INTO team_members(team_id,employee_id) VALUES(?,?)', [(parent_id, value) if from_team else (value, parent_id) for value in ids])
                return self.respond(200, {'ok': True})
            if self.path == '/api/auth/logout':
                actor = self.current_user(con)
                if actor:
                    con.execute('UPDATE visit_locations SET active=0 WHERE employee_id=?', (actor['id'],))
                con.execute('DELETE FROM sessions WHERE token=?', (self.token(),))
                cookie_flags = 'SameSite=None; Secure' if COOKIE_SECURE else 'SameSite=Strict'
                return self.respond(200, {'ok': True}, f'session=; HttpOnly; {cookie_flags}; Path=/; Max-Age=0')
            if self.path in ('/api/auth/login', '/api/mobile/login'):
                client = self.client_address[0]
                now = time.time()
                attempt = con.execute('SELECT * FROM attempts WHERE client=?', (client,)).fetchone()
                if attempt and attempt['reset'] > now and attempt['count'] >= 10:
                    return self.respond(429, {'error': 'Too many attempts. Try again in 15 minutes.'})
                email = str(data.get('email', '')).strip().lower()
                password = str(data.get('password', ''))
                if len(password) > 256:
                    return self.respond(400, {'error': 'Invalid credentials.'})
                user = con.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
                # Perform a hash even for unknown accounts.
                valid = password_valid(password, user['password'] if user else '00'*16 + ':' + '00'*64)
                if not user or not valid:
                    count = attempt['count'] + 1 if attempt and attempt['reset'] > now else 1
                    reset = attempt['reset'] if attempt and attempt['reset'] > now else now + 900
                    con.execute('INSERT OR REPLACE INTO attempts VALUES(?,?,?)', (client, count, reset))
                    return self.respond(401, {'error': 'Email or password is incorrect.'})
                con.execute('DELETE FROM attempts WHERE client=?', (client,))
                return self.sign_in(con, user)
            if self.path in ('/api/auth/setup', '/api/users'):
                # Serialize setup to ensure only one first account can be created.
                con.execute('BEGIN IMMEDIATE')
                if self.path == '/api/auth/setup':
                    if con.execute('SELECT 1 FROM users LIMIT 1').fetchone():
                        return self.respond(409, {'error': 'Setup is already complete. Please sign in.'})
                    role = 'superuser'
                else:
                    actor = self.current_user(con)
                    if not actor:
                        return self.respond(401, {'error': 'Please sign in.'})
                    if actor['role'] not in ('superuser', 'manager'):
                        return self.respond(403, {'error': 'Manager or Super User access required.'})
                    role = data.get('role')
                    if actor['role'] == 'manager' and role != 'employee':
                        return self.respond(403, {'error': 'Managers can only create Employee accounts.'})
                name = str(data.get('name', '')).strip()
                email = str(data.get('email', '')).strip().lower()
                password = str(data.get('password', ''))
                if not 1 <= len(name) <= 100 or not 3 <= len(email) <= 254 or '@' not in email or role not in ROLES:
                    return self.respond(400, {'error': 'Enter a name, valid email, and role.'})
                if not 10 <= len(password) <= 256:
                    return self.respond(400, {'error': 'Use a password with 10–256 characters.'})
                team_ids = data.get('team_ids', [])
                if not isinstance(team_ids, list) or len(team_ids) > 1000 or any(type(value) is not int for value in team_ids) or (role != 'employee' and team_ids):
                    return self.respond(400, {'error': 'Choose valid teams for an Employee account.'})
                for team_id in set(team_ids):
                    team = con.execute('SELECT * FROM teams WHERE id=?', (team_id,)).fetchone()
                    if not team:
                        return self.respond(400, {'error': 'Team not found.'})
                    if self.path != '/api/auth/setup' and actor['role'] == 'manager' and team['manager_id'] != actor['id']:
                        return self.respond(403, {'error': 'You can only assign employees to teams you manage.'})
                cursor = con.execute('INSERT INTO users(name,email,password,role,created_by) VALUES(?,?,?,?,?)', (name, email, password_hash(password), role, actor['id'] if self.path != '/api/auth/setup' else None))
                con.executemany('INSERT INTO team_members(team_id,employee_id) VALUES(?,?)', [(team_id, cursor.lastrowid) for team_id in set(team_ids)])
                user = con.execute('SELECT * FROM users WHERE id=?', (cursor.lastrowid,)).fetchone()
                if self.path == '/api/auth/setup':
                    return self.sign_in(con, user)
                return self.respond(201, {'user': public_user(user)})
            self.respond(404, {'error': 'Not found.'})

    def sign_in(self, con, user):
        token = secrets.token_urlsafe(32)
        con.execute('DELETE FROM sessions WHERE expires<? OR token=?', (time.time(), self.token()))
        con.execute('INSERT INTO sessions VALUES(?,?,?)', (hashlib.sha256(token.encode()).hexdigest(), user['id'], time.time() + 28800))
        result = {'user': public_user(user)}
        if self.path == '/api/mobile/login':
            result['token'] = token
        cookie_flags = 'SameSite=None; Secure' if COOKIE_SECURE else 'SameSite=Strict'
        self.respond(200, result, f'session={token}; HttpOnly; {cookie_flags}; Path=/; Max-Age=28800')

if __name__ == '__main__':
    ThreadingHTTPServer.allow_reuse_address = False
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', '8000'))
    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        if getattr(exc, 'winerror', None) == 10048 or exc.errno == 98:
            sys.exit('Port 8000 is already in use. If this backend is already running, use that instance. Otherwise, stop the process using port 8000 and run python server.py again.')
        raise
    with httpd:
        initialize()
        seed_demo_accounts()
        print(f'Server running at http://{host}:{port}', flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
