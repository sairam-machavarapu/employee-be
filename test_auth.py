"""Run from be: python -m unittest -v"""
import http.cookiejar
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
import server

class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = server.DB
        server.DB = Path(self.temp.name) / 'users.sqlite3'
        server.initialize()
        self.http = server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.base = 'http://127.0.0.1:' + str(self.http.server_port)
        self.client = self.new_client()

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join()
        server.DB = self.old_db
        self.temp.cleanup()

    def new_client(self):
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, path, data=None, client=None, header=True):
        headers = {'Content-Type': 'application/json'}
        if header:
            headers['X-Requested-With'] = 'app'
        request = urllib.request.Request(self.base + path, data=json.dumps(data).encode() if data is not None else None, headers=headers)
        try:
            response = (client or self.client).open(request)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response), response.headers

    def setup_account(self):
        code, result, headers = self.call('/api/auth/setup', {'name': 'Owner', 'email': 'owner@example.com', 'password': 'strong-password', 'role': 'employee'})
        self.assertEqual(code, 200)
        self.assertEqual(result['user']['role'], 'superuser')
        self.assertNotIn('password', result['user'])
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', headers['Set-Cookie'])

    def test_roles_sessions_and_account_management(self):
        self.assertTrue(self.call('/api/auth/status')[1]['needs_setup'])
        self.assertEqual(self.call('/api/users')[0], 401)
        self.setup_account()
        self.assertFalse(self.call('/api/auth/status')[1]['needs_setup'])
        self.assertEqual(self.call('/api/auth/setup', {'name': 'Other'})[0], 409)
        for role in ('manager', 'employee', 'superuser'):
            account = {'name': role, 'email': role + '@example.com', 'password': 'strong-password', 'role': role}
            self.assertEqual(self.call('/api/users', account)[0], 201)
            self.assertEqual(self.call('/api/users', account)[0], 409)
            client = self.new_client()
            code, data, _ = self.call('/api/auth/login', account, client)
            self.assertEqual(code, 200)
            self.assertEqual(data['user']['role'], role)
            self.assertEqual(self.call('/api/auth/status', client=client)[1]['user']['role'], role)
            expected = 200 if role in ('superuser', 'manager') else 403
            self.assertEqual(self.call('/api/users', client=client)[0], expected)
            if role != 'superuser':
                self.assertEqual(self.call('/api/users', account, client)[0], 403)
            self.assertEqual(self.call('/api/auth/logout', {}, client)[0], 200)
            self.assertIsNone(self.call('/api/auth/status', client=client)[1]['user'])
        self.assertEqual(len(self.call('/api/users')[1]['users']), 4)
        with server.database() as con:
            self.assertNotIn('strong-password', con.execute('SELECT password FROM users LIMIT 1').fetchone()[0])

    def test_validation_csrf_and_login_throttling(self):
        self.assertEqual(self.call('/api/auth/setup', {}, header=False)[0], 403)
        self.assertEqual(self.call('/api/auth/setup', {'name': 'Owner', 'email': 'o@example.com', 'password': 'short'})[0], 400)
        self.setup_account()
        self.assertEqual(self.call('/api/users', {'name': 'X', 'email': 'x@example.com', 'password': 'strong-password', 'role': 'admin'})[0], 400)
        client = self.new_client()
        for _ in range(10):
            self.assertEqual(self.call('/api/auth/login', {'email': 'owner@example.com', 'password': 'incorrect'}, client)[0], 401)
        self.assertEqual(self.call('/api/auth/login', {'email': 'owner@example.com', 'password': 'strong-password'}, client)[0], 429)

    def test_team_membership_from_both_screens(self):
        self.assertEqual(self.call('/api/teams')[0], 401)
        self.assertEqual(self.call('/api/teams', {'name': 'Blocked'})[0], 401)
        self.setup_account()
        def employee(name):
            code, result, _ = self.call('/api/users', {'name': name, 'email': name + '@example.com', 'password': 'strong-password', 'role': 'employee'})
            self.assertEqual(code, 201)
            return result['user']['id']
        first, second = employee('First'), employee('Second')
        code, result, _ = self.call('/api/teams', {'name': 'Operations'})
        self.assertEqual(code, 201)
        team_a = result['team']['id']
        team_b = self.call('/api/teams', {'name': 'Support'})[1]['team']['id']
        self.assertEqual(self.call('/api/teams', {'name': ' operations '})[0], 409)
        self.assertEqual(self.call('/api/teams', {'name': '  '})[0], 400)
        self.assertEqual(self.call('/api/teams/members', {'team_id': team_a, 'employee_ids': [first, second, first]})[0], 200)
        self.assertEqual(self.call('/api/teams')[1]['teams'][0]['employee_ids'], [first, second])
        self.assertEqual(self.call('/api/employees/teams', {'employee_id': first, 'team_ids': [team_a, team_b]})[0], 200)
        teams = self.call('/api/teams')[1]['teams']
        self.assertEqual(teams[1]['employee_ids'], [first])
        self.assertEqual(self.call('/api/teams/members', {'team_id': team_a, 'employee_ids': [99999]})[0], 400)
        self.assertEqual(self.call('/api/teams')[1]['teams'][0]['employee_ids'], [first, second])
        owner_id = self.call('/api/auth/status')[1]['user']['id']
        self.assertEqual(self.call('/api/teams/members', {'team_id': team_a, 'employee_ids': [owner_id]})[0], 400)
        self.assertEqual(self.call('/api/employees/teams', {'employee_id': first, 'team_ids': [99999]})[0], 400)
        self.assertEqual(self.call('/api/teams/members', {'team_id': True, 'employee_ids': []})[0], 400)
        self.assertEqual(self.call('/api/teams/members', {'team_id': 99999, 'employee_ids': []})[0], 404)
        self.assertEqual(self.call('/api/employees/teams', {'employee_id': first, 'team_ids': []})[0], 200)
        self.assertEqual(self.call('/api/teams')[1]['teams'][0]['employee_ids'], [second])
        self.assertEqual(self.call('/api/teams')[1]['teams'][1]['employee_ids'], [])
        self.assertEqual(self.call('/api/teams/members', {'team_id': team_a, 'employee_ids': []})[0], 200)
        self.assertEqual(self.call('/api/teams')[1]['teams'][0]['employee_ids'], [])
        for role in ('employee', 'manager'):
            email = 'restricted-' + role + '@example.com'
            self.call('/api/users', {'name': role, 'email': email, 'password': 'strong-password', 'role': role})
            client = self.new_client()
            self.call('/api/auth/login', {'email': email, 'password': 'strong-password'}, client)
            self.assertEqual(self.call('/api/teams', client=client)[0], 200 if role == 'manager' else 403)
            for path, data in [('/api/teams', {'name': 'Forbidden'}), ('/api/teams/members', {'team_id': team_a, 'employee_ids': [first]}), ('/api/employees/teams', {'employee_id': first, 'team_ids': [team_a]})]:
                self.assertEqual(self.call(path, data, client)[0], 403)

    def test_manager_employee_creation_and_team_scope(self):
        self.setup_account()
        def account(name, role='employee', client=None, team_ids=None):
            return self.call('/api/users', {'name': name, 'email': name + '@example.com', 'password': 'strong-password', 'role': role, 'team_ids': team_ids or []}, client)
        manager_id = account('ManagerOne', 'manager')[1]['user']['id']
        other_manager = account('ManagerTwo', 'manager')[1]['user']['id']
        team_a = self.call('/api/teams', {'name': 'A'})[1]['team']['id']
        team_b = self.call('/api/teams', {'name': 'B'})[1]['team']['id']
        self.assertEqual(self.call('/api/teams/manager', {'team_id': team_a, 'manager_id': manager_id})[0], 200)
        self.assertEqual(self.call('/api/teams/manager', {'team_id': team_b, 'manager_id': other_manager})[0], 200)
        client = self.new_client()
        self.call('/api/auth/login', {'email': 'ManagerOne@example.com', 'password': 'strong-password'}, client)
        self.assertEqual([t['id'] for t in self.call('/api/teams', client=client)[1]['teams']], [team_a])
        self.assertEqual(account('Escalation', 'superuser', client)[0], 403)
        self.assertEqual(account('ManagerEscalation', 'manager', client)[0], 403)
        self.assertEqual(account('CrossTeam', client=client, team_ids=[team_b])[0], 403)
        code, result, _ = account('OwnEmployee', client=client, team_ids=[team_a])
        self.assertEqual(code, 201)
        employee_id = result['user']['id']
        outsider = account('OtherEmployee')[1]['user']['id']
        self.assertEqual([u['id'] for u in self.call('/api/users', client=client)[1]['users']], [employee_id])
        self.assertEqual(self.call('/api/teams/members', {'team_id': team_a, 'employee_ids': [outsider]}, client)[0], 403)
        self.assertEqual(self.call('/api/employees/teams', {'employee_id': outsider, 'team_ids': [team_a]}, client)[0], 403)
        self.assertEqual(self.call('/api/teams/members', {'team_id': team_b, 'employee_ids': [employee_id]}, client)[0], 403)
        self.assertEqual(self.call('/api/teams/manager', {'team_id': team_b, 'manager_id': manager_id}, client)[0], 403)
        self.assertEqual(self.call('/api/teams/manager', {'team_id': team_b, 'manager_id': employee_id})[0], 400)
        # A manager changing their mappings must preserve other managers' mappings.
        self.call('/api/employees/teams', {'employee_id': employee_id, 'team_ids': [team_a, team_b]})
        self.assertEqual(self.call('/api/employees/teams', {'employee_id': employee_id, 'team_ids': []}, client)[0], 200)
        self.assertEqual(self.call('/api/teams')[1]['teams'][1]['employee_ids'], [employee_id])
        self.assertEqual(self.call('/api/employees/teams', {'employee_id': employee_id, 'team_ids': [team_a]}, client)[0], 200)
        self.assertEqual(self.call('/api/teams')[1]['teams'][0]['employee_ids'], [employee_id])
        # Super User assignment grants visibility of an existing employee to a manager.
        self.call('/api/teams/members', {'team_id': team_a, 'employee_ids': [employee_id, outsider]})
        self.assertEqual(len(self.call('/api/users', client=client)[1]['users']), 2)
        self.call('/api/teams/manager', {'team_id': team_a, 'manager_id': None})
        self.assertEqual(self.call('/api/teams', client=client)[1]['teams'], [])
        self.assertEqual(self.call('/api/employees/teams', {'employee_id': employee_id, 'team_ids': [team_a]}, client)[0], 403)
        with server.database() as con:
            self.assertFalse(con.execute("SELECT id FROM users WHERE email='crossteam@example.com'").fetchone())

    def test_task_assignment_permissions_and_progress(self):
        self.assertEqual(self.call('/api/tasks')[0], 401)
        self.assertEqual(self.call('/api/tasks', {'title': 'X'})[0], 401)
        self.setup_account()
        def add(name, role):
            return self.call('/api/users', {'name': name, 'email': name + '@example.com', 'password': 'strong-password', 'role': role})[1]['user']['id']
        manager_id, employee_id, outsider_id = add('TaskManager', 'manager'), add('TaskEmployee', 'employee'), add('Outsider', 'employee')
        manager, employee, outsider = self.new_client(), self.new_client(), self.new_client()
        for name, client in [('TaskManager', manager), ('TaskEmployee', employee), ('Outsider', outsider)]:
            self.call('/api/auth/login', {'email': name + '@example.com', 'password': 'strong-password'}, client)
        team_id = self.call('/api/teams', {'name': 'Task Team'})[1]['team']['id']
        self.call('/api/teams/manager', {'team_id': team_id, 'manager_id': manager_id})
        self.call('/api/teams/members', {'team_id': team_id, 'employee_ids': [employee_id]})
        self.assertEqual([u['id'] for u in self.call('/api/tasks', client=manager)[1]['assignees']], [employee_id])
        task = {'title': 'Prepare report', 'description': 'Monthly report', 'assignee_id': manager_id, 'due_date': '2026-12-01'}
        code, result, _ = self.call('/api/tasks', task)
        self.assertEqual(code, 201)
        task_id = result['id']
        self.assertEqual(len(self.call('/api/tasks', client=manager)[1]['tasks']), 1)
        self.assertEqual(self.call('/api/tasks', client=employee)[1]['tasks'], [])
        self.assertEqual(self.call('/api/tasks', {**task, 'assignee_id': outsider_id}, manager)[0], 403)
        self.assertEqual(self.call('/api/tasks', task, manager)[0], 403)
        self.assertEqual(self.call('/api/tasks', {**task, 'assignee_id': employee_id}, employee)[0], 403)
        self.assertEqual(self.call('/api/tasks', {**task, 'due_date': '2026-02-30'})[0], 400)
        self.assertEqual(self.call('/api/tasks', {**task, 'title': '   '})[0], 400)
        owner_id = self.call('/api/auth/status')[1]['user']['id']
        self.assertEqual(self.call('/api/tasks', {**task, 'assignee_id': owner_id})[0], 403)
        delegated = {**task, 'id': task_id, 'assignee_id': employee_id}
        self.assertEqual(self.call('/api/tasks/update', delegated, manager)[0], 200)
        self.assertEqual(len(self.call('/api/tasks', client=employee)[1]['tasks']), 1)
        self.assertEqual(len(self.call('/api/tasks', client=manager)[1]['tasks']), 1)
        self.assertEqual(self.call('/api/tasks', client=outsider)[1]['tasks'], [])
        self.assertEqual(self.call('/api/tasks/status', {'id': task_id, 'status': 'Done'}, outsider)[0], 404)
        self.assertEqual(self.call('/api/tasks/update', delegated, employee)[0], 403)
        self.assertEqual(self.call('/api/tasks/status', {'id': task_id, 'status': 'Invalid'}, employee)[0], 400)
        self.assertEqual(self.call('/api/tasks/status', {'id': task_id, 'status': 'In progress'}, employee)[0], 200)
        self.assertEqual(self.call('/api/tasks/status', {'id': task_id, 'status': 'Done'}, employee)[0], 200)
        self.assertEqual(self.call('/api/tasks')[1]['tasks'][0]['status'], 'Done')
        code, result, _ = self.call('/api/tasks', {**task, 'assignee_id': employee_id}, manager)
        self.assertEqual(code, 201)
        own_id = result['id']
        self.call('/api/teams/members', {'team_id': team_id, 'employee_ids': []})
        self.assertEqual(self.call('/api/tasks/update', {**delegated, 'id': own_id}, manager)[0], 403)
        self.assertEqual(self.call('/api/tasks/status', {'id': own_id, 'status': 'Done'}, manager)[0], 403)
        self.assertEqual(self.call('/api/tasks/update', {**delegated, 'id': own_id, 'assignee_id': outsider_id})[0], 200)
        self.assertEqual(self.call('/api/tasks/status', {'id': own_id, 'status': 'Done'}, employee)[0], 404)

    def test_monthly_attendance_scope_and_marking(self):
        path = '/api/attendance?month=2026-11'
        self.assertEqual(self.call(path)[0], 401)
        self.setup_account()
        def add(name, role):
            return self.call('/api/users', {'name': name, 'email': name + '@example.com', 'password': 'strong-password', 'role': role})[1]['user']['id']
        manager_id, employee_id, other_id = add('AttendanceManager', 'manager'), add('AttendanceEmployee', 'employee'), add('OtherEmployee', 'employee')
        manager, employee = self.new_client(), self.new_client()
        for name, client in [('AttendanceManager', manager), ('AttendanceEmployee', employee)]:
            self.call('/api/auth/login', {'email': name + '@example.com', 'password': 'strong-password'}, client)
        first = self.call('/api/teams', {'name': 'First Team'})[1]['team']['id']
        second = self.call('/api/teams', {'name': 'Second Team'})[1]['team']['id']
        self.call('/api/teams/manager', {'team_id': first, 'manager_id': manager_id})
        self.call('/api/teams/members', {'team_id': first, 'employee_ids': [employee_id]})
        self.call('/api/teams/members', {'team_id': second, 'employee_ids': [other_id]})
        mark = {'user_id': employee_id, 'day': '2026-11-02', 'status': 'Present'}
        self.assertEqual(self.call('/api/attendance', mark, manager)[0], 200)
        self.assertEqual(self.call('/api/attendance', {**mark, 'user_id': manager_id})[0], 200)
        self.assertEqual(self.call('/api/attendance', {**mark, 'user_id': other_id, 'status': 'Leave'})[0], 200)
        self.assertEqual(self.call('/api/attendance', mark, employee)[0], 403)
        self.assertEqual(self.call('/api/attendance', {**mark, 'user_id': manager_id}, manager)[0], 403)
        self.assertEqual(self.call('/api/attendance', {**mark, 'user_id': other_id}, manager)[0], 403)
        self.assertEqual(self.call('/api/attendance', {**mark, 'day': '2026-02-30'})[0], 400)
        self.assertEqual(self.call('/api/attendance', {**mark, 'status': 'Wrong'})[0], 400)
        self.assertEqual(self.call('/api/attendance?month=2026-13')[0], 400)
        self.assertEqual(self.call('/api/attendance')[0], 400)
        employee_view = self.call(path, client=employee)[1]
        self.assertEqual([p['id'] for p in employee_view['people']], [employee_id])
        self.assertEqual(len(employee_view['records']), 1)
        self.assertEqual(employee_view['teams'], [])
        manager_view = self.call(path, client=manager)[1]
        self.assertEqual({p['id'] for p in manager_view['people']}, {manager_id, employee_id})
        self.assertEqual({r['user_id'] for r in manager_view['records']}, {manager_id, employee_id})
        self.assertEqual(len(manager_view['teams']), 1)
        owner_view = self.call(path)[1]
        self.assertEqual(len(owner_view['teams']), 2)
        self.assertEqual(len(owner_view['records']), 3)
        self.assertEqual(self.call('/api/attendance?month=2026-12')[1]['records'], [])
        self.assertEqual(self.call('/api/attendance', {**mark, 'status': 'Absent'}, manager)[0], 200)
        self.assertEqual(self.call(path, client=employee)[1]['records'][0]['status'], 'Absent')
        self.assertEqual(self.call('/api/attendance', {**mark, 'status': 'Unmarked'}, manager)[0], 200)
        self.assertEqual(self.call(path, client=employee)[1]['records'], [])
        self.call('/api/teams/manager', {'team_id': first, 'manager_id': None})
        self.assertEqual(self.call('/api/attendance', mark, manager)[0], 403)
        self.assertEqual([p['id'] for p in self.call(path, client=manager)[1]['people']], [manager_id])

    def test_profile_updates_and_password_change(self):
        self.assertEqual(self.call('/api/profile', {'name': 'X', 'email': 'x@example.com'})[0], 401)
        self.setup_account()
        second = self.new_client()
        self.call('/api/auth/login', {'email': 'owner@example.com', 'password': 'strong-password'}, second)
        form = {'name': 'Updated Owner', 'email': 'owner@example.com', 'role': 'employee'}
        code, result, _ = self.call('/api/profile', form)
        self.assertEqual(code, 200)
        self.assertEqual(result['user']['name'], 'Updated Owner')
        self.assertEqual(result['user']['role'], 'superuser')
        self.assertEqual(self.call('/api/profile', {**form, 'email': 'new@example.com'})[0], 400)
        self.assertEqual(self.call('/api/profile', {**form, 'new_password': 'short', 'current_password': 'strong-password'})[0], 400)
        changed = {**form, 'email': 'new@example.com', 'current_password': 'strong-password', 'new_password': 'new-strong-password'}
        self.assertEqual(self.call('/api/profile', changed)[0], 200)
        self.assertIsNone(self.call('/api/auth/status', client=second)[1]['user'])
        self.assertEqual(self.call('/api/auth/status')[1]['user']['email'], 'new@example.com')
        self.assertEqual(self.call('/api/auth/login', {'email': 'new@example.com', 'password': 'strong-password'}, second)[0], 401)
        self.assertEqual(self.call('/api/auth/login', {'email': 'new@example.com', 'password': 'new-strong-password'}, second)[0], 200)
        self.call('/api/users', {'name': 'Other', 'email': 'other@example.com', 'password': 'strong-password', 'role': 'employee'})
        self.assertEqual(self.call('/api/profile', {**form, 'name': 'Should roll back', 'email': 'other@example.com', 'current_password': 'new-strong-password'})[0], 409)
        self.assertEqual(self.call('/api/auth/status')[1]['user']['name'], 'Updated Owner')
        employee = self.new_client()
        self.call('/api/auth/login', {'email': 'other@example.com', 'password': 'strong-password'}, employee)
        code, result, _ = self.call('/api/profile', {'name': 'Employee Updated', 'email': 'other@example.com', 'role': 'superuser', 'id': 1}, employee)
        self.assertEqual(code, 200)
        self.assertEqual(result['user']['role'], 'employee')
        self.assertNotEqual(result['user']['id'], 1)

    def test_site_visit_tracking_permissions_and_lifecycle(self):
        import time
        self.setup_account()
        def add(name, role):
            return self.call('/api/users', {'name': name, 'email': name + '@example.com', 'password': 'strong-password', 'role': role})[1]['user']['id']
        employee_id, manager_id = add('Visitor', 'employee'), add('VisitManager', 'manager')
        employee, manager = self.new_client(), self.new_client()
        self.call('/api/auth/login', {'email': 'Visitor@example.com', 'password': 'strong-password'}, employee)
        self.call('/api/auth/login', {'email': 'VisitManager@example.com', 'password': 'strong-password'}, manager)
        team = self.call('/api/teams', {'name': 'Visits'})[1]['team']['id']
        self.call('/api/teams/manager', {'team_id': team, 'manager_id': manager_id})
        self.call('/api/teams/members', {'team_id': team, 'employee_ids': [employee_id]})
        task = {'title': 'Visit client', 'description': '', 'assignee_id': employee_id, 'task_type': 'site_visit', 'site_address': 'Client office'}
        self.assertEqual(self.call('/api/tasks', {**task, 'site_address': ''})[0], 400)
        code, result, _ = self.call('/api/tasks', task, manager)
        self.assertEqual(code, 201)
        task_id = result['id']
        point = {'task_id': task_id, 'latitude': 16.5, 'longitude': 80.6, 'accuracy': 15, 'captured_at': time.time()}
        self.assertEqual(self.call('/api/visits/location', point, employee)[0], 409)
        self.assertEqual(self.call('/api/visits/start', {'task_id': task_id}, manager)[0], 403)
        self.assertEqual(self.call('/api/visits/start', {'task_id': task_id}, employee)[0], 200)
        self.assertEqual(self.call('/api/visits/location', {**point, 'latitude': 200}, employee)[0], 400)
        self.assertEqual(self.call('/api/visits/location', point, employee)[0], 200)
        location = self.call('/api/tasks', client=manager)[1]['tasks'][0]['location']
        self.assertTrue(location['is_recent'])
        self.assertEqual(location['latitude'], 16.5)
        self.call('/api/visits/location', {**point, 'latitude': 10, 'captured_at': point['captured_at'] - 10}, employee)
        self.assertEqual(self.call('/api/tasks')[1]['tasks'][0]['location']['latitude'], 16.5)
        self.assertEqual(self.call('/api/visits/stop', {'task_id': task_id}, employee)[0], 200)
        self.assertFalse(self.call('/api/tasks')[1]['tasks'][0]['location']['is_recent'])
        self.assertEqual(self.call('/api/visits/location', point, employee)[0], 409)
        self.call('/api/visits/start', {'task_id': task_id}, employee)
        self.call('/api/visits/location', point, employee)
        self.call('/api/teams/manager', {'team_id': team, 'manager_id': None})
        self.assertIsNone(self.call('/api/tasks', client=manager)[1]['tasks'][0]['location'])
        self.call('/api/tasks/status', {'id': task_id, 'status': 'Done'})
        self.assertEqual(self.call('/api/visits/location', point, employee)[0], 400)
        self.assertFalse(self.call('/api/tasks')[1]['tasks'][0]['location']['active'])
        self.call('/api/tasks/status', {'id': task_id, 'status': 'To do'})
        self.call('/api/tasks/update', {**task, 'id': task_id, 'task_type': 'standard'})
        self.assertIsNone(self.call('/api/tasks')[1]['tasks'][0]['location'])
        self.assertEqual(self.call('/api/visits/start', {'task_id': task_id}, employee)[0], 403)
        # Mobile token authenticates without browser cookies and is revoked on logout.
        code, login, _ = self.call('/api/mobile/login', {'email': 'Visitor@example.com', 'password': 'strong-password'}, self.new_client())
        self.assertEqual(code, 200)
        request = urllib.request.Request(self.base + '/api/tasks', headers={'Authorization': 'Bearer ' + login['token']})
        with urllib.request.urlopen(request) as response:
            self.assertEqual(response.status, 200)
        request = urllib.request.Request(self.base + '/api/auth/logout', data=b'{}', headers={'Authorization': 'Bearer ' + login['token'], 'X-Requested-With': 'app'})
        urllib.request.urlopen(request).close()
        request = urllib.request.Request(self.base + '/api/tasks', headers={'Authorization': 'Bearer ' + login['token']})
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        self.assertEqual(error.exception.code, 401)

    def test_fixed_monthly_payroll_scope_and_lifecycle(self):
        path = '/api/payroll?month=2026-11'
        self.assertEqual(self.call(path)[0], 401)
        self.setup_account()
        def add(name, role):
            return self.call('/api/users', {'name': name, 'email': name + '@example.com', 'password': 'strong-password', 'role': role})[1]['user']['id']
        manager_id, employee_id, outsider_id = add('PayManager', 'manager'), add('PayEmployee', 'employee'), add('PayOutsider', 'employee')
        manager, employee = self.new_client(), self.new_client()
        for name, client in [('PayManager', manager), ('PayEmployee', employee)]:
            self.call('/api/auth/login', {'email': name + '@example.com', 'password': 'strong-password'}, client)
        team = self.call('/api/teams', {'name': 'Payroll Team'})[1]['team']['id']
        self.call('/api/teams/manager', {'team_id': team, 'manager_id': manager_id})
        self.call('/api/teams/members', {'team_id': team, 'employee_ids': [employee_id]})
        salary = {'user_id': employee_id, 'base': '30000.10', 'allowances': '2000.20', 'deductions': '500.05'}
        self.assertEqual(self.call('/api/payroll?month=invalid')[0], 400)
        self.assertEqual(self.call('/api/payroll/generate', {'month': '2026-11'})[0], 400)
        for client in (manager, employee):
            self.assertEqual(self.call('/api/payroll/salary', salary, client)[0], 403)
            self.assertEqual(self.call('/api/payroll/generate', {'month': '2026-11'}, client)[0], 403)
        self.assertEqual(self.call('/api/payroll/salary', {**salary, 'base': 'NaN'})[0], 400)
        self.assertEqual(self.call('/api/payroll/salary', {**salary, 'base': '10.001'})[0], 400)
        self.assertEqual(self.call('/api/payroll/salary', {**salary, 'deductions': '999999'})[0], 400)
        for user_id in (employee_id, manager_id, outsider_id):
            self.assertEqual(self.call('/api/payroll/salary', {**salary, 'user_id': user_id})[0], 200)
        self.assertEqual(self.call('/api/payroll/generate', {'month': '2026-11'})[1]['created'], 3)
        self.assertEqual(self.call('/api/payroll/generate', {'month': '2026-11'})[1]['created'], 0)
        rows = self.call(path)[1]['rows']
        row = next(row for row in rows if row['user_id'] == employee_id)
        self.assertEqual(row['base'] + row['allowances'] - row['deductions'], 3150025)
        record_id = row['id']
        self.assertEqual(self.call(path, client=employee)[1]['rows'], [])
        manager_view = self.call(path, client=manager)[1]
        self.assertEqual({row['user_id'] for row in manager_view['rows']}, {manager_id, employee_id})
        self.assertEqual(manager_view['people'], [])
        for action in ('update', 'approve', 'paid'):
            self.assertEqual(self.call('/api/payroll/' + action, {'id': record_id}, manager)[0], 403)
        self.assertEqual(self.call('/api/payroll/paid', {'id': record_id})[0], 409)
        self.assertEqual(self.call('/api/payroll/update', {**salary, 'id': record_id, 'deductions': '700.05'})[0], 200)
        self.assertEqual(self.call('/api/payroll/approve', {'id': record_id})[0], 200)
        self.assertEqual(self.call('/api/payroll/update', {**salary, 'id': record_id})[0], 409)
        self.assertEqual(self.call('/api/payroll/approve', {'id': record_id})[0], 409)
        self.assertEqual(len(self.call(path, client=employee)[1]['rows']), 1)
        self.assertEqual(self.call('/api/payroll/paid', {'id': record_id, 'payment_reference': 'BANK-REF'})[0], 200)
        self.assertEqual(self.call('/api/payroll/paid', {'id': record_id})[0], 409)
        paid = self.call(path, client=employee)[1]['rows'][0]
        self.assertEqual(paid['payment_reference'], 'BANK-REF')
        self.assertEqual(paid['status'], 'Paid')
        self.call('/api/payroll/salary', {**salary, 'base': '40000.00'})
        self.call('/api/attendance', {'user_id': employee_id, 'day': '2026-11-01', 'status': 'Absent'})
        self.call('/api/payroll/generate', {'month': '2026-11'})
        self.assertEqual(self.call(path, client=employee)[1]['rows'][0]['base'], 3000010)
        self.assertEqual(self.call('/api/payroll?month=2026-12', client=employee)[1]['rows'], [])
        self.call('/api/payroll/generate', {'month': '2026-12'})
        december = next(row for row in self.call('/api/payroll?month=2026-12')[1]['rows'] if row['user_id'] == employee_id)
        self.assertEqual(december['base'], 4000000)
        self.call('/api/teams/manager', {'team_id': team, 'manager_id': None})
        self.assertEqual({row['user_id'] for row in self.call(path, client=manager)[1]['rows']}, {manager_id})

    def test_attendance_payroll_deductions_and_frozen_approval(self):
        self.setup_account()
        employee_id = self.call('/api/users', {'name': 'Attendance Pay', 'email': 'attendancepay@example.com', 'password': 'strong-password', 'role': 'employee'})[1]['user']['id']
        self.call('/api/payroll/salary', {'user_id': employee_id, 'base': '31000', 'allowances': '1000', 'deductions': '200'})
        def mark(day, status):
            self.assertEqual(self.call('/api/attendance', {'user_id': employee_id, 'day': day, 'status': status})[0], 200)
        mark('2026-10-01', 'Absent')
        mark('2026-10-02', 'Absent')
        mark('2026-10-03', 'Present')
        mark('2026-10-04', 'Leave')
        self.assertEqual(self.call('/api/payroll/generate', {'month': '2026-10', 'attendance_policy': 'bad'})[0], 400)
        self.call('/api/payroll/generate', {'month': '2026-10', 'attendance_policy': 'calendar'})
        def october():
            return self.call('/api/payroll?month=2026-10')[1]['rows'][0]
        row = october()
        self.assertEqual(row['basis_days'], 31)
        self.assertEqual(row['absent_days'], 2)
        self.assertEqual(row['attendance_deduction'], 200000)
        self.assertEqual(row['net_pay'], 2980000)
        # Attendance updates refresh draft amounts without overwriting manual salary edits.
        mark('2026-10-02', 'Present')
        self.assertEqual(october()['attendance_deduction'], 100000)
        self.assertEqual(self.call('/api/payroll/approve', {'id': row['id'], 'expected_net_pay': row['net_pay'], 'expected_absent_days': 2})[0], 409)
        self.call('/api/payroll/update', {'id': row['id'], 'base': '31000', 'allowances': '1000', 'deductions': '200', 'attendance_policy': 'fixed30'})
        row = october()
        self.assertEqual(row['attendance_deduction'], 100000)
        self.assertEqual(row['basis_days'], 31)
        self.assertEqual(self.call('/api/payroll/approve', {'id': row['id'], 'expected_net_pay': row['net_pay'], 'expected_absent_days': 1})[0], 200)
        mark('2026-10-01', 'Present')
        locked = october()
        self.assertEqual(locked['absent_days'], 1)
        self.assertEqual(locked['attendance_deduction'], 100000)
        self.assertEqual(locked['net_pay'], row['net_pay'])
        self.assertEqual(self.call('/api/payroll/update', {'id': row['id'], 'base': '31000', 'allowances': '1000', 'deductions': '0', 'attendance_policy': 'calendar'})[0], 409)
        # Leap February uses 29 days; unmarked and other-month absences do not deduct.
        mark('2028-02-01', 'Absent')
        mark('2028-01-01', 'Absent')
        self.call('/api/payroll/generate', {'month': '2028-02'})
        feb = self.call('/api/payroll?month=2028-02')[1]['rows'][0]
        self.assertEqual(feb['basis_days'], 29)
        self.assertEqual(feb['absent_days'], 1)
        self.assertEqual(feb['attendance_deduction'], 106897)
        # A fully absent 31-day month on a fixed-30 policy is capped at base salary.
        for day in range(1, 32):
            mark('2026-12-' + str(day).zfill(2), 'Absent')
        self.call('/api/payroll/generate', {'month': '2026-12', 'attendance_policy': 'fixed30'})
        december = self.call('/api/payroll?month=2026-12')[1]['rows'][0]
        self.assertEqual(december['attendance_deduction'], 3100000)
        self.assertEqual(december['net_pay'], 80000)
        # Existing manual deductions cannot cause approval of negative payroll.
        self.call('/api/payroll/salary', {'user_id': employee_id, 'base': '31000', 'allowances': '0', 'deductions': '1000'})
        mark('2027-01-01', 'Absent')
        self.call('/api/payroll/generate', {'month': '2027-01'})
        january = self.call('/api/payroll?month=2027-01')[1]['rows'][0]
        self.assertEqual(january['net_pay'], 2900000)
        for day in range(2, 32):
            mark('2027-01-' + str(day).zfill(2), 'Absent')
        self.assertEqual(self.call('/api/payroll/approve', {'id': january['id']})[0], 409)

    def test_month_working_days_and_paid_leave_allowance(self):
        self.setup_account()
        employee_id = self.call('/api/users', {'name': 'Working Days', 'email': 'workingdays@example.com', 'password': 'strong-password', 'role': 'employee'})[1]['user']['id']
        employee = self.new_client()
        self.call('/api/auth/login', {'email': 'workingdays@example.com', 'password': 'strong-password'}, employee)
        settings = {'month': '2026-11', 'working_days': 22, 'paid_leave_days': 2, 'notes': 'Monthly rules'}
        self.assertEqual(self.call('/api/payroll/settings', settings, employee)[0], 403)
        self.assertEqual(self.call('/api/payroll/settings', {**settings, 'paid_leave_days': 31})[0], 400)
        self.assertEqual(self.call('/api/payroll/settings', {**settings, 'paid_leave_days': 1.5})[0], 400)
        self.call('/api/payroll/salary', {'user_id': employee_id, 'base': '30000', 'allowances': '0', 'deductions': '0'})
        self.assertEqual(self.call('/api/payroll/generate', {'month': '2026-11', 'attendance_policy': 'working'})[0], 400)
        self.assertEqual(self.call('/api/payroll/settings', settings)[0], 200)
        self.assertEqual(self.call('/api/payroll/generate', {'month': '2026-11', 'attendance_policy': 'working'})[0], 200)
        for day, status in [('01','Absent'),('02','Leave'),('03','Leave'),('04','Leave'),('05','Leave'),('06','Present')]:
            self.call('/api/attendance', {'user_id': employee_id, 'day': '2026-11-' + day, 'status': status})
        def record():
            return self.call('/api/payroll?month=2026-11')[1]['rows'][0]
        row = record()
        self.assertEqual(row['basis_days'], 30)
        self.assertEqual(row['leave_days'], 4)
        self.assertEqual(row['paid_leave_allowance'], 2)
        self.assertEqual(row['unpaid_days'], 3)
        self.assertEqual(row['attendance_deduction'], 300000)
        self.assertEqual(row['attendance_policy'], 'calendar')
        self.assertEqual(self.call('/api/payroll?month=2026-11')[1]['month_settings']['working_days'], 30)
        self.call('/api/payroll/settings', {**settings, 'working_days': 20, 'paid_leave_days': 1})
        changed = record()
        self.assertEqual(changed['unpaid_days'], 4)
        self.assertEqual(changed['attendance_deduction'], 400000)
        self.assertEqual(self.call('/api/payroll/approve', {'id': row['id'], 'expected_net_pay': row['net_pay'], 'expected_absent_days': row['absent_days']})[0], 409)
        self.assertEqual(self.call('/api/payroll/approve', {'id': row['id'], 'expected_net_pay': changed['net_pay'], 'expected_absent_days': 1, 'expected_basis_days': 30, 'expected_leave_days': 4, 'expected_paid_leave_allowance': 1})[0], 200)
        self.call('/api/payroll/settings', {**settings, 'working_days': 24, 'paid_leave_days': 4})
        frozen = record()
        self.assertEqual(frozen['basis_days'], 30)
        self.assertEqual(frozen['paid_leave_allowance'], 1)
        self.assertEqual(frozen['unpaid_days'], 4)
        self.assertEqual(frozen['attendance_deduction'], 400000)
        self.assertEqual(self.call('/api/payroll?month=2026-12')[1]['month_settings'], None)
        self.assertEqual(self.call('/api/payroll?month=2026-11', client=employee)[1]['rows'][0]['paid_leave_allowance'], 1)

    def test_leave_year_carry_forward_and_night_shift_pay(self):
        self.setup_account()
        employee_id = self.call('/api/users', {'name': 'Annual Leave', 'email': 'annual@example.com', 'password': 'strong-password', 'role': 'employee'})[1]['user']['id']
        self.call('/api/payroll/salary', {'user_id': employee_id, 'base': '22000', 'allowances': '0', 'deductions': '0'})
        def settings(month, leave=2, rate='250.50'):
            return self.call('/api/payroll/settings', {'month': month, 'working_days': 22, 'paid_leave_days': leave, 'night_shift_rate': rate})
        def generate(month):
            self.assertEqual(self.call('/api/payroll/generate', {'month': month, 'attendance_policy': 'working'})[0], 200)
        def row(month):
            return self.call('/api/payroll?month=' + month)[1]['rows'][0]
        def mark(day, status='Leave', night=False):
            return self.call('/api/attendance', {'user_id': employee_id, 'day': day, 'status': status, 'night_shift': night, 'night_hours': '8' if night else '0'})
        self.assertEqual(settings('2026-01')[0], 200)
        self.assertEqual(settings('2026-02')[0], 200)
        self.assertEqual(settings('2026-03')[0], 200)
        generate('2026-01')
        january = row('2026-01')
        self.assertEqual(january['leave_opening'], 0)
        self.assertEqual(january['leave_balance_after'], 2)
        generate('2026-02')
        for day in ('01','02','03'):
            mark('2026-02-' + day)
        february = row('2026-02')
        self.assertEqual(february['leave_opening'], 2)
        self.assertEqual(february['paid_leave_used'], 3)
        self.assertEqual(february['leave_balance_after'], 1)
        self.assertEqual(february['attendance_deduction'], 0)
        self.assertEqual(self.call('/api/payroll/approve', {'id': february['id']})[0], 409)
        self.assertEqual(self.call('/api/payroll/approve', {'id': january['id']})[0], 200)
        # Closed January balance is preserved when prior settings or attendance change.
        settings('2026-01', leave=5)
        mark('2026-01-01')
        self.assertEqual(row('2026-02')['leave_opening'], 2)
        self.assertEqual(self.call('/api/payroll/approve', {'id': february['id']})[0], 200)
        generate('2026-03')
        for day in ('01','02','03','04'):
            mark('2026-03-' + day)
        mark('2026-03-05', 'Absent')
        self.assertEqual(mark('2026-03-06', 'Present', True)[0], 200)
        self.assertEqual(mark('2026-03-07', 'Present', True)[0], 200)
        self.assertEqual(mark('2026-03-08', 'Leave', True)[0], 400)
        self.assertEqual(mark('2026-03-09', 'Absent', True)[0], 400)
        march = row('2026-03')
        self.assertEqual(march['leave_opening'], 1)
        self.assertEqual(march['unpaid_days'], 2)
        self.assertEqual(march['leave_balance_after'], 0)
        self.assertEqual(march['night_shifts'], 2)
        self.assertEqual(march['night_shift_rate'], 25050)
        self.assertEqual(march['night_hours_hundredths'], 1600)
        self.assertEqual(march['night_shift_pay'], 400800)
        self.assertEqual(march['attendance_deduction'], 141935)
        self.assertEqual(march['net_pay'], 2458865)
        records = self.call('/api/attendance?month=2026-03')[1]['records']
        self.assertEqual(sum(r['night_shift'] for r in records), 2)
        self.assertEqual(settings('2026-03', rate='-1')[0], 400)
        self.assertEqual(settings('2026-03', rate='1.234')[0], 400)
        self.assertEqual(self.call('/api/payroll/approve', {'id': march['id'], 'expected_net_pay': march['net_pay'], 'expected_absent_days': 1, 'expected_night_shifts': 0})[0], 409)
        self.assertEqual(self.call('/api/payroll/approve', {'id': march['id']})[0], 200)
        settings('2026-03', rate='999')
        mark('2026-03-06', 'Present', False)
        self.assertEqual(row('2026-03')['night_shift_pay'], 400800)
        self.assertEqual(row('2026-03')['night_shifts'], 2)
        # No balance is brought across December into January.
        settings('2026-12', leave=4)
        generate('2026-12')
        self.assertEqual(row('2026-12')['leave_balance_after'], 4)
        settings('2027-01', leave=1)
        generate('2027-01')
        self.assertEqual(row('2027-01')['leave_opening'], 0)
        self.assertEqual(row('2027-01')['leave_balance_after'], 1)

    def test_fractional_night_hours_validation_and_rounding(self):
        self.setup_account()
        person = self.call('/api/users', {'name': 'Night Hours', 'email': 'hours@example.com', 'password': 'strong-password', 'role': 'employee'})[1]['user']['id']
        self.call('/api/payroll/salary', {'user_id': person, 'base': '1000', 'allowances': '0', 'deductions': '0'})
        self.call('/api/payroll/settings', {'month': '2026-11', 'working_days': 22, 'paid_leave_days': 1, 'night_shift_rate': '0.05'})
        data = {'user_id': person, 'day': '2026-11-01', 'status': 'Present', 'night_shift': True, 'night_hours': '0.10'}
        for invalid in ('0', '-1', '24.01', '1.001', 'NaN'):
            self.assertEqual(self.call('/api/attendance', {**data, 'night_hours': invalid})[0], 400)
        self.assertEqual(self.call('/api/attendance', data)[0], 200)
        self.call('/api/payroll/generate', {'month': '2026-11', 'attendance_policy': 'working'})
        row = self.call('/api/payroll?month=2026-11')[1]['rows'][0]
        self.assertEqual(row['night_hours_hundredths'], 10)
        self.assertEqual(row['night_shift_pay'], 1)
        self.assertEqual(row['net_pay'], 100001)
        self.assertEqual(self.call('/api/attendance', {**data, 'night_shift': False, 'night_hours': '0'})[0], 200)
        row = self.call('/api/payroll?month=2026-11')[1]['rows'][0]
        self.assertEqual(row['night_shift_pay'], 0)
        self.assertEqual(row['night_hours_hundredths'], 0)

    def test_demo_accounts(self):
        server.seed_demo_accounts()
        server.seed_demo_accounts()
        with server.database() as con:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM users').fetchone()[0], 3)
        for role in server.ROLES:
            code, data, _ = self.call('/api/auth/login', {'email': role + '@demo.local', 'password': server.DEMO_PASSWORD}, self.new_client())
            self.assertEqual(code, 200)
            self.assertEqual(data['user']['role'], role)

if __name__ == '__main__':
    unittest.main()
