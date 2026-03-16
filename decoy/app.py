from flask import (
    Flask, request, render_template, redirect,
    url_for, session, jsonify, Response
)
from logger import HoneypotLogger
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)

logger = HoneypotLogger()

# ── Fake user database ────────────────────────────────────────────────
FAKE_USERS = {
    'admin':     'Admin@2024!',
    'root':      'R00tPass#99',
    'sysadmin':  'Sysadm1n@Corp',
    'superuser': 'Super#Secure1',
}

# ── Fake employee data for dashboard / API ────────────────────────────
FAKE_EMPLOYEES = [
    {'id': 1, 'name': 'Alice Chen',    'role': 'DevOps Engineer',   'email': 'a.chen@nexuscorp.io',    'status': 'Active'},
    {'id': 2, 'name': 'Bob Martinez',  'role': 'Backend Developer', 'email': 'b.martinez@nexuscorp.io','status': 'Active'},
    {'id': 3, 'name': 'Carol Singh',   'role': 'Security Analyst',  'email': 'c.singh@nexuscorp.io',   'status': 'Active'},
    {'id': 4, 'name': 'Daniel Park',   'role': 'Database Admin',    'email': 'd.park@nexuscorp.io',    'status': 'Inactive'},
    {'id': 5, 'name': 'Eva Novak',     'role': 'CTO',               'email': 'e.novak@nexuscorp.io',   'status': 'Active'},
]

# ── Logging middleware — log EVERY request ────────────────────────────
@app.before_request
def log_request():
    logger.log_request(request)

# ── Mask server identity ──────────────────────────────────────────────
@app.after_request
def mask_headers(response):
    response.headers['Server']          = 'nginx/1.24.0'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers.pop('X-Powered-By', None)
    return response

# ── Routes ────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if session.get('authenticated'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        logger.log_credential_attempt(request, username, password)

        if username in FAKE_USERS and FAKE_USERS[username] == password:
            session['authenticated'] = True
            session['username'] = username
            logger.log_event(request, 'login_success', {'username': username})
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. Please try again.'
            logger.log_event(request, 'login_failure', {'username': username})

    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    return render_template('dashboard.html',
                           user=session.get('username', 'admin'),
                           employees=FAKE_EMPLOYEES)


@app.route('/users')
def users():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    logger.log_event(request, 'user_enumeration', {})
    return render_template('users.html', employees=FAKE_EMPLOYEES)


@app.route('/settings')
def settings():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    return render_template('settings.html')


# ── Honeypot trap: .env file ──────────────────────────────────────────
@app.route('/.env')
def fake_env():
    logger.log_event(request, 'credential_harvest', {
        'file': '.env',
        'severity': 'CRITICAL',
    })
    content = open(os.path.join(os.path.dirname(__file__), '.env')).read()
    return Response(content, mimetype='text/plain')


# ── Honeypot trap: backup directory ──────────────────────────────────
@app.route('/backup/')
@app.route('/backup/<path:filename>')
def fake_backup(filename=''):
    logger.log_event(request, 'backup_access', {'path': filename or 'listing'})
    return render_template('403.html'), 403


# ── Fake REST API ─────────────────────────────────────────────────────
@app.route('/api/v1/users', methods=['GET'])
def api_users():
    logger.log_event(request, 'api_enumeration', {'endpoint': '/api/v1/users'})
    return jsonify({'users': FAKE_EMPLOYEES, 'total': len(FAKE_EMPLOYEES)})


@app.route('/api/v1/users/<int:user_id>', methods=['GET'])
def api_user(user_id):
    logger.log_event(request, 'api_enumeration', {'endpoint': f'/api/v1/users/{user_id}'})
    user = next((e for e in FAKE_EMPLOYEES if e['id'] == user_id), None)
    if not user:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(user)


@app.route('/api/v1/config', methods=['GET', 'POST'])
def api_config():
    logger.log_event(request, 'config_access', {
        'method': request.method,
        'body': request.get_json(silent=True) or {},
    })
    return jsonify({
        'db_host':         'db.nexuscorp.internal',
        'cache':           'redis://cache.nexuscorp.internal:6379',
        'max_connections': 200,
        'debug_mode':      False,
    })


@app.route('/api/v1/exec', methods=['POST'])
def api_exec():
    """Fake RCE endpoint — logs command injection attempts. Executes nothing."""
    body = request.get_json(silent=True) or {}
    logger.log_event(request, 'rce_attempt', {
        'command': body.get('cmd', body.get('command', '')),
        'severity': 'CRITICAL',
    })
    return jsonify({'status': 'queued', 'job_id': '8f3a9b2e'}), 202


@app.route('/api/v1/upload', methods=['POST'])
def api_upload():
    file = request.files.get('file')
    logger.log_event(request, 'file_upload_attempt', {
        'filename': file.filename if file else 'no_file',
        'content_type': request.content_type,
    })
    return jsonify({'status': 'uploaded', 'path': '/var/www/uploads/payload.php'}), 200


# ── Path traversal & catch-all detector ──────────────────────────────
@app.route('/<path:undefined_path>')
def catch_all(undefined_path):
    if any(t in undefined_path for t in ['../', '%2e', '%2f', 'etc/passwd', 'etc/shadow']):
        logger.log_event(request, 'path_traversal', {'path': undefined_path})
    elif any(x in undefined_path for x in ['wp-admin', 'phpmyadmin', '.git', 'admin']):
        logger.log_event(request, 'recon_probe', {'path': undefined_path})
    return render_template('403.html'), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
