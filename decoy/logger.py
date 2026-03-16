import redis
import json
import time
from flask import Request

CONFIRMED_MALICIOUS_EVENTS = {
    'credential_attempt',
    'credential_harvest',
    'api_enumeration',
    'path_traversal',
    'rce_attempt',
    'file_upload_attempt',
    'config_access',
    'backup_access',
}


class HoneypotLogger:
    """
    Logs every honeypot interaction to Redis.
    Confirmed malicious events are also pushed to honeypot_retrain_queue
    for the ML retraining worker to consume.
    """

    def __init__(self):
        self.r = redis.Redis(host='localhost', port=6379, decode_responses=True)

    def _base_entry(self, request: Request) -> dict:
        return {
            'timestamp':    time.time(),
            'src_ip':       request.remote_addr,
            'method':       request.method,
            'path':         request.path,
            'user_agent':   request.headers.get('User-Agent', ''),
            'referrer':     request.headers.get('Referer', ''),
            'query_string': request.query_string.decode('utf-8', errors='replace'),
        }

    def log_request(self, request: Request):
        """Log every incoming HTTP request for passive recon tracking."""
        entry = self._base_entry(request)
        entry['event_type'] = 'http_request'
        self.r.lpush('honeypot_raw_requests', json.dumps(entry))
        self.r.ltrim('honeypot_raw_requests', 0, 9999)

    def log_event(self, request: Request, event_type: str, extra: dict):
        """Log a classified security event and queue for retraining if malicious."""
        entry = self._base_entry(request)
        entry['event_type'] = event_type
        entry['extra']      = extra

        self.r.lpush('honeypot_events', json.dumps(entry))
        self.r.ltrim('honeypot_events', 0, 9999)

        if event_type in CONFIRMED_MALICIOUS_EVENTS:
            retrain_entry = {
                **entry,
                'confirmed_malicious': True,
                'label': 1,
            }
            self.r.lpush('honeypot_retrain_queue', json.dumps(retrain_entry))

    def log_credential_attempt(self, request: Request, username: str, password: str):
        """
        Specialized logger for login attempts.
        Logs username + password length — NOT the plaintext password.
        """
        entry = self._base_entry(request)
        entry['event_type']      = 'credential_attempt'
        entry['username']        = username
        entry['password_length'] = len(password)
        entry['common_password'] = password in [
            'admin', 'password', '123456', 'admin123', 'root', 'pass'
        ]

        self.r.lpush('honeypot_events', json.dumps(entry))
        self.r.ltrim('honeypot_events', 0, 9999)
        self.r.lpush('honeypot_retrain_queue', json.dumps({**entry, 'label': 1}))
