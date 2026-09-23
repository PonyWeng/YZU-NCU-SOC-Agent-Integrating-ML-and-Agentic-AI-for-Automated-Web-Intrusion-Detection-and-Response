"""Local account authentication with scrypt password hashes and opaque sessions."""
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request

from siem import store

SESSION_COOKIE = 'siem_session'
SESSION_HOURS = max(1, int(os.getenv('SIEM_SESSION_HOURS','12')))
IDLE_TIMEOUT_MINUTES = max(1, int(os.getenv('SIEM_IDLE_TIMEOUT_MINUTES','30')))
IDLE_WARNING_MINUTES = max(1, min(IDLE_TIMEOUT_MINUTES, int(os.getenv('SIEM_IDLE_WARNING_MINUTES','5'))))


def _password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f'scrypt${salt.hex()}${digest.hex()}'


def _password_ok(password, encoded):
    try:
        _, salt, expected = encoded.split('$', 2)
        actual = _password_hash(password, bytes.fromhex(salt)).split('$', 2)[2]
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def bootstrap_admin(db):
    if db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
        return
    username = os.getenv('SIEM_ADMIN_USERNAME', 'admin').strip() or 'admin'
    password = os.getenv('SIEM_ADMIN_PASSWORD', 'admin@ncu-siem')
    db.execute('''INSERT INTO users(username,display_name,password_hash,role,enabled,created_at,updated_at)
                  VALUES (?,?,?,?,1,?,?)''',
               (username, '系統管理員', _password_hash(password), 'admin', store.now(), store.now()))


def login(username, password, user_agent=''):
    with store.connection() as db:
        row = db.execute('SELECT * FROM users WHERE lower(username)=lower(?)', (username.strip(),)).fetchone()
        if not row or not row['enabled'] or not _password_ok(password, row['password_hash']):
            raise HTTPException(401, '帳號或密碼錯誤')
        token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)).isoformat(timespec='seconds')
        db.execute('DELETE FROM user_sessions WHERE expires_at<=?', (store.now(),))
        created=store.now()
        db.execute('INSERT INTO user_sessions(token_hash,user_id,created_at,expires_at,user_agent,last_activity_at) VALUES (?,?,?,?,?,?)',
                   (_token_hash(token), row['id'], created, expires, user_agent[:300], created))
        store.audit('auth.login', '登入成功', actor=row['username'], db=db)
        return token, public_user(row)


def logout(token):
    if not token:
        return
    with store.connection() as db:
        db.execute('DELETE FROM user_sessions WHERE token_hash=?', (_token_hash(token),))


def session_from_token(token):
    if not token:
        return None, 'missing'
    with store.connection() as db:
        row = db.execute('''SELECT u.*,s.created_at session_created_at,s.expires_at session_expires_at,
                            s.last_activity_at session_last_activity_at FROM user_sessions s
                            JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND u.enabled=1''',
                         (_token_hash(token),)).fetchone()
        if not row: return None, 'invalid'
        now=datetime.now(timezone.utc)
        absolute=datetime.fromisoformat(row['session_expires_at'])
        last=datetime.fromisoformat(row['session_last_activity_at'] or row['session_created_at'])
        reason='absolute' if now >= absolute else 'idle' if now-last >= timedelta(minutes=IDLE_TIMEOUT_MINUTES) else ''
        if reason:
            db.execute('DELETE FROM user_sessions WHERE token_hash=?',(_token_hash(token),))
            store.audit('auth.timeout','登入時效到期' if reason=='absolute' else '閒置逾期登出',actor=row['username'],db=db)
            return None, reason
        return dict(row), ''


def user_from_token(token):
    return session_from_token(token)[0]


def session_info(row):
    return {'last_activity_at':row['session_last_activity_at'],
            'absolute_expires_at':row['session_expires_at'],
            'idle_timeout_seconds':IDLE_TIMEOUT_MINUTES*60,
            'warning_seconds':IDLE_WARNING_MINUTES*60}


def touch_session(token):
    user,reason=session_from_token(token)
    if not user: raise HTTPException(401,'登入已逾期' if reason in ('idle','absolute') else '請先登入')
    stamp=store.now()
    with store.connection() as db:
        db.execute('UPDATE user_sessions SET last_activity_at=? WHERE token_hash=?',(stamp,_token_hash(token)))
    user['session_last_activity_at']=stamp
    return session_info(user)


def current_user(request: Request):
    user = getattr(request.state, 'user', None)
    if not user:
        raise HTTPException(401, '請先登入')
    return user


def require_admin(request: Request):
    user = current_user(request)
    if user['role'] != 'admin':
        raise HTTPException(403, '此操作需要管理員權限')
    return user


def public_user(row):
    return {k: row[k] for k in ('id', 'username', 'display_name', 'role', 'enabled', 'created_at', 'updated_at')}


def create_user(username, display_name, password, role, actor):
    username = username.strip()
    if not username or len(username) > 64 or not all(c.isalnum() or c in '._-' for c in username):
        raise HTTPException(422, '帳號限英數字、句點、底線與連字號')
    if len(password) < 4:
        raise HTTPException(422, '密碼至少需要 4 個字元')
    with store.connection() as db:
        try:
            cur = db.execute('''INSERT INTO users(username,display_name,password_hash,role,enabled,created_at,updated_at)
                                VALUES (?,?,?,?,1,?,?)''',
                             (username, display_name.strip() or username, _password_hash(password), role, store.now(), store.now()))
        except Exception as exc:
            if 'UNIQUE' in str(exc):
                raise HTTPException(409, '帳號已存在')
            raise
        store.audit('user.create', f'{username} ({role})', actor=actor, db=db)
        return cur.lastrowid


def update_user(user_id, display_name, role, enabled, password, actor, actor_id):
    if user_id == actor_id and (not enabled or role != 'admin'):
        raise HTTPException(409, '不能停用自己的帳號或移除自己的管理員權限')
    with store.connection() as db:
        row = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, '找不到使用者')
        if row['role'] == 'admin' and (not enabled or role != 'admin'):
            admins = db.execute("SELECT count(*) FROM users WHERE role='admin' AND enabled=1").fetchone()[0]
            if admins <= 1:
                raise HTTPException(409, '系統至少需要一個啟用中的管理員')
        if password and len(password) < 4:
            raise HTTPException(422, '密碼至少需要 4 個字元')
        if password:
            db.execute('UPDATE users SET display_name=?,role=?,enabled=?,password_hash=?,updated_at=? WHERE id=?',
                       (display_name.strip(), role, int(enabled), _password_hash(password), store.now(), user_id))
            db.execute('DELETE FROM user_sessions WHERE user_id=?', (user_id,))
        else:
            db.execute('UPDATE users SET display_name=?,role=?,enabled=?,updated_at=? WHERE id=?',
                       (display_name.strip(), role, int(enabled), store.now(), user_id))
        store.audit('user.update', f'{row["username"]} ({role}, enabled={enabled})', actor=actor, db=db)


def update_own_account(user_id, display_name, current_password, new_password):
    if new_password and len(new_password) < 4:
        raise HTTPException(422, '新密碼至少需要 4 個字元')
    with store.connection() as db:
        row = db.execute('SELECT * FROM users WHERE id=? AND enabled=1', (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, '找不到使用者')
        if new_password and not _password_ok(current_password, row['password_hash']):
            raise HTTPException(422, '目前密碼不正確')
        name = display_name.strip()
        if new_password:
            db.execute('UPDATE users SET display_name=?,password_hash=?,updated_at=? WHERE id=?',
                       (name, _password_hash(new_password), store.now(), user_id))
            db.execute('DELETE FROM user_sessions WHERE user_id=?', (user_id,))
        else:
            db.execute('UPDATE users SET display_name=?,updated_at=? WHERE id=?', (name, store.now(), user_id))
        store.audit('account.update', '更新個人資料及密碼' if new_password else '更新個人資料', actor=row['username'], db=db)
        return bool(new_password)
