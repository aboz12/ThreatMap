"""
User Authentication and Authorization for Threat Map
Provides login, sessions, and role-based access control
"""

import hashlib
import secrets
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class User:
    """User account"""
    username: str
    password_hash: str
    role: str  # admin, analyst, viewer
    email: str = ""
    created_at: str = ""
    last_login: Optional[str] = None
    enabled: bool = True
    api_key: Optional[str] = None


@dataclass
class Session:
    """User session"""
    session_id: str
    username: str
    role: str
    created_at: str
    expires_at: str
    ip_address: str = ""
    user_agent: str = ""


@dataclass
class AuditLog:
    """Audit log entry"""
    timestamp: str
    username: str
    action: str
    details: str
    ip_address: str = ""
    success: bool = True


# Role permissions
ROLE_PERMISSIONS = {
    "admin": [
        "view_dashboard", "view_attacks", "view_alerts", "view_reports",
        "manage_alerts", "manage_feeds", "manage_users", "manage_settings",
        "export_data", "run_queries", "view_audit_log"
    ],
    "analyst": [
        "view_dashboard", "view_attacks", "view_alerts", "view_reports",
        "manage_alerts", "export_data", "run_queries"
    ],
    "viewer": [
        "view_dashboard", "view_attacks", "view_alerts", "view_reports"
    ]
}


class AuthManager:
    """Manages authentication and authorization"""

    def __init__(self):
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self.audit_log: List[AuditLog] = []
        self.session_duration = timedelta(hours=8)
        self.max_sessions_per_user = 5

        # Create default admin user
        self._init_default_users()

    def _init_default_users(self):
        """Create default users"""
        # Default admin password: "admin" (change in production!)
        self.create_user("admin", "admin", "admin", "admin@threatmap.local")

        # Demo analyst
        self.create_user("analyst", "analyst", "analyst", "analyst@threatmap.local")

        # Demo viewer
        self.create_user("viewer", "viewer", "viewer", "viewer@threatmap.local")

    def _hash_password(self, password: str, salt: str = None) -> tuple:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return salt + ":" + hashed.hex(), salt

    def _verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        try:
            salt, hash_value = stored_hash.split(":")
            computed_hash, _ = self._hash_password(password, salt)
            return computed_hash == stored_hash
        except:
            return False

    def create_user(self, username: str, password: str, role: str, email: str = "") -> Optional[User]:
        """Create a new user"""
        if username in self.users:
            return None

        if role not in ROLE_PERMISSIONS:
            return None

        password_hash, _ = self._hash_password(password)

        user = User(
            username=username,
            password_hash=password_hash,
            role=role,
            email=email,
            created_at=datetime.utcnow().isoformat() + "Z",
            api_key=secrets.token_hex(32)
        )
        self.users[username] = user

        self._log_action(username, "user_created", f"User {username} created with role {role}")

        return user

    def delete_user(self, username: str, deleted_by: str) -> bool:
        """Delete a user"""
        if username not in self.users:
            return False

        if username == "admin":
            return False  # Prevent deleting admin

        del self.users[username]

        # Invalidate all sessions
        self.sessions = {
            sid: s for sid, s in self.sessions.items()
            if s.username != username
        }

        self._log_action(deleted_by, "user_deleted", f"User {username} deleted")
        return True

    def update_password(self, username: str, new_password: str, updated_by: str) -> bool:
        """Update user password"""
        if username not in self.users:
            return False

        password_hash, _ = self._hash_password(new_password)
        self.users[username].password_hash = password_hash

        # Invalidate existing sessions
        self.sessions = {
            sid: s for sid, s in self.sessions.items()
            if s.username != username
        }

        self._log_action(updated_by, "password_changed", f"Password changed for {username}")
        return True

    def update_role(self, username: str, new_role: str, updated_by: str) -> bool:
        """Update user role"""
        if username not in self.users:
            return False

        if new_role not in ROLE_PERMISSIONS:
            return False

        old_role = self.users[username].role
        self.users[username].role = new_role

        self._log_action(updated_by, "role_changed", f"Role changed for {username}: {old_role} -> {new_role}")
        return True

    def login(self, username: str, password: str, ip_address: str = "", user_agent: str = "") -> Optional[Session]:
        """Authenticate user and create session"""
        if username not in self.users:
            self._log_action(username, "login_failed", "User not found", ip_address, False)
            return None

        user = self.users[username]

        if not user.enabled:
            self._log_action(username, "login_failed", "Account disabled", ip_address, False)
            return None

        if not self._verify_password(password, user.password_hash):
            self._log_action(username, "login_failed", "Invalid password", ip_address, False)
            return None

        # Create session
        session = self._create_session(user, ip_address, user_agent)

        # Update last login
        user.last_login = datetime.utcnow().isoformat() + "Z"

        self._log_action(username, "login_success", f"Login from {ip_address}", ip_address)
        return session

    def _create_session(self, user: User, ip_address: str, user_agent: str) -> Session:
        """Create a new session"""
        # Clean old sessions for this user
        user_sessions = [
            (sid, s) for sid, s in self.sessions.items()
            if s.username == user.username
        ]
        if len(user_sessions) >= self.max_sessions_per_user:
            # Remove oldest
            oldest = min(user_sessions, key=lambda x: x[1].created_at)
            del self.sessions[oldest[0]]

        now = datetime.utcnow()
        session = Session(
            session_id=secrets.token_hex(32),
            username=user.username,
            role=user.role,
            created_at=now.isoformat() + "Z",
            expires_at=(now + self.session_duration).isoformat() + "Z",
            ip_address=ip_address,
            user_agent=user_agent
        )
        self.sessions[session.session_id] = session
        return session

    def logout(self, session_id: str) -> bool:
        """Logout and invalidate session"""
        if session_id in self.sessions:
            username = self.sessions[session_id].username
            del self.sessions[session_id]
            self._log_action(username, "logout", "User logged out")
            return True
        return False

    def validate_session(self, session_id: str) -> Optional[Session]:
        """Validate session and return it if valid"""
        if session_id not in self.sessions:
            return None

        session = self.sessions[session_id]

        # Check expiry
        expires = datetime.fromisoformat(session.expires_at.replace("Z", "+00:00"))
        if datetime.now(expires.tzinfo) > expires:
            del self.sessions[session_id]
            return None

        return session

    def validate_api_key(self, api_key: str) -> Optional[User]:
        """Validate API key and return user"""
        for user in self.users.values():
            if user.api_key == api_key and user.enabled:
                return user
        return None

    def check_permission(self, session_id: str, permission: str) -> bool:
        """Check if session has permission"""
        session = self.validate_session(session_id)
        if not session:
            return False

        return permission in ROLE_PERMISSIONS.get(session.role, [])

    def regenerate_api_key(self, username: str, regenerated_by: str) -> Optional[str]:
        """Regenerate API key for user"""
        if username not in self.users:
            return None

        new_key = secrets.token_hex(32)
        self.users[username].api_key = new_key

        self._log_action(regenerated_by, "api_key_regenerated", f"API key regenerated for {username}")
        return new_key

    def _log_action(self, username: str, action: str, details: str, ip_address: str = "", success: bool = True):
        """Log an action to audit log"""
        entry = AuditLog(
            timestamp=datetime.utcnow().isoformat() + "Z",
            username=username,
            action=action,
            details=details,
            ip_address=ip_address,
            success=success
        )
        self.audit_log.append(entry)

        # Keep log bounded
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-5000:]

    def get_users(self) -> List[dict]:
        """Get all users (without sensitive data)"""
        return [
            {
                "username": u.username,
                "role": u.role,
                "email": u.email,
                "enabled": u.enabled,
                "created_at": u.created_at,
                "last_login": u.last_login
            }
            for u in self.users.values()
        ]

    def get_active_sessions(self) -> List[dict]:
        """Get all active sessions"""
        now = datetime.utcnow()
        active = []

        for session in self.sessions.values():
            expires = datetime.fromisoformat(session.expires_at.replace("Z", "+00:00"))
            if now < expires.replace(tzinfo=None):
                active.append({
                    "session_id": session.session_id[:8] + "...",
                    "username": session.username,
                    "role": session.role,
                    "created_at": session.created_at,
                    "expires_at": session.expires_at,
                    "ip_address": session.ip_address
                })

        return active

    def get_audit_log(self, limit: int = 100, username: str = None, action: str = None) -> List[dict]:
        """Get audit log entries"""
        entries = self.audit_log

        if username:
            entries = [e for e in entries if e.username == username]

        if action:
            entries = [e for e in entries if e.action == action]

        return [
            {
                "timestamp": e.timestamp,
                "username": e.username,
                "action": e.action,
                "details": e.details,
                "ip_address": e.ip_address,
                "success": e.success
            }
            for e in entries[-limit:]
        ]

    def get_statistics(self) -> dict:
        """Get authentication statistics"""
        return {
            "total_users": len(self.users),
            "active_sessions": len(self.sessions),
            "users_by_role": {
                role: len([u for u in self.users.values() if u.role == role])
                for role in ROLE_PERMISSIONS.keys()
            },
            "recent_logins": len([
                e for e in self.audit_log[-100:]
                if e.action == "login_success"
            ]),
            "failed_logins": len([
                e for e in self.audit_log[-100:]
                if e.action == "login_failed"
            ])
        }
