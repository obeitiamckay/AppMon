"""Privileged and administrative user account auditing."""

from app.users.admin_audit import audit_admin_users

__all__ = ["audit_admin_users"]
