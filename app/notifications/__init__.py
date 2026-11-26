"""Notification channels (Gmail SMTP email delivery for reports and logs)."""

from app.notifications.email_sender import EmailConfig, send_report_email, send_test_email

__all__ = ["EmailConfig", "send_report_email", "send_test_email"]
