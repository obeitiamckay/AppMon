"""Tests for v2.0 Gmail SMTP email notifications and encrypted SMTP settings."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.database import get_db
from app.main import app
from app.models.monitoring import Report, ScanRun
from app.models.system import AppSetting, SystemUser
from app.notifications.email_sender import load_email_config, send_report_email
from app.security import SecretCipher, hash_password


def test_gmail_smtp_report_delivery_and_attachments(db_session, tmp_path: Path):
    db, _ = db_session
    cipher = SecretCipher()
    db.add_all([
        AppSetting(key="smtp_enabled", value="true"),
        AppSetting(key="smtp_host", value="smtp.gmail.com"),
        AppSetting(key="smtp_port", value="587"),
        AppSetting(key="smtp_use_tls", value="true"),
        AppSetting(key="smtp_user", value="soc-alerts@gmail.com"),
        AppSetting(key="smtp_password_enc", value=cipher.encrypt("abcd-efgh-ijkl-mnop")),
        AppSetting(key="smtp_to", value="ai-soc@gmail.com, admin@gmail.com"),
    ])

    html_file = tmp_path / "report.html"
    json_file = tmp_path / "report.json"
    html_file.write_text("<html><body>OK</body></html>", encoding="utf-8")
    json_file.write_text('{"summary":{"total_hosts":1}}', encoding="utf-8")

    scan = ScanRun(trigger_type="manual", triggered_by="pytest", status="completed", total_hosts=1, ok_hosts=1)
    db.add(scan)
    db.flush()
    report = Report(
        scan_run_id=scan.id,
        title="Reporte Test v2.0",
        html_path=str(html_file),
        json_path=str(json_file),
        summary_stats={"total_hosts": 1, "ok_hosts": 1, "warning_hosts": 0, "critical_hosts": 0, "unreachable_hosts": 0},
    )
    db.add(report)
    db.commit()

    cfg = load_email_config(db)
    assert cfg.enabled is True
    assert cfg.password == "abcd-efgh-ijkl-mnop"
    assert cfg.recipients == ["ai-soc@gmail.com", "admin@gmail.com"]

    mock_smtp = MagicMock()
    with patch("app.notifications.email_sender.smtplib.SMTP") as smtp_cls:
        smtp_cls.return_value.__enter__.return_value = mock_smtp
        sent = send_report_email(db, scan, report)

    assert sent is True
    mock_smtp.starttls.assert_called_once()
    mock_smtp.login.assert_called_once_with("soc-alerts@gmail.com", "abcd-efgh-ijkl-mnop")
    mock_smtp.send_message.assert_called_once()

    sent_msg = mock_smtp.send_message.call_args[0][0]
    filenames = [part.get_filename() for part in sent_msg.iter_attachments()]
    assert "report.json" in filenames
    assert "report.html" in filenames


def test_settings_web_saves_encrypted_smtp_and_test_email(db_session):
    db, SessionFactory = db_session
    admin = SystemUser(username="admin_smtp", password_hash=hash_password("Pass123!"), role="admin", is_active=True)
    db.add(admin)
    db.commit()

    def override_get_db():
        s = SessionFactory()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)
        client.post("/login", data={"username": "admin_smtp", "password": "Pass123!"}, follow_redirects=False)

        r_save = client.post(
            "/settings",
            data={
                "retention_days": "90",
                "scan_hour": "2",
                "smtp_enabled": "true",
                "smtp_host": "smtp.gmail.com",
                "smtp_port": "587",
                "smtp_use_tls": "true",
                "smtp_user": "bot@gmail.com",
                "smtp_password": "my-app-password",
                "smtp_to": "ia@gmail.com",
            },
            follow_redirects=False,
        )
        assert r_save.status_code == 303

        enc_row = db.get(AppSetting, "smtp_password_enc")
        assert enc_row is not None
        assert enc_row.value != "my-app-password"
        assert SecretCipher().decrypt(enc_row.value) == "my-app-password"

        with patch("app.notifications.email_sender.smtplib.SMTP") as smtp_cls:
            r_test = client.post("/settings/test-email", follow_redirects=False)
            assert r_test.status_code == 303
            assert "OK" in r_test.headers["location"]
            smtp_cls.assert_called_once_with("smtp.gmail.com", 587, timeout=30)
    finally:
        app.dependency_overrides.clear()
