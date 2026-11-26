"""Tests for security primitives (Fernet, Argon2, JWT) and web console RBAC/threshold updates."""

from fastapi.testclient import TestClient

from app.database import get_db
from app.main import app
from app.models.inventory import HostGroup, Threshold
from app.models.system import SystemUser
from app.security import SecretCipher, hash_password, verify_password


def test_fernet_and_argon2_roundtrip():
    cipher = SecretCipher()
    secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nTEST\n-----END OPENSSH PRIVATE KEY-----"
    enc = cipher.encrypt(secret)
    assert enc != secret
    assert cipher.decrypt(enc) == secret

    hashed = hash_password("SuperSecret!2026")
    assert verify_password("SuperSecret!2026", hashed) is True
    assert verify_password("wrong", hashed) is False


def test_web_login_and_threshold_configuration(db_session):
    db, SessionFactory = db_session
    admin = SystemUser(username="admin_test", password_hash=hash_password("AdminPass123!"), role="admin", is_active=True)
    grp = HostGroup(name="Web")
    db.add_all([admin, grp])
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
        # Unauthenticated access redirects or returns 401
        r_unauth = client.get("/", headers={"Accept": "application/json"})
        assert r_unauth.status_code == 401

        # Login
        r_login = client.post("/login", data={"username": "admin_test", "password": "AdminPass123!"}, follow_redirects=False)
        assert r_login.status_code == 303

        # Update threshold via web console
        r_th = client.post(
            "/groups/thresholds",
            data={
                "group_id": str(grp.id),
                "metric_name": "disk_pct",
                "warning_value": "75",
                "critical_value": "88",
                "sustained_minutes": "0",
            },
            follow_redirects=False,
        )
        assert r_th.status_code == 303

        th = db.query(Threshold).filter_by(group_id=grp.id, metric_name="disk_pct").one()
        assert th.warning_value == 75.0
        assert th.critical_value == 88.0
    finally:
        app.dependency_overrides.clear()
