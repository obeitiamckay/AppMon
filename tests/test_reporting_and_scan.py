"""End-to-end concurrent scan and report generation (HTML, PDF, JSON) tests."""

import json
from pathlib import Path

from app.collectors.base import HostTelemetry
from app.config import get_settings
from app.models.inventory import CredentialRef, Host, HostGroup
from app.models.monitoring import Report
from app.scheduler.runner import run_full_scan
from app.security import SecretCipher
from tests.mocks import (
    MockCollector,
    make_linux_mock_1,
    make_linux_mock_2,
    make_windows_mock_1,
    make_windows_mock_2,
)


def test_full_scan_with_2_linux_2_windows_and_unreachable_host(db_session, tmp_path: Path):
    db, SessionFactory = db_session
    settings = get_settings()
    settings.reports_dir = tmp_path / "reports"

    cipher = SecretCipher()
    cred = CredentialRef(name="mock-cred", auth_type="ssh_key", username="socmon_ro", encrypted_secret=cipher.encrypt("dummy"))
    grp = HostGroup(name="Prod")
    db.add_all([cred, grp])
    db.flush()

    hosts_data = [
        ("linux-web-01", "10.0.1.10", "linux", 22),
        ("linux-db-01", "10.0.1.11", "linux", 22),
        ("win-app-01", "10.0.2.10", "windows", 5986),
        ("win-dc-01", "10.0.2.11", "windows", 5986),
        ("linux-down-01", "10.0.9.99", "linux", 22),
    ]
    for hn, ip, os_t, port in hosts_data:
        db.add(Host(hostname=hn, ip_address=ip, os_type=os_t, port=port, group_id=grp.id, credential_id=cred.id))
    db.commit()

    telemetry_map = {
        "linux-web-01": make_linux_mock_1(),
        "linux-db-01": make_linux_mock_2(),
        "win-app-01": make_windows_mock_1(),
        "win-dc-01": make_windows_mock_2(),
        "linux-down-01": HostTelemetry(hostname="linux-down-01", os_type="linux", reachable=False, error_message="Timeout"),
    }

    def factory(host, _cred, _timeout):
        return MockCollector(telemetry_map[host.hostname])

    scan = run_full_scan(
        trigger_type="manual",
        triggered_by="pytest",
        session_factory=SessionFactory,
        collector_factory=factory,
    )

    assert scan.status == "completed"
    assert scan.total_hosts == 5
    assert scan.ok_hosts == 2
    assert scan.unreachable_hosts == 1
    assert scan.critical_hosts >= 1

    report = db.query(Report).filter_by(scan_run_id=scan.id).one()
    assert Path(report.html_path).exists()
    assert Path(report.json_path).exists()

    json_data = json.loads(Path(report.json_path).read_text(encoding="utf-8"))
    assert json_data["summary"]["total_hosts"] == 5
    assert len(json_data["findings"]) > 0
    sample = json_data["findings"][0]
    for required_field in ("id", "timestamp", "host", "grupo", "check", "categoria", "severidad", "titulo", "descripcion", "evidencia", "recomendacion", "comando_sugerido", "mitre_id", "estado"):
        assert required_field in sample
