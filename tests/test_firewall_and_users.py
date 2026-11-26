"""Tests for firewall/ports comparison and admin user auditing."""

from app.firewall.analyzer import analyze_firewall_and_ports
from app.models.inventory import Host, HostGroup
from app.models.monitoring import ScanRun
from app.models.security_audit import AdminUserAllowed, AdminUserHistory, FirewallAllowedRule
from app.users.admin_audit import audit_admin_users
from tests.mocks import make_linux_mock_2, make_windows_mock_2


def test_firewall_comparison_detects_unauthorized_ports_and_0000(db_session):
    db, _ = db_session
    grp = HostGroup(name="DB")
    db.add(grp)
    db.flush()
    db.add(FirewallAllowedRule(group_id=grp.id, port=5432, protocol="tcp", allowed_sources="10.0.0.0/8"))

    host = Host(hostname="linux-db-01", ip_address="10.0.2.10", os_type="linux", port=22, group_id=grp.id)
    scan = ScanRun(trigger_type="manual", triggered_by="pytest")
    db.add_all([host, scan])
    db.flush()

    telemetry = make_linux_mock_2()
    port_table, findings = analyze_firewall_and_ports(db, scan.id, host, telemetry)

    statuses = {p["port"]: p["status"] for p in port_table}
    assert statuses[4444] == "no autorizado"
    assert statuses[5432] == "revisar"
    assert any("0.0.0.0/0" in f.title for f in findings)
    assert any("4444" in f.title for f in findings)


def test_firewall_detects_any_to_any_on_windows(db_session):
    db, _ = db_session
    host = Host(hostname="win-dc-01", ip_address="10.0.3.20", os_type="windows", port=5986)
    scan = ScanRun(trigger_type="manual", triggered_by="pytest")
    db.add_all([host, scan])
    db.flush()

    _, findings = analyze_firewall_and_ports(db, scan.id, host, make_windows_mock_2())
    assert any("Any-to-Any" in f.title for f in findings)


def test_admin_audit_detects_unauthorized_inactive_and_service_admins(db_session):
    db, _ = db_session
    grp = HostGroup(name="DB")
    db.add(grp)
    db.flush()
    db.add(AdminUserAllowed(group_id=grp.id, username="root", account_type="human"))

    host = Host(hostname="linux-db-01", ip_address="10.0.2.10", os_type="linux", port=22, group_id=grp.id)
    scan = ScanRun(trigger_type="manual", triggered_by="pytest")
    db.add_all([host, scan])
    db.flush()

    findings = audit_admin_users(db, scan.id, host, make_linux_mock_2())
    titles = [f.title for f in findings]
    assert any("rogue_admin" in t and "NO autorizado" in t for t in titles)
    assert any("inactiva >90 días" in t for t in titles)
    assert any("sin expiración" in t for t in titles)

    # Run second scan with rogue_admin removed -> should record AdminUserHistory
    t2 = make_linux_mock_2()
    t2.admins = [{"username": "root", "privilege_source": "uid_0", "is_service_account": False}]
    audit_admin_users(db, scan.id, host, t2)
    db.commit()

    hist = db.query(AdminUserHistory).filter_by(host_id=host.id).all()
    assert any(h.username == "rogue_admin" and h.change_type == "removed" for h in hist)
