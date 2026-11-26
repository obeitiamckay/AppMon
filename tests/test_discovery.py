"""Tests for initial discovery, versioned baselines, and drift detection."""

from app.discovery.baseline_service import (
    approve_new_baseline,
    compute_baseline_diff,
    create_initial_baseline,
    get_active_baseline,
)
from app.models.inventory import Host
from tests.mocks import make_linux_mock_1


def test_discovery_creates_baseline_and_detects_drift(db_session):
    db, _ = db_session
    host = Host(hostname="linux-web-01", ip_address="10.0.1.10", os_type="linux", port=22)
    db.add(host)
    db.flush()

    t1 = make_linux_mock_1()
    b1 = create_initial_baseline(db, host, t1)
    db.commit()

    assert b1.version == 1
    assert b1.is_active is True
    assert get_active_baseline(db, host.id).id == b1.id

    # Introduce drift: new service and new listening port
    t2 = make_linux_mock_1()
    t2.services.append({"name": "backdoor.service", "active_state": "active", "sub_state": "running", "enabled_state": "enabled"})
    t2.ports.append({"protocol": "tcp", "address": "0.0.0.0", "port": 9999, "process": "nc"})

    diff = compute_baseline_diff(b1, t2)
    assert diff["has_drift"] is True
    assert "backdoor.service" in diff["added_services"]
    assert "tcp/9999" in diff["added_ports"]

    # Approve new baseline -> version 2 becomes active
    b2 = approve_new_baseline(
        db,
        host.id,
        {"services": t2.services, "ports": t2.ports, "os_info": t2.os_info, "firewall": t2.firewall, "admins": t2.admins},
        approved_by="socadmin",
    )
    db.commit()
    assert b2.version == 2
    assert get_active_baseline(db, host.id).version == 2
