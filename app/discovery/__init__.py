"""Initial discovery, versioned baseline management, and drift detection."""

from app.discovery.baseline_service import (
    approve_new_baseline,
    compute_baseline_diff,
    create_initial_baseline,
    get_active_baseline,
)

__all__ = [
    "get_active_baseline",
    "create_initial_baseline",
    "compute_baseline_diff",
    "approve_new_baseline",
]
