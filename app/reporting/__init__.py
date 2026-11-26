"""Report generation (Interactive HTML, PDF via WeasyPrint, and LLM-ready JSON)."""

from app.reporting.generator import generate_scan_report

__all__ = ["generate_scan_report"]
