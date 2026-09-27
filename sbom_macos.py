#!/usr/bin/env python3
"""Backward-compatible entry point. Prefer sbom_auditor.py or sbom-sca-auditor."""

from sbom_builder.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
