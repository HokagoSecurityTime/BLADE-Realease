"""Explicit opt-in keeps existing Phase 1 deployments in enforcement mode."""
import os


def enabled(name: str, default: bool = True) -> bool:
    phase2 = os.getenv('BLADE_PHASE2_ENABLED', 'false').lower() == 'true'
    return phase2 and os.getenv(name, str(default)).lower() == 'true'
