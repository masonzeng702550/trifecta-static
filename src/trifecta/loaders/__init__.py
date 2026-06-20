"""Framework adapters: normalise tool/agent definitions into the IR."""

from .registry import load_path, detect_frameworks

__all__ = ["load_path", "detect_frameworks"]
