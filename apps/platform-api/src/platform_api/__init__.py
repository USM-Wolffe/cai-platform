"""Minimal deterministic API app for cai-platform-v2."""

from platform_api.app import create_app, get_runtime_host, get_runtime_port, main

__all__ = ["create_app", "get_runtime_host", "get_runtime_port", "main"]
