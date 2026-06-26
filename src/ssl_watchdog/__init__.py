"""
ssl-watchdog: Monitoraggio della salute dei domini (SSL e WHOIS)
"""

from .main import analizza_dominio, cli_entrypoint

__version__ = "1.0.0"
__author__ = "Patrizio Fanelli"

__all__ = [
    "analizza_dominio",
    "cli_entrypoint",
]
