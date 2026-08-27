"""
xfs package
===========
Authoritative XFS forensic recovery engine package for FirSeFile.
"""

from src.recovery.xfs.adapter import XfsRecoveryEngine, recover_xfs_image

__all__ = ["XfsRecoveryEngine", "recover_xfs_image"]
