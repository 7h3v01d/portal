# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Portal — a secure, self-hosted Windows remote-assistance and file-transfer tool.

Working name: "Portal". This is the foundation package; see docs/ROADMAP.md for the
build sequence. The guiding rule for the whole codebase: **transport connectivity
grants zero authority by itself.** Every capability is explicitly granted and
independently revocable.
"""

__version__ = "0.2.0"
__author__ = "Leon Priest"
__license__ = "Apache-2.0"
