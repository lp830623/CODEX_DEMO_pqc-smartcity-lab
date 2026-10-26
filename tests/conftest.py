"""Pytest configuration.

The dynamic linker reads LD_LIBRARY_PATH at process start. OQS_INSTALL_PATH is
read by liboqs-python at import, which happens after this file is loaded.
"""

from __future__ import annotations

import os
from pathlib import Path

_install = Path(os.environ.get("OQS_INSTALL_PATH", "/opt/liboqs"))
if (_install / "lib").is_dir():
    os.environ.setdefault("OQS_INSTALL_PATH", str(_install))
