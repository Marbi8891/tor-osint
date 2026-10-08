"""Permite ejecutar ``python -m tor_osint``."""

import sys

from .cli import main

sys.exit(main())
