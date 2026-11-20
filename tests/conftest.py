"""Fixture AP lines and expected rows are in US Pacific time."""

import os
from pathlib import Path
import sys
import time

os.environ["TZ"] = "America/Los_Angeles"
time.tzset()
sys.path.insert(0, str(Path(__file__).parent))
