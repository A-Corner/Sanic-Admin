#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""`python -m tools.mcp_server` 入口（stdio 传输）。"""

import sys

from tools.mcp_server import main

if __name__ == "__main__":
    sys.exit(main())
