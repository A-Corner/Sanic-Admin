#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
测试包初始化文件

包含测试环境设置和共享测试工具
"""

import os
import sys
import asyncio
import pytest
from typing import Dict, Any, List, Optional

# 确保能够导入应用模块
app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if app_path not in sys.path:
    sys.path.insert(0, app_path) 