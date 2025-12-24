#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Profit2Pitfall: Task-Oriented Scam App Analysis Toolkit

A toolkit for analyzing task-oriented scam mobile applications.

Features:
- Network evasion detection (Time-Based Domain Rotation)
- Remote cloud server loading detection
- Certificate analysis and reuse detection
- Dangerous permission analysis
- APK similarity clustering
- Emulator detection analysis

Usage:
    from src import network, detection, collection, utils
    
    # Detect domain rotation
    from src.network import DomainRotationDetector
    detector = DomainRotationDetector()
    result = detector.detect(traffic_t1, traffic_t2)
"""

__version__ = "1.0.0"
__license__ = "MIT"

from . import detection
from . import collection
from . import network
from . import utils

__all__ = [
    'detection',
    'collection', 
    'network',
    'utils',
    '__version__',
]