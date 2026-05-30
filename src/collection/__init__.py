#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Collection Module

Utilities for APK sample collection and preprocessing:
- Sample deduplication and merging
- Hash-based file naming
- Collection timeline tracking
- Similarity clustering
"""

from .duplicate_merge import (
    find_duplicates,
    merge_duplicates,
    deduplicate_directory,
    compute_file_hash,
)
from .moguahashname import rename_by_hash, batch_rename
from .moguatime import CollectionTimeline, organize_by_date
from .zhihuaspace import SimilarityClusterer

__all__ = [
    'find_duplicates',
    'merge_duplicates',
    'deduplicate_directory',
    'compute_file_hash',
    'rename_by_hash',
    'batch_rename',
    'CollectionTimeline',
    'organize_by_date',
    'SimilarityClusterer',
]