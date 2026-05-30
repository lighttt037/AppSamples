#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK Collection Timeline Module

Organizes and tracks APK samples by collection time for temporal analysis.
Part of the Profit2Pitfall toolkit.
"""

import os
import json
import shutil
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CollectionTimeline:
    """Manages APK collection timeline data."""
    
    def __init__(self, data_dir: str = "./collection_timeline"):
        """
        Initialize timeline manager.
        
        Args:
            data_dir: Directory to store timeline data
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.timeline_file = self.data_dir / "timeline.json"
        self.timeline = self._load_timeline()
        
    def _load_timeline(self) -> Dict[str, Any]:
        """Load existing timeline data."""
        if self.timeline_file.exists():
            with open(self.timeline_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {'entries': [], 'metadata': {}}
        
    def _save_timeline(self):
        """Save timeline data."""
        with open(self.timeline_file, 'w', encoding='utf-8') as f:
            json.dump(self.timeline, f, indent=2, ensure_ascii=False)
            
    def add_collection(
        self,
        collection_id: str,
        source: str,
        file_count: int,
        description: str = "",
        metadata: Dict[str, Any] = None
    ):
        """
        Add a new collection entry.
        
        Args:
            collection_id: Unique identifier for collection
            source: Source of the samples
            file_count: Number of files in collection
            description: Description of collection
            metadata: Additional metadata
        """
        entry = {
            'collection_id': collection_id,
            'timestamp': datetime.now().isoformat(),
            'source': source,
            'file_count': file_count,
            'description': description,
            'metadata': metadata or {}
        }
        
        self.timeline['entries'].append(entry)
        self._save_timeline()
        logger.info(f"Added collection: {collection_id}")
        
    def get_collections_by_date(
        self,
        start_date: str = None,
        end_date: str = None
    ) -> List[Dict[str, Any]]:
        """
        Get collections within a date range.
        
        Args:
            start_date: Start date (YYYY-MM-DD)
            end_date: End date (YYYY-MM-DD)
            
        Returns:
            List of matching collection entries
        """
        entries = self.timeline.get('entries', [])
        
        if not start_date and not end_date:
            return entries
            
        filtered = []
        for entry in entries:
            entry_date = entry['timestamp'][:10]
            
            if start_date and entry_date < start_date:
                continue
            if end_date and entry_date > end_date:
                continue
                
            filtered.append(entry)
            
        return filtered
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get timeline statistics."""
        entries = self.timeline.get('entries', [])
        
        if not entries:
            return {'total_collections': 0, 'total_files': 0}
            
        total_files = sum(e.get('file_count', 0) for e in entries)
        sources = {}
        
        for entry in entries:
            source = entry.get('source', 'unknown')
            sources[source] = sources.get(source, 0) + entry.get('file_count', 0)
            
        return {
            'total_collections': len(entries),
            'total_files': total_files,
            'sources': sources,
            'first_collection': entries[0]['timestamp'] if entries else None,
            'last_collection': entries[-1]['timestamp'] if entries else None
        }
        
    def export_report(self, output_file: str):
        """Export timeline report."""
        stats = self.get_statistics()
        entries = self.timeline.get('entries', [])
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("APK Collection Timeline Report\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Total collections: {stats['total_collections']}\n")
            f.write(f"Total files: {stats['total_files']}\n")
            f.write(f"First collection: {stats.get('first_collection', 'N/A')}\n")
            f.write(f"Last collection: {stats.get('last_collection', 'N/A')}\n\n")
            
            f.write("Sources:\n")
            for source, count in stats.get('sources', {}).items():
                f.write(f"  {source}: {count} files\n")
            f.write("\n")
            
            f.write("Collection History:\n")
            f.write("-" * 40 + "\n")
            for entry in entries[-20:]:  # Last 20 entries
                f.write(f"{entry['timestamp'][:10]} | {entry['collection_id']} | {entry['file_count']} files\n")
                
        logger.info(f"Report saved to: {output_file}")


def organize_by_date(
    input_dir: str,
    output_dir: str,
    date_format: str = "%Y-%m"
) -> Dict[str, int]:
    """
    Organize files by modification date.
    
    Args:
        input_dir: Input directory
        output_dir: Output directory
        date_format: Date format for subdirectories
        
    Returns:
        Dictionary of date -> file count
    """
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    
    if not input_path.exists():
        logger.error(f"Directory not found: {input_dir}")
        return {}
        
    date_counts = {}
    
    for file_path in input_path.glob("*.apk"):
        mtime = os.path.getmtime(file_path)
        date_str = datetime.fromtimestamp(mtime).strftime(date_format)
        
        dest_dir = output_path / date_str
        dest_dir.mkdir(parents=True, exist_ok=True)
        
        dest_file = dest_dir / file_path.name
        if not dest_file.exists():
            shutil.copy2(file_path, dest_file)
            
        date_counts[date_str] = date_counts.get(date_str, 0) + 1
        
    return date_counts


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Manage APK collection timeline')
    parser.add_argument('--add', '-a', nargs=4, metavar=('ID', 'SOURCE', 'COUNT', 'DESC'),
                       help='Add collection: ID SOURCE COUNT DESCRIPTION')
    parser.add_argument('--stats', '-s', action='store_true', help='Show statistics')
    parser.add_argument('--report', '-r', help='Export report to file')
    parser.add_argument('--organize', '-o', nargs=2, metavar=('INPUT', 'OUTPUT'),
                       help='Organize files by date')
    parser.add_argument('--data-dir', '-d', default='./collection_timeline',
                       help='Timeline data directory')
    
    args = parser.parse_args()
    
    timeline = CollectionTimeline(args.data_dir)
    
    if args.add:
        collection_id, source, count, desc = args.add
        timeline.add_collection(collection_id, source, int(count), desc)
        print(f"Added collection: {collection_id}")
        
    elif args.stats:
        stats = timeline.get_statistics()
        print(f"\nTimeline Statistics:")
        print(f"  Total collections: {stats['total_collections']}")
        print(f"  Total files: {stats['total_files']}")
        
    elif args.report:
        timeline.export_report(args.report)
        print(f"Report saved to: {args.report}")
        
    elif args.organize:
        input_dir, output_dir = args.organize
        counts = organize_by_date(input_dir, output_dir)
        print(f"\nOrganized {sum(counts.values())} files into {len(counts)} date groups")
        
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
