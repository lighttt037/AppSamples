#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Traffic Recording Module

Records and analyzes network traffic patterns from APK executions.
Part of the Profit2Pitfall toolkit.
"""

import os
import json
import time
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class TrafficRecorder:
    """Records and manages network traffic data."""
    
    def __init__(self, output_dir: str = "./traffic_records"):
        """
        Initialize traffic recorder.
        
        Args:
            output_dir: Directory to store recordings
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.current_session: Optional[Dict[str, Any]] = None
        
    def start_session(self, app_id: str, metadata: Dict[str, Any] = None) -> str:
        """
        Start a new recording session.
        
        Args:
            app_id: Application identifier
            metadata: Optional metadata for session
            
        Returns:
            Session ID
        """
        session_id = f"{app_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.current_session = {
            'session_id': session_id,
            'app_id': app_id,
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'metadata': metadata or {},
            'traffic_entries': [],
            'summary': {}
        }
        
        logger.info(f"Started session: {session_id}")
        return session_id
        
    def add_traffic_entry(self, entry: Dict[str, Any]):
        """Add a traffic entry to current session."""
        if not self.current_session:
            logger.error("No active session")
            return
            
        entry['timestamp'] = datetime.now().isoformat()
        self.current_session['traffic_entries'].append(entry)
        
    def end_session(self) -> str:
        """End current session and save to file."""
        if not self.current_session:
            logger.error("No active session")
            return ""
            
        self.current_session['end_time'] = datetime.now().isoformat()
        self.current_session['summary'] = self._generate_summary()
        
        output_file = self.output_dir / f"{self.current_session['session_id']}.json"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.current_session, f, indent=2, ensure_ascii=False)
            
        logger.info(f"Session saved: {output_file}")
        
        session_id = self.current_session['session_id']
        self.current_session = None
        
        return str(output_file)
        
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics for session."""
        entries = self.current_session.get('traffic_entries', [])
        
        hosts = set()
        ips = set()
        urls = []
        
        for entry in entries:
            if 'host' in entry:
                hosts.add(entry['host'])
            if 'ip' in entry:
                ips.add(entry['ip'])
            if 'url' in entry:
                urls.append(entry['url'])
                
        return {
            'total_entries': len(entries),
            'unique_hosts': len(hosts),
            'unique_ips': len(ips),
            'hosts_list': sorted(hosts),
            'total_urls': len(urls)
        }
        
    def load_session(self, session_file: str) -> Dict[str, Any]:
        """Load a saved session file."""
        with open(session_file, 'r', encoding='utf-8') as f:
            return json.load(f)
            
    def merge_sessions(
        self,
        session_files: List[str],
        output_file: str
    ) -> Dict[str, Any]:
        """Merge multiple session files."""
        merged = {
            'merged_at': datetime.now().isoformat(),
            'sessions': [],
            'all_hosts': set(),
            'all_ips': set()
        }
        
        for sf in session_files:
            try:
                session = self.load_session(sf)
                merged['sessions'].append({
                    'session_id': session['session_id'],
                    'app_id': session['app_id'],
                    'entry_count': len(session.get('traffic_entries', []))
                })
                
                summary = session.get('summary', {})
                merged['all_hosts'].update(summary.get('hosts_list', []))
                
            except Exception as e:
                logger.error(f"Error loading {sf}: {e}")
                
        merged['all_hosts'] = sorted(merged['all_hosts'])
        merged['all_ips'] = sorted(merged['all_ips'])
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(merged, f, indent=2, ensure_ascii=False, default=list)
            
        return merged


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Record and manage traffic data')
    parser.add_argument('--view', '-v', help='View a session file')
    parser.add_argument('--merge', '-m', nargs='+', help='Merge session files')
    parser.add_argument('--output', '-o', default='merged_sessions.json', help='Output file for merge')
    parser.add_argument('--list', '-l', help='List sessions in directory')
    
    args = parser.parse_args()
    
    recorder = TrafficRecorder()
    
    if args.view:
        session = recorder.load_session(args.view)
        print(f"\nSession: {session['session_id']}")
        print(f"App: {session['app_id']}")
        print(f"Start: {session['start_time']}")
        print(f"End: {session.get('end_time', 'N/A')}")
        
        summary = session.get('summary', {})
        print(f"\nSummary:")
        print(f"  Total entries: {summary.get('total_entries', 0)}")
        print(f"  Unique hosts: {summary.get('unique_hosts', 0)}")
        print(f"  Unique IPs: {summary.get('unique_ips', 0)}")
        
    elif args.merge:
        result = recorder.merge_sessions(args.merge, args.output)
        print(f"\nMerged {len(result['sessions'])} sessions")
        print(f"Total unique hosts: {len(result['all_hosts'])}")
        print(f"Output: {args.output}")
        
    elif args.list:
        sessions_dir = Path(args.list)
        session_files = list(sessions_dir.glob("*.json"))
        print(f"\nFound {len(session_files)} session files:")
        for sf in session_files[:20]:
            print(f"  - {sf.name}")
            
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
