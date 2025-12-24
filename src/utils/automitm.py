#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auto MITM Module

Automates MITM proxy setup for capturing APK network traffic.
Part of the Profit2Pitfall toolkit.
"""

import os
import subprocess
import argparse
import logging
import time
import signal
from pathlib import Path
from typing import Optional, Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class MitmProxyController:
    """Controller for mitmproxy to capture app traffic."""
    
    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 8080,
        output_dir: str = "./mitm_captures"
    ):
        """
        Initialize MITM proxy controller.
        
        Args:
            listen_host: Host to bind proxy
            listen_port: Port for proxy
            output_dir: Directory to save captures
        """
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.process: Optional[subprocess.Popen] = None
        
    def verify_mitmproxy(self) -> bool:
        """Verify mitmproxy is installed."""
        try:
            result = subprocess.run(
                ["mitmdump", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            logger.info(f"mitmproxy version: {result.stdout.strip().split()[0]}")
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.error("mitmproxy not found. Install with: pip install mitmproxy")
            return False
            
    def start_capture(
        self,
        app_name: str,
        duration: int = 300,
        flow_file: Optional[str] = None
    ) -> str:
        """
        Start capturing traffic.
        
        Args:
            app_name: Application identifier for naming output
            duration: Capture duration in seconds
            flow_file: Optional custom output file path
            
        Returns:
            Path to captured flow file
        """
        if flow_file is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            flow_file = str(self.output_dir / f"{app_name}_{timestamp}.flow")
            
        cmd = [
            "mitmdump",
            "--listen-host", self.listen_host,
            "--listen-port", str(self.listen_port),
            "-w", flow_file,
            "--set", "ssl_insecure=true"
        ]
        
        logger.info(f"Starting MITM capture on {self.listen_host}:{self.listen_port}")
        logger.info(f"Output: {flow_file}")
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            logger.info(f"Capturing for {duration} seconds...")
            time.sleep(duration)
            
            self.stop_capture()
            
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.stop_capture()
            
        return flow_file
        
    def stop_capture(self):
        """Stop the capture process."""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None
            logger.info("Capture stopped")
            
    def parse_flow_file(self, flow_file: str) -> Dict[str, Any]:
        """
        Parse captured flow file.
        
        Args:
            flow_file: Path to flow file
            
        Returns:
            Dictionary with parsed data
        """
        if not os.path.exists(flow_file):
            logger.error(f"Flow file not found: {flow_file}")
            return {}
            
        # Use mitmdump to read and output flows
        cmd = [
            "mitmdump",
            "-r", flow_file,
            "-n",  # Don't start proxy
            "--set", "flow_detail=0"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Parse output for URLs and hosts
            lines = result.stdout.strip().split('\n')
            requests = []
            
            for line in lines:
                if line.strip():
                    requests.append(line.strip())
                    
            return {
                'flow_file': flow_file,
                'request_count': len(requests),
                'requests': requests
            }
            
        except Exception as e:
            logger.error(f"Parse error: {e}")
            return {}


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Capture app traffic with MITM proxy')
    parser.add_argument('--app-name', '-a', default='capture', help='Application name for output')
    parser.add_argument('--duration', '-d', type=int, default=300, help='Capture duration in seconds')
    parser.add_argument('--port', '-p', type=int, default=8080, help='Proxy port')
    parser.add_argument('--output-dir', '-o', default='./mitm_captures', help='Output directory')
    parser.add_argument('--parse', help='Parse existing flow file')
    
    args = parser.parse_args()
    
    controller = MitmProxyController(
        listen_port=args.port,
        output_dir=args.output_dir
    )
    
    if args.parse:
        results = controller.parse_flow_file(args.parse)
        print(f"\nParsed {results.get('request_count', 0)} requests")
        return
        
    if not controller.verify_mitmproxy():
        print("Error: mitmproxy not found")
        return
        
    try:
        flow_file = controller.start_capture(args.app_name, args.duration)
        print(f"\nCapture saved to: {flow_file}")
    except KeyboardInterrupt:
        controller.stop_capture()
        print("\nCapture interrupted")


if __name__ == "__main__":
    main()
