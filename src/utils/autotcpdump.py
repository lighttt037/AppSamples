#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auto TCPDump Module

Automates tcpdump for capturing network traffic from Android emulators/devices.
Part of the Profit2Pitfall toolkit.
"""

import os
import subprocess
import argparse
import logging
import time
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class TcpDumpController:
    """Controller for tcpdump network capture."""
    
    def __init__(self, output_dir: str = "./pcap_captures"):
        """
        Initialize tcpdump controller.
        
        Args:
            output_dir: Directory to save PCAP files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.process: Optional[subprocess.Popen] = None
        
    def verify_adb(self) -> bool:
        """Verify ADB is available."""
        try:
            result = subprocess.run(
                ["adb", "version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            logger.info(f"ADB available: {result.stdout.strip().split()[0]}")
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.error("ADB not found. Please install Android SDK tools")
            return False
            
    def get_connected_devices(self) -> list:
        """Get list of connected Android devices."""
        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            devices = []
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            for line in lines:
                if '\t' in line:
                    device_id = line.split('\t')[0]
                    devices.append(device_id)
                    
            return devices
        except Exception as e:
            logger.error(f"Error getting devices: {e}")
            return []
            
    def start_capture(
        self,
        device_id: Optional[str] = None,
        interface: str = "any",
        duration: int = 300,
        app_name: str = "capture"
    ) -> str:
        """
        Start capturing traffic on device.
        
        Args:
            device_id: Android device ID (uses first if not specified)
            interface: Network interface to capture
            duration: Capture duration in seconds
            app_name: Application name for output file
            
        Returns:
            Path to captured PCAP file
        """
        devices = self.get_connected_devices()
        if not devices:
            logger.error("No connected Android devices found")
            return ""
            
        if device_id is None:
            device_id = devices[0]
            logger.info(f"Using device: {device_id}")
            
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        remote_path = f"/sdcard/{app_name}_{timestamp}.pcap"
        local_path = str(self.output_dir / f"{app_name}_{timestamp}.pcap")
        
        # Start tcpdump on device
        adb_prefix = ["adb", "-s", device_id]
        
        # Check if tcpdump exists on device
        check_cmd = adb_prefix + ["shell", "which", "tcpdump"]
        result = subprocess.run(check_cmd, capture_output=True, text=True)
        
        if "tcpdump" not in result.stdout:
            logger.error("tcpdump not found on device. Please install it.")
            return ""
            
        # Start capture
        tcpdump_cmd = f"tcpdump -i {interface} -w {remote_path}"
        capture_cmd = adb_prefix + ["shell", tcpdump_cmd]
        
        logger.info(f"Starting capture on device {device_id}")
        logger.info(f"Interface: {interface}, Duration: {duration}s")
        
        try:
            self.process = subprocess.Popen(
                capture_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            time.sleep(duration)
            
            # Stop capture
            self.stop_capture(device_id)
            
            # Pull file from device
            pull_cmd = adb_prefix + ["pull", remote_path, local_path]
            subprocess.run(pull_cmd, capture_output=True, timeout=60)
            
            # Clean up remote file
            rm_cmd = adb_prefix + ["shell", "rm", remote_path]
            subprocess.run(rm_cmd, capture_output=True, timeout=10)
            
            logger.info(f"Capture saved to: {local_path}")
            return local_path
            
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.stop_capture(device_id)
            return ""
            
    def stop_capture(self, device_id: str):
        """Stop the capture process."""
        if self.process:
            self.process.terminate()
            self.process = None
            
        # Kill tcpdump on device
        try:
            kill_cmd = ["adb", "-s", device_id, "shell", "pkill", "tcpdump"]
            subprocess.run(kill_cmd, capture_output=True, timeout=10)
        except Exception:
            pass
            
        logger.info("Capture stopped")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Capture network traffic from Android device')
    parser.add_argument('--device', '-d', help='Android device ID')
    parser.add_argument('--interface', '-i', default='any', help='Network interface')
    parser.add_argument('--duration', '-t', type=int, default=300, help='Capture duration (seconds)')
    parser.add_argument('--app-name', '-a', default='capture', help='Application name for output')
    parser.add_argument('--output-dir', '-o', default='./pcap_captures', help='Output directory')
    parser.add_argument('--list-devices', '-l', action='store_true', help='List connected devices')
    
    args = parser.parse_args()
    
    controller = TcpDumpController(args.output_dir)
    
    if not controller.verify_adb():
        return
        
    if args.list_devices:
        devices = controller.get_connected_devices()
        print(f"\nConnected devices ({len(devices)}):")
        for device in devices:
            print(f"  - {device}")
        return
        
    try:
        pcap_file = controller.start_capture(
            device_id=args.device,
            interface=args.interface,
            duration=args.duration,
            app_name=args.app_name
        )
        if pcap_file:
            print(f"\nCapture complete: {pcap_file}")
    except KeyboardInterrupt:
        print("\nCapture interrupted")


if __name__ == "__main__":
    main()
