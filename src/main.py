#!/usr/bin/env python
"""
BasicFirewall - A simple firewall implementation using Python

This script allows users to set up and configure basic firewall rules
to monitor and filter network traffic.
"""

import sys
import argparse
from firewall import BasicFirewall

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="A simple Python-based firewall for monitoring and filtering network traffic"
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to firewall configuration file",
        default="firewall_config.json"
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to monitor",
        default=None
    )
    parser.add_argument(
        "-l", "--log",
        help="Path to log file",
        default="firewall.log"
    )
    parser.add_argument(
        "-v", "--verbose",
        help="Enable verbose output",
        action="store_true"
    )
    return parser.parse_args()

def main():
    """Main entry point for the firewall application."""
    args = parse_args()
    
    try:
        # Initialize the firewall
        firewall = BasicFirewall(
            config_file=args.config,
            interface=args.interface,
            log_file=args.log,
            verbose=args.verbose
        )
        
        # Start the firewall
        firewall.start()
    except KeyboardInterrupt:
        print("\nFirewall shutting down...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
