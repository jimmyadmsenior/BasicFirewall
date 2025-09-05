"""
BasicFirewall core module - provides firewall functionality
"""

import json
import logging
import socket
import time
from datetime import datetime
import threading
from collections import defaultdict
import ipaddress
from src.packet_handler import PacketHandler
from src.rule_parser import RuleParser

class BasicFirewall:
    """
    A basic firewall implementation that can filter network traffic
    based on rules defined in a configuration file.
    """
    
    def __init__(self, config_file="firewall_config.json", interface=None, log_file="firewall.log", verbose=False):
        """
        Initialize the firewall with configuration settings
        
        Args:
            config_file (str): Path to configuration file
            interface (str): Network interface to monitor
            log_file (str): Path to log file
            verbose (bool): Enable verbose logging
        """
        self.config_file = config_file
        self.interface = interface
        self.log_file = log_file
        self.verbose = verbose
        
        # Set up logging
        self._setup_logging()
        
        # Load configuration
        self.config = self._load_config()
        
        # Initialize rule parser
        self.rule_parser = RuleParser(self.config.get("rules", []))
        
        # Initialize packet handler
        self.packet_handler = PacketHandler(interface)
        
        # Statistics tracking
        self.stats = {
            "packets_processed": 0,
            "packets_blocked": 0,
            "packets_allowed": 0,
            "start_time": datetime.now(),
        }
        
        # Traffic monitoring
        self.traffic_monitor = defaultdict(int)
        self.traffic_lock = threading.Lock()
        
        self.running = False
        
    def _setup_logging(self):
        """Configure logging based on settings"""
        log_level = logging.DEBUG if self.verbose else logging.INFO
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger("BasicFirewall")
        
    def _load_config(self):
        """Load firewall configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                self.logger.info(f"Loaded configuration from {self.config_file}")
                return config
        except FileNotFoundError:
            self.logger.warning(f"Configuration file {self.config_file} not found. Using default configuration.")
            return {
                "rules": [
                    {
                        "name": "Default Allow Rule",
                        "action": "allow",
                        "priority": 999
                    }
                ],
                "settings": {
                    "default_action": "allow",
                    "log_level": "info"
                }
            }
        except json.JSONDecodeError:
            self.logger.error(f"Error parsing configuration file {self.config_file}. Using default configuration.")
            return {"rules": [], "settings": {"default_action": "allow"}}
            
    def start(self):
        """Start the firewall"""
        self.running = True
        self.logger.info("Starting firewall...")
        
        # Start traffic monitoring in a separate thread
        traffic_thread = threading.Thread(target=self._monitor_traffic)
        traffic_thread.daemon = True
        traffic_thread.start()
        
        # Start packet processing
        try:
            self._process_packets()
        except Exception as e:
            self.logger.error(f"Error in packet processing: {e}")
            self.stop()
            
    def stop(self):
        """Stop the firewall"""
        self.running = False
        self.logger.info("Stopping firewall...")
        self._print_stats()
        
    def _process_packets(self):
        """Process network packets according to firewall rules"""
        self.logger.info("Starting packet processing...")
        
        for packet in self.packet_handler.capture_packets():
            if not self.running:
                break
                
            self.stats["packets_processed"] += 1
            
            # Apply firewall rules
            action = self.rule_parser.evaluate_packet(packet)
            
            # Update statistics
            if action == "block":
                self.stats["packets_blocked"] += 1
                self.logger.info(f"Blocked packet: {packet.summary()}")
            else:
                self.stats["packets_allowed"] += 1
                if self.verbose:
                    self.logger.debug(f"Allowed packet: {packet.summary()}")
            
            # Update traffic monitor
            self._update_traffic_stats(packet)
            
            # Every 1000 packets, log basic stats
            if self.stats["packets_processed"] % 1000 == 0:
                self._log_stats_summary()
    
    def _update_traffic_stats(self, packet):
        """Update traffic statistics for the packet"""
        try:
            # Get source and destination IPs
            if hasattr(packet, 'src') and hasattr(packet, 'dst'):
                with self.traffic_lock:
                    self.traffic_monitor[packet.src] += len(packet)
        except Exception as e:
            self.logger.error(f"Error updating traffic stats: {e}")
    
    def _monitor_traffic(self):
        """Monitor traffic patterns to identify potential threats"""
        self.logger.info("Starting traffic monitoring...")
        
        # Check for suspicious traffic patterns every 30 seconds
        while self.running:
            time.sleep(30)
            self._analyze_traffic()
    
    def _analyze_traffic(self):
        """Analyze traffic for suspicious patterns"""
        with self.traffic_lock:
            # Find IPs with high traffic volume
            high_traffic = {ip: bytes for ip, bytes in self.traffic_monitor.items() if bytes > 1000000}  # > 1MB
            
            for ip, bytes in high_traffic.items():
                self.logger.warning(f"High traffic detected from {ip}: {bytes / 1000000:.2f} MB")
    
    def _log_stats_summary(self):
        """Log a summary of firewall statistics"""
        runtime = datetime.now() - self.stats["start_time"]
        self.logger.info(
            f"Stats: {self.stats['packets_processed']} packets processed, "
            f"{self.stats['packets_blocked']} blocked, "
            f"{self.stats['packets_allowed']} allowed, "
            f"Running for {runtime.total_seconds():.1f}s"
        )
    
    def _print_stats(self):
        """Print firewall statistics"""
        runtime = datetime.now() - self.stats["start_time"]
        self.logger.info("=" * 50)
        self.logger.info("Firewall Statistics:")
        self.logger.info(f"Runtime: {runtime}")
        self.logger.info(f"Packets processed: {self.stats['packets_processed']}")
        self.logger.info(f"Packets blocked: {self.stats['packets_blocked']}")
        self.logger.info(f"Packets allowed: {self.stats['packets_allowed']}")
        self.logger.info("=" * 50)
