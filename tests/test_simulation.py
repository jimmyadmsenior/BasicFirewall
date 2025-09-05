"""
Simulation test for BasicFirewall - Tests functionality without capturing real packets
"""

import sys
import os
import json
from scapy.all import IP, TCP, UDP, ICMP
import unittest

# Add parent directory to path to import firewall modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.firewall import BasicFirewall
from src.rule_parser import RuleParser

class MockPacket:
    """Mock packet for testing"""
    def __init__(self, src_ip, dst_ip, src_port=None, dst_port=None, proto=None):
        self.src = src_ip
        self.dst = dst_ip
        if src_port is not None:
            self.sport = src_port
        if dst_port is not None:
            self.dport = dst_port
        if proto is not None:
            self.proto = proto
            
    def summary(self):
        """Return a summary string for the packet"""
        src_port = getattr(self, 'sport', '-')
        dst_port = getattr(self, 'dst_port', '-')
        return f"{self.src}:{src_port} > {self.dst}:{dst_port}"

def create_test_config():
    """Create a test configuration file"""
    config = {
        "rules": [
            {
                "name": "Block Telnet",
                "action": "block",
                "dst_port": 23,
                "protocol": "tcp",
                "priority": 10
            },
            {
                "name": "Block FTP",
                "action": "block",
                "dst_port": "20-21",
                "protocol": "tcp",
                "priority": 20
            },
            {
                "name": "Allow HTTP/HTTPS",
                "action": "allow",
                "dst_port": [80, 443],
                "protocol": "tcp",
                "priority": 30
            },
            {
                "name": "Allow DNS",
                "action": "allow",
                "dst_port": 53,
                "priority": 40
            },
            {
                "name": "Block Local Network Access",
                "action": "block",
                "dst_ip": "192.168.1.0/24",
                "priority": 50
            },
            {
                "name": "Default Rule",
                "action": "block",
                "priority": 999
            }
        ],
        "settings": {
            "default_action": "block",
            "log_level": "info",
        }
    }
    
    # Save the configuration to a temporary file
    with open("test_firewall_config.json", "w") as f:
        json.dump(config, f, indent=4)
        
    return "test_firewall_config.json"

class TestFirewallSimulation(unittest.TestCase):
    """Test the firewall with simulated packets"""
    
    @classmethod
    def setUpClass(cls):
        """Set up the test environment"""
        cls.config_file = create_test_config()
        
    @classmethod
    def tearDownClass(cls):
        """Clean up after tests"""
        if os.path.exists(cls.config_file):
            os.remove(cls.config_file)
            
    def setUp(self):
        """Set up each test"""
        # Create a firewall instance for testing
        self.firewall = BasicFirewall(config_file=self.config_file)
        
    def test_telnet_blocked(self):
        """Test that Telnet traffic is blocked"""
        # Create a mock Telnet packet
        packet = MockPacket("8.8.8.8", "192.168.1.100", 12345, 23, 6)  # TCP to port 23
        
        # Manually evaluate the packet against the rules
        action = self.firewall.rule_parser.evaluate_packet(packet)
        
        # Check that the packet is blocked
        self.assertEqual(action, "block")
        
    def test_http_allowed(self):
        """Test that HTTP traffic is allowed"""
        # Create a mock HTTP packet
        packet = MockPacket("8.8.8.8", "192.168.1.100", 12345, 80, 6)  # TCP to port 80
        
        # Manually evaluate the packet against the rules
        action = self.firewall.rule_parser.evaluate_packet(packet)
        
        # Check that the packet is allowed
        self.assertEqual(action, "allow")
        
    def test_https_allowed(self):
        """Test that HTTPS traffic is allowed"""
        # Create a mock HTTPS packet
        packet = MockPacket("8.8.8.8", "192.168.1.100", 12345, 443, 6)  # TCP to port 443
        
        # Manually evaluate the packet against the rules
        action = self.firewall.rule_parser.evaluate_packet(packet)
        
        # Check that the packet is allowed
        self.assertEqual(action, "allow")
        
    def test_ftp_blocked(self):
        """Test that FTP traffic is blocked"""
        # Create a mock FTP control packet
        packet1 = MockPacket("8.8.8.8", "192.168.1.100", 12345, 21, 6)  # TCP to port 21
        
        # Create a mock FTP data packet
        packet2 = MockPacket("8.8.8.8", "192.168.1.100", 12345, 20, 6)  # TCP to port 20
        
        # Manually evaluate the packets against the rules
        action1 = self.firewall.rule_parser.evaluate_packet(packet1)
        action2 = self.firewall.rule_parser.evaluate_packet(packet2)
        
        # Check that both packets are blocked
        self.assertEqual(action1, "block")
        self.assertEqual(action2, "block")
        
    def test_local_network_blocked(self):
        """Test that access to the local network is blocked"""
        # Create a mock packet to a local network address
        packet = MockPacket("8.8.8.8", "192.168.1.10", 12345, 8080, 6)
        
        # Manually evaluate the packet against the rules
        action = self.firewall.rule_parser.evaluate_packet(packet)
        
        # Check that the packet is blocked
        self.assertEqual(action, "block")
        
    def test_unknown_port_blocked(self):
        """Test that traffic to an unknown port is blocked by default"""
        # Create a mock packet to an uncommon port
        packet = MockPacket("8.8.8.8", "203.0.113.1", 12345, 12345, 6)  # Some random port
        
        # Manually evaluate the packet against the rules
        action = self.firewall.rule_parser.evaluate_packet(packet)
        
        # Check that the packet is blocked by the default rule
        self.assertEqual(action, "block")

if __name__ == "__main__":
    unittest.main()
