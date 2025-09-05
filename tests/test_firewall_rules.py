"""
Test module for the BasicFirewall components
"""

import unittest
import os
import json
import tempfile
from src.rule_parser import Rule, RuleParser

class TestFirewallRules(unittest.TestCase):
    """Test cases for firewall rule parsing and evaluation"""
    
    def test_rule_creation(self):
        """Test creating a rule from a dictionary"""
        rule_dict = {
            "name": "Test Rule",
            "action": "block",
            "src_ip": "192.168.1.0/24",
            "dst_port": 80,
            "protocol": "tcp",
            "priority": 10
        }
        
        rule = Rule(rule_dict)
        
        self.assertEqual(rule.name, "Test Rule")
        self.assertEqual(rule.action, "block")
        self.assertEqual(rule.priority, 10)
        self.assertEqual(str(rule.src_network), "192.168.1.0/24")
        self.assertEqual(rule.dst_port, 80)
        self.assertEqual(rule.protocol, "tcp")
    
    def test_rule_matching(self):
        """Test rule matching logic"""
        rule = Rule({
            "name": "Test Rule",
            "action": "block",
            "src_ip": "192.168.1.0/24",
            "dst_port": 80,
            "protocol": "tcp"
        })
        
        # Packet that should match
        packet_match = {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "src_port": 12345,
            "dst_port": 80,
            "proto": 6  # TCP
        }
        
        # Packet that shouldn't match (different IP)
        packet_no_match_ip = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 12345,
            "dst_port": 80,
            "proto": 6
        }
        
        # Packet that shouldn't match (different port)
        packet_no_match_port = {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "src_port": 12345,
            "dst_port": 443,
            "proto": 6
        }
        
        self.assertTrue(rule.match(packet_match))
        self.assertFalse(rule.match(packet_no_match_ip))
        self.assertFalse(rule.match(packet_no_match_port))
    
    def test_port_range_matching(self):
        """Test matching port ranges"""
        rule = Rule({
            "name": "Port Range Test",
            "dst_port": "1000-2000"
        })
        
        self.assertTrue(rule.match({"dst_port": 1000}))
        self.assertTrue(rule.match({"dst_port": 1500}))
        self.assertTrue(rule.match({"dst_port": 2000}))
        self.assertFalse(rule.match({"dst_port": 999}))
        self.assertFalse(rule.match({"dst_port": 2001}))
    
    def test_port_list_matching(self):
        """Test matching port lists"""
        rule = Rule({
            "name": "Port List Test",
            "dst_port": [80, 443, 8080]
        })
        
        self.assertTrue(rule.match({"dst_port": 80}))
        self.assertTrue(rule.match({"dst_port": 443}))
        self.assertTrue(rule.match({"dst_port": 8080}))
        self.assertFalse(rule.match({"dst_port": 8888}))
    
    def test_rule_parser(self):
        """Test the rule parser with a list of rules"""
        rules_list = [
            {
                "name": "Block Rule",
                "action": "block",
                "dst_port": 23,
                "priority": 10
            },
            {
                "name": "Allow Rule",
                "action": "allow",
                "dst_port": 80,
                "priority": 20
            }
        ]
        
        parser = RuleParser(rules_list)
        
        # Test that rules are sorted by priority
        self.assertEqual(len(parser.rules), 2)
        self.assertEqual(parser.rules[0].name, "Block Rule")
        self.assertEqual(parser.rules[0].priority, 10)
        self.assertEqual(parser.rules[1].name, "Allow Rule")
        self.assertEqual(parser.rules[1].priority, 20)


if __name__ == "__main__":
    unittest.main()
